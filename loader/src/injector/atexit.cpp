#include "atexit.hpp"

#include "elf_parser.hpp"
#include "logging.hpp"

namespace Atexit {

void AtexitArray::recompact() {
    if (!needs_recompaction()) {
        LOGD("needs_recompaction returns false");
    }

    set_writable(true, 0, size_);

    // Optimization: quickly skip over the initial non-null entries.
    size_t src = 0, dst = 0;
    while (src < size_ && array_[src].fn != nullptr) {
        ++src;
        ++dst;
    }

    // Shift the non-null entries forward, and zero out the removed entries at the end of the array.
    for (; src < size_; ++src) {
        const AtexitEntry entry = array_[src];
        array_[src] = {};
        if (entry.fn != nullptr) {
            array_[dst++] = entry;
        }
    }

    // If the table uses fewer pages, clean the pages at the end.
    size_t old_bytes = page_end_of_index(size_);
    size_t new_bytes = page_end_of_index(dst);
    if (new_bytes < old_bytes) {
        madvise(reinterpret_cast<char *>(array_) + new_bytes, old_bytes - new_bytes, MADV_DONTNEED);
    }

    set_writable(false, 0, size_);

    size_ = dst;
    extracted_count_ = 0;
    total_appends_ = size_;
}

// Use mprotect to make the array writable or read-only. Returns true on success. Making the array
// read-only could protect against either unintentional or malicious corruption of the array.
void AtexitArray::set_writable(bool writable, size_t start_idx, size_t num_entries) {
    if (array_ == nullptr) return;

    const size_t start_byte = page_start_of_index(start_idx);
    const size_t stop_byte = page_end_of_index(start_idx + num_entries);
    const size_t byte_len = stop_byte - start_byte;

    const int prot = PROT_READ | (writable ? PROT_WRITE : 0);
    if (mprotect(reinterpret_cast<char *>(array_) + start_byte, byte_len, prot) != 0) {
        PLOGE("mprotect failed on atexit array: %m");
    }
}

AtexitArray *findAtexitArray() {
    ElfParser::ElfImage libc("libc.so");
    auto p_array = ElfParser::findDirectSymbol<AtexitEntry *>(libc, "_ZL7g_array.0");
    auto p_size = ElfParser::findDirectSymbol<size_t>(libc, "_ZL7g_array.1");
    auto p_extracted_count = ElfParser::findDirectSymbol<size_t>(libc, "_ZL7g_array.2");
    auto p_capacity = ElfParser::findDirectSymbol<size_t>(libc, "_ZL7g_array.3");
    auto p_total_appends = ElfParser::findDirectSymbol<uint64_t>(libc, "_ZL7g_array.4");

    if (p_array == nullptr || p_size == nullptr || p_extracted_count == nullptr ||
        p_capacity == nullptr || p_total_appends == nullptr) {
        LOGD("failed to find exported g_array fields in memory");
        return nullptr;
    }

    return reinterpret_cast<AtexitArray *>(p_array);
}

}  // namespace Atexit
