#include "atexit.hpp"

#include "elf_parser.hpp"
#include "logging.hpp"

namespace Atexit {

void AtexitArray::recompact() {
    if (!needs_recompaction()) {
        LOGV("needs_recompaction returns false");
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
        PLOGE("mprotect on atexit array");
    }
}

AtexitArray *findAtexitArray() {
    ElfParser::ElfImage libc("libc.so");
    if (!libc.isValid()) {
        PLOGE("load libc.so");
        return nullptr;
    }

    AtexitArray *g_array = nullptr;

    // --- Primary Method: Modern, component-based symbol ---
    // On many modern systems, the `g_array` struct is exported as individual
    // global variables. The symbol `_ZL7g_array.0` points to the first field,
    // which is the start of the effective AtexitArray struct in memory.
    auto p_array_start = ElfParser::findDirectSymbol<void *>(libc, "_ZL7g_array.0");
    if (p_array_start != nullptr) {
        LOGV("found modern atexit symbol '_ZL7g_array.0' at %p", p_array_start);
        g_array = reinterpret_cast<AtexitArray *>(p_array_start);
    } else {
        // --- Fallback Method: Legacy, monolithic symbol ---
        // On older systems, the entire AtexitArray struct was exported under a single symbol name.
        LOGV("modern atexit symbol not found, trying legacy '_ZL7g_array'");
        g_array = ElfParser::findDirectSymbol<AtexitArray>(libc, "_ZL7g_array");
    }

    // --- Validation ---
    if (g_array == nullptr) {
        LOGE("failed to find any 'g_array' symbol for atexit in libc.so");
        return nullptr;
    }

    // A sanity check to ensure we are pointing to a valid structure and not
    // garbage memory. An abnormally large size is a strong indicator of an error.
    constexpr size_t MAX_REASONABLE_ATEXIT_ENTRIES = 4096 * 16;
    if (g_array->size() < MAX_REASONABLE_ATEXIT_ENTRIES) {
        LOGV("successfully validated atexit array at %p with size: %zu", g_array, g_array->size());
    } else {
        LOGE("found atexit array symbol at %p, but its size (%zu) is unreasonably large", g_array,
             g_array->size());
        return nullptr;
    }

    return g_array;
}
}  // namespace Atexit
