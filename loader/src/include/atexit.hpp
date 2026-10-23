#pragma once

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/cdefs.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/prctl.h>
#include <sys/user.h>

#include <memory>
#include <sstream>

namespace Atexit {

// Bionic resolves this through AT_PAGESZ on every architecture that can boot with pages larger
// than 4 KiB. The NDK, in contrast, still hands us a compile-time PAGE_SIZE of 4096 on arm64
// (bits/page_size.h keeps the macro for __NDK_MAJOR__ <= 27), so trusting the macro would give us
// a different view of the array's pages than libc has on a 16 KiB-page device.
inline size_t page_size() {
    static const size_t page_size = getauxval(AT_PAGESZ);
    return page_size;
}

// The maximum page size supported on any Android device. As
// of API level 35, this is limited by ART.
constexpr size_t max_android_page_size() {
#if defined(PAGE_SIZE)
    return PAGE_SIZE;
#else
    return 16384;
#endif
}

// Returns the address of the page containing address 'x'.
inline uintptr_t page_start(uintptr_t x) { return x & ~(page_size() - 1); }

// Returns the offset of address 'x' in its page.
inline uintptr_t page_offset(uintptr_t x) { return x & (page_size() - 1); }

// Returns the address of the next page after address 'x', unless 'x' is
// itself at the start of a page.
inline uintptr_t page_end(uintptr_t x) { return page_start(x + page_size() - 1); }

// Why a fingerprint scrub stopped where it did. The caller reports this once libc's atexit lock is
// released, never from inside the critical section.
enum class ScrubStatus {
    kDone,            // the array was compacted and its counters rewound
    kNothingToScrub,  // libc's array carries no trace of the modules we unloaded
    kNoArray,         // libc's private atexit array could not be located
    kNoLock,          // libc's atexit mutex could not be located, so we cannot mutate safely
    kLockBusy,        // another thread is registering or running handlers right now
    kNotWritable,     // mprotect refused to open up the array pages
    kLeftWritable,    // the array was compacted, but could not be protected read-only again
};

const char* describe(ScrubStatus status);

struct AtexitEntry {
    void (*fn)(void*);  // the __cxa_atexit callback
    void* arg;          // argument for `fn` callback
    void* dso;          // shared module handle
};

class AtexitArray {
public:
    AtexitArray(AtexitEntry* existing_array, size_t current_size, size_t current_capacity,
                size_t initial_extracted_count, uint64_t initial_total_appends)
        : array_(existing_array),
          size_(current_size),
          extracted_count_(initial_extracted_count),
          capacity_(current_capacity),
          total_appends_(initial_total_appends) {}

    std::string format_state_string() const {
        std::stringstream ss;

        // Use the << operator to stream text and variables into the stringstream.
        // The '\n' and '\t' characters provide the desired logcat formatting.
        ss << "\n--- Live AtexitArray Snapshot State ---\n";
        ss << "\t(this pointer):  " << static_cast<const void*>(this) << "\n";
        ss << "\tarray_:          " << static_cast<const void*>(array_) << "\n";

        // For numeric values, show both decimal and hexadecimal for easier debugging.
        ss << "\tsize_:           " << size_ << " (0x" << std::hex << size_ << std::dec << ")\n";
        ss << "\textracted_count_: " << extracted_count_ << " (0x" << std::hex << extracted_count_
           << std::dec << ")\n";
        ss << "\tcapacity_:       " << capacity_ << " (0x" << std::hex << capacity_ << std::dec
           << ")\n";
        ss << "\ttotal_appends_:  " << total_appends_ << " (0x" << std::hex << total_appends_
           << std::dec << ")\n";

        ss << "---------------------------------------";

        // The .str() method returns the complete, concatenated string.
        return ss.str();
    }

    size_t size() const { return size_; }
    uint64_t total_appends() const { return total_appends_; }
    const AtexitEntry& operator[](size_t idx) const { return array_[idx]; }

    // Compacts the array in place and rewinds the counters that give our unloaded modules away.
    //
    // The caller must hold libc's atexit lock. __cxa_atexit and __cxa_finalize mutate the array,
    // its page protections and even its mapping (append_entry() mremaps it to grow) under that
    // lock; flipping the pages back to PROT_READ behind their back makes their store fault with
    // SEGV_ACCERR, and moving entries while they append loses or corrupts them.
    //
    // The caller must also keep logging out of that critical section, since liblog can reach
    // __cxa_atexit and deadlock on the very mutex we hold. An mprotect failure is therefore
    // reported through `protect_errno` instead of a log line.
    ScrubStatus recompact(int& protect_errno);

private:
    AtexitEntry* array_;
    size_t size_;
    size_t extracted_count_;
    size_t capacity_;

    // An entry can be appended by a __cxa_finalize callback. Track the number of appends so we
    // restart concurrent __cxa_finalize passes.
    uint64_t total_appends_;

    static size_t page_start_of_index(size_t idx) { return page_start(idx * sizeof(AtexitEntry)); }
    static size_t page_end_of_index(size_t idx) { return page_end(idx * sizeof(AtexitEntry)); }

    // True while the array still shows that handlers were registered and then removed: either null
    // holes left behind by __cxa_finalize, or an append counter that outruns the live entries.
    // Bionic instead asks whether compaction would free a page, which is not our concern here.
    bool has_fingerprint() const { return extracted_count_ > 0 || total_appends_ > size_; }

    bool set_writable(bool writable, size_t start_idx, size_t num_entries);
};

// Erases the traces that unloading our modules left in libc's exit-handler array. Best effort:
// every obstacle leaves libc's state exactly as it was.
ScrubStatus scrubFingerprint();

}  // namespace Atexit
