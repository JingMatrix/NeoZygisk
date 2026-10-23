#include "atexit.hpp"

#include <errno.h>
#include <sched.h>

#include "elf_parser.hpp"
#include "logging.hpp"

namespace Atexit {

namespace {

// How many times we try to take libc's atexit lock before abandoning the pass. The lock is only
// ever held for a handful of instructions, so yielding a few times is enough to let the holder
// finish. We never block on it: a fork can hand us a mutex that was locked by a thread this
// process did not inherit, and waiting on that would hang the app for good.
constexpr int kLockAttempts = 8;

AtexitArray *findArray(const ElfParser::ElfImage &libc) {
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

pthread_mutex_t *findLock(ElfParser::ElfImage &libc) {
    // `g_atexit_lock` is a file-static pthread_mutex_t, so it only ever appears in .symtab under
    // its mangled local name, never in .dynsym.
    auto *lock = ElfParser::findDirectSymbol<pthread_mutex_t>(libc, "_ZL13g_atexit_lock");
    if (lock != nullptr) {
        LOGV("found atexit lock symbol '_ZL13g_atexit_lock' at %p", lock);
        return lock;
    }

    // Link-time optimization can rename or split file-static objects, exactly as it did to
    // `g_array` above, so accept the first symbol carrying the mangled prefix.
    const auto name = libc.findSymbolNameByPrefix("_ZL13g_atexit_lock");
    if (name.empty()) {
        LOGE("failed to find the 'g_atexit_lock' symbol for atexit in libc.so");
        return nullptr;
    }
    LOGV("found atexit lock under split symbol '%.*s'", static_cast<int>(name.size()), name.data());
    return ElfParser::findDirectSymbol<pthread_mutex_t>(libc, name);
}

}  // namespace

ScrubStatus AtexitArray::recompact(int &protect_errno) {
    protect_errno = 0;

    if (!has_fingerprint()) return ScrubStatus::kNothingToScrub;

    bool restored = true;

    // Null holes are the only thing that needs the array pages opened up. When __cxa_finalize
    // already compacted them away, rewinding the append counter below is the whole scrub, and we
    // can leave the mapping's protections untouched.
    if (extracted_count_ > 0) {
        // If the pages cannot be made writable, do not touch the array. mprotect can fail with
        // ENOMEM under memory pressure (e.g. splitting a VMA past max_map_count), and writing into
        // memory that was never made writable would fault with SEGV_ACCERR.
        if (!set_writable(true, 0, size_)) {
            protect_errno = errno;
            return ScrubStatus::kNotWritable;
        }

        // Optimization: quickly skip over the initial non-null entries.
        size_t src = 0, dst = 0;
        while (src < size_ && array_[src].fn != nullptr) {
            ++src;
            ++dst;
        }

        // Shift the non-null entries forward, and zero out the removed entries at the end of the
        // array.
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
            madvise(reinterpret_cast<char *>(array_) + new_bytes, old_bytes - new_bytes,
                    MADV_DONTNEED);
        }

        // Restoring the original protection has to be reported too. Bionic treats this mprotect
        // as fatal, and leaving the array writable for the rest of the process costs libc the
        // hardening the read-only resting state buys it. Re-protecting the same range we opened
        // normally merges VMAs rather than splitting any, so this is far less likely to fail than
        // the call above, but it is not guaranteed.
        restored = set_writable(false, 0, size_);
        if (!restored) protect_errno = errno;

        size_ = dst;
        extracted_count_ = 0;
    }

    // Unlike bionic, we also rewind the append counter: a count that outruns the live entries is
    // what tells a detector that handlers came and went.
    total_appends_ = size_;
    return restored ? ScrubStatus::kDone : ScrubStatus::kLeftWritable;
}

// Use mprotect to make the array writable or read-only. Returns true on success, and leaves errno
// set on failure. Making the array read-only could protect against either unintentional or
// malicious corruption of the array.
bool AtexitArray::set_writable(bool writable, size_t start_idx, size_t num_entries) {
    if (array_ == nullptr) {
        errno = EFAULT;
        return false;
    }

    const size_t start_byte = page_start_of_index(start_idx);
    const size_t stop_byte = page_end_of_index(start_idx + num_entries);
    const size_t byte_len = stop_byte - start_byte;

    const int prot = PROT_READ | (writable ? PROT_WRITE : 0);
    return mprotect(reinterpret_cast<char *>(array_) + start_byte, byte_len, prot) == 0;
}

const char *describe(ScrubStatus status) {
    switch (status) {
    case ScrubStatus::kDone:
        return "array compacted";
    case ScrubStatus::kNothingToScrub:
        return "nothing to scrub";
    case ScrubStatus::kNoArray:
        return "atexit array not found";
    case ScrubStatus::kNoLock:
        return "atexit lock not found";
    case ScrubStatus::kLockBusy:
        return "atexit lock held by another thread";
    case ScrubStatus::kNotWritable:
        return "array could not be made writable";
    case ScrubStatus::kLeftWritable:
        return "array compacted but left writable";
    }
    return "unknown";
}

ScrubStatus scrubFingerprint() {
    ElfParser::ElfImage libc("libc.so");
    if (!libc.isValid()) {
        PLOGE("load libc.so");
        return ScrubStatus::kNoArray;
    }

    AtexitArray *g_array = findArray(libc);
    if (g_array == nullptr) return ScrubStatus::kNoArray;

    // The lock is resolved together with the array: without it we have no safe way to mutate
    // libc's state, and leaving the fingerprint behind beats crashing the app.
    pthread_mutex_t *lock = findLock(libc);
    if (lock == nullptr) return ScrubStatus::kNoLock;

    LOGV("g_array before scrub: %s", g_array->format_state_string().c_str());

    bool locked = false;
    for (int attempt = 0; attempt < kLockAttempts && !locked; ++attempt) {
        if (pthread_mutex_trylock(lock) == 0) {
            locked = true;
        } else {
            sched_yield();
        }
    }
    if (!locked) return ScrubStatus::kLockBusy;

    int protect_errno = 0;
    const ScrubStatus status = g_array->recompact(protect_errno);
    pthread_mutex_unlock(lock);

    // Logging only once the lock is released, so that a liblog path reaching __cxa_atexit cannot
    // deadlock on it.
    if (status == ScrubStatus::kNotWritable || status == ScrubStatus::kLeftWritable) {
        LOGE("mprotect on atexit array failed with %d: %s", protect_errno, strerror(protect_errno));
    }
    if (status != ScrubStatus::kNotWritable) {
        LOGV("g_array after scrub: %s", g_array->format_state_string().c_str());
    }

    return status;
}
}  // namespace Atexit
