#include <linux/mman.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#include <lsplt.hpp>

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif

#include "atexit.hpp"
#include "fossil.hpp"
#include "logging.hpp"
#include "solist.hpp"
#include "zygisk.hpp"

void clean_libc_trace() {
    const auto status = Atexit::scrubFingerprint();
    if (status != Atexit::ScrubStatus::kDone && status != Atexit::ScrubStatus::kNothingToScrub) {
        LOGW("atexit fingerprint left in place: %s", Atexit::describe(status));
    }
}

void clean_linker_trace(const char *path, size_t loaded_modules, size_t unloaded_modules,
                        bool unload_soinfo, uintptr_t *out_base, size_t *out_size) {
    LOGV("cleaning linker trace for path %s", path);
    Linker::dropSoPath(path, unload_soinfo, out_base, out_size);

    if (unload_soinfo) {
        Linker::resetCounters(loaded_modules, loaded_modules);
    } else {
        Linker::resetCounters(loaded_modules, unloaded_modules);
    }
}

void spoof_virtual_maps(const char *path, bool clear_write_permission) {
    // spoofing map path names is futile in Android, we do it simply
    // to avoid trivial Zygisk detections based on string comparison.
    for (auto &map : lsplt::MapInfo::Scan()) {
        void *addr = (void *) map.start;
        size_t size = map.end - map.start;

        if (strstr(map.path.c_str(), path)) {
            LOGV("spoofing entry path contaning string %s", map.path.c_str());
            // Create an anonymous mapping to hold a copy of the original data
            void *copy =
                mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
            if (copy == MAP_FAILED) {
                LOGE("failed to backup block %s [%p, %p]", map.path.c_str(), addr,
                     (void *) map.end);
                continue;
            }
            // The segment is live until it is replaced, so widen its permissions to read it
            // and narrow them back at once: whoever owns it may be running from it.
            const bool widened = (map.perms & PROT_READ) == 0;
            if (widened && mprotect(addr, size, map.perms | PROT_READ) == -1) {
                PLOGE("make %s readable [%p, %p]", map.path.c_str(), addr, (void *) map.end);
                munmap(copy, size);
                continue;
            }
            memcpy(copy, addr, size);
            if (widened) mprotect(addr, size, map.perms);
            // Pages that carry code need the writes in memory before the first fetch from them.
            if (map.perms & PROT_EXEC) {
                __builtin___clear_cache(static_cast<char *>(copy),
                                        static_cast<char *>(copy) + size);
            }
            // mremap carries the source permissions onto the address it lands on, and that is
            // the only chance to set them: a segment that goes live without PROT_EXEC takes
            // every call meant to repair it into code that can no longer be executed. A
            // writable segment already carries them, and skipping the call keeps the span in
            // which its owner's writes land on the pages we are about to drop as short as it
            // can be.
            if (map.perms != (PROT_READ | PROT_WRITE) && mprotect(copy, size, map.perms) == -1) {
                PLOGE("set permissions on the copy of %s", map.path.c_str());
                munmap(copy, size);
                continue;
            }
            // Overwrite the original mapping with our anonymous copy. MREMAP_FIXED unmaps the
            // source range, so the copy is gone once this succeeds and unmapping it ourselves
            // would only take out whatever lands there next.
            if (mremap(copy, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, addr) == MAP_FAILED) {
                PLOGE("mremap failed for %s [%p, %p]", map.path.c_str(), addr, (void *) map.end);
                munmap(copy, size);
                continue;
            }
            prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, size, "dalvik-DEX data");
        }

        // A named anonymous mapping belongs to no library, and the writable executable ones
        // among them are the code caches that hooks run through.
        if (clear_write_permission && map.path.size() > 0 && map.path[0] != '[' &&
            (map.perms & (PROT_READ | PROT_WRITE | PROT_EXEC)) ==
                (PROT_READ | PROT_WRITE | PROT_EXEC)) {
            LOGV("clearing write permission for entry %s", map.path.c_str());
            int new_perms = map.perms & ~PROT_WRITE;  // Remove the write permission
            if (mprotect(addr, size, new_perms) == -1) {
                PLOGE("remove write permission from %s [%p, %p]", map.path.c_str(), addr,
                      (void *) map.end);
            } else {
                LOGV("write permission removed from %s [%p, %p]", map.path.c_str(), addr,
                     (void *) map.end);
            }
        }
    }
}

void spoof_zygote_fossil(char *search_from, char *search_to, const char *anchor) {
    Fossil::MountArgv suspicious_fossil = Fossil::MountArgv::find(search_from, search_to);
    if (!suspicious_fossil.isValid()) {
        LOGV("no valid fossil found on the stack");
        return;
    }
    suspicious_fossil.dump("current fossil");

    if (suspicious_fossil.getTarget().find(anchor) != std::string::npos) {
        LOGV("stack fossil appears to be the legitimate 'ref_profiles' entry");
        return;
    }

    auto mount_entries = Fossil::parseMountInfo();
    std::optional<Fossil::MountInfoEntry> clean_template_opt;
    for (size_t i = 1; i < mount_entries.size(); ++i) {
        if (mount_entries[i - 1].target.find(anchor) != std::string::npos &&
            mount_entries[i].is_suspicious) {
            clean_template_opt = mount_entries[i - 1];
            break;
        }
    }
    if (!clean_template_opt) {
        LOGV("no suspicious mount was found in mountinfo to identify a template");
        return;
    }
    const Fossil::MountInfoEntry &clean_entry = *clean_template_opt;
    LOGV("using preceding entry as the clean spoof template: '%s'", clean_entry.target.c_str());

    Fossil::MountArgv clean_fossil_to_write(clean_entry, suspicious_fossil.getStartAddress(),
                                            suspicious_fossil.getBaseFlags());
    clean_fossil_to_write.dump("spoofed fossil");

    suspicious_fossil.cleanMemory();
    clean_fossil_to_write.writeToMemory();
}
