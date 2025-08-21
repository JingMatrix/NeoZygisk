#include <linux/mman.h>
#include <sys/mman.h>

#include <lsplt.hpp>

#include "fossil.hpp"
#include "logging.hpp"
#include "solist.hpp"
#include "zygisk.hpp"

void clean_linker_trace(const char *path, size_t loaded_modules, size_t unloaded_modules,
                        bool unload_soinfo) {
    LOGD("cleaning linker trace for path %s", path);
    Linker::dropSoPath(path, unload_soinfo);

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
            LOGD("spoofing entry path contaning string %s", map.path.c_str());
            // Create an anonymous mapping to hold a copy of the original data
            void *copy = mmap(nullptr, size, PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
            if (copy == MAP_FAILED) {
                LOGE("failed to backup block %s [%p, %p]", map.path.c_str(), addr,
                     (void *) map.end);
                continue;
            }
            // Ensure the original mapping is readable before copying
            if ((map.perms & PROT_READ) == 0) {
                mprotect(addr, size, PROT_READ);
            }
            memcpy(copy, addr, size);
            // Overwrite the original mapping with our anonymous copy
            if (mremap(copy, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, addr) == MAP_FAILED) {
                LOGE("mremap failed for %s [%p, %p]", map.path.c_str(), addr, (void *) map.end);
            }
            // The backup copy is now at the original address, we can unmap our temporary one.
            // Note: The man page for mremap is ambiguous on whether the old mapping at 'copy'
            // is unmapped. To be safe and avoid potential leaks, we explicitly unmap it.
            munmap(copy, size);
            // Restore the original permissions
            mprotect(addr, size, map.perms);
        }

        if (clear_write_permission && map.path.size() > 0 &&
            (map.perms & (PROT_READ | PROT_WRITE | PROT_EXEC)) ==
                (PROT_READ | PROT_WRITE | PROT_EXEC)) {
            LOGD("clearing write permission for entry %s", map.path.c_str());
            int new_perms = map.perms & ~PROT_WRITE;  // Remove the write permission
            if (mprotect(addr, size, new_perms) == -1) {
                PLOGE("Failed to remove write permission from %s [%p, %p]", map.path.c_str(), addr,
                      (void *) map.end);
            } else {
                LOGD("Successfully removed write permission from %s [%p, %p]", map.path.c_str(),
                     addr, (void *) map.end);
            }
        }
    }
}

void spoof_zygote_fossil(char *search_from, char *search_to, const char *anchor) {
    Fossil::MountArgv suspicious_fossil = Fossil::MountArgv::find(search_from, search_to);
    if (!suspicious_fossil.isValid()) {
        LOGD("no valid fossil found on the stack");
        return;
    }
    suspicious_fossil.dumpToLog();

    if (suspicious_fossil.getTarget().find(anchor) != std::string::npos) {
        LOGD("stack fossil appears to be the legitimate 'ref_profiles' entry");
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
        LOGD("no suspicious mount was found in mountinfo to identify a template");
        return;
    }
    const Fossil::MountInfoEntry &clean_entry = *clean_template_opt;
    LOGD("using preceding entry as the clean spoof template: '%s'", clean_entry.target.c_str());

    Fossil::MountArgv clean_fossil_to_write(clean_entry, suspicious_fossil.getStartAddress(),
                                            suspicious_fossil.getBaseFlags());
    LOGD("created a clean fossil object to write:");
    clean_fossil_to_write.dumpToLog();

    suspicious_fossil.cleanMemory();
    clean_fossil_to_write.writeToMemory();
}
