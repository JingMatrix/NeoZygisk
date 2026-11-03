#include <linux/mman.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include <lsplt.hpp>

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif

#include "atexit.hpp"
#include "cfi.hpp"
#include "fossil.hpp"
#include "logging.hpp"
#include "solist.hpp"
#include "zygisk.hpp"

constexpr const char *kConfigPath = "/data/adb/nyazygisk/config.prop";

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

// True if config.prop contains a line matching exactly "key=value".
static bool config_line_present(const char *key, const char *value) {
    FILE *fp = fopen(kConfigPath, "re");
    if (fp == nullptr) return false;

    char needle[64];
    snprintf(needle, sizeof(needle), "%s=%s", key, value);

    char line[128];
    bool found = false;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        char *end = line + strlen(line);
        while (end > line && (end[-1] == '\n' || end[-1] == '\r' || end[-1] == ' ' ||
                              end[-1] == '\t')) {
            *--end = '\0';
        }
        if (strcmp(line, needle) == 0) {
            found = true;
            break;
        }
    }
    fclose(fp);
    return found;
}

bool is_anonymous_memory_enabled() { return config_line_present("anonymous_memory", "1"); }

// Opt-in, like anonymous_memory: the custom module loader (loader/src/linker/) is
// experimental, so a missing config.prop (fresh install) or a config without the key
// keeps the plain android_dlopen_ext path until the WebUI explicitly turns it on.
bool is_custom_linker_enabled() { return config_line_present("custom_linker", "1"); }

// PLT hook engine for ZN modules: bytehook (default) or lsplt.
bool is_lsplt_engine_configured() { return config_line_present("plt_engine", "lsplt"); }

static size_t page_size() {
    long sz = sysconf(_SC_PAGESIZE);
    return sz > 0 ? static_cast<size_t>(sz) : 4096;
}

static inline uintptr_t page_down(uintptr_t addr, size_t pg) {
    return addr & ~(static_cast<uintptr_t>(pg) - 1);
}

static inline uintptr_t page_up(uintptr_t addr, size_t pg) {
    return (addr + pg - 1) & ~(static_cast<uintptr_t>(pg) - 1);
}

static inline uintptr_t elf_runtime_address(ElfW(Addr) load_bias, ElfW(Addr) value) {
    return static_cast<uintptr_t>(load_bias + value);
}

/* Android bionic CFI shadow format */
constexpr uintptr_t kCfiShadowGranularity = 18;  // 256KB
constexpr uintptr_t kCfiShadowEntrySize = sizeof(uint16_t);

struct CfiShadowRange {
    uintptr_t start = 0;
    uintptr_t end = 0;
    int prot = 0;
};

static inline uintptr_t cfi_shadow_offset(uintptr_t addr) {
    return (addr >> kCfiShadowGranularity) << 1;
}

static bool find_cfi_shadow(CfiShadowRange *out) {
    FILE *fp = fopen("/proc/self/maps", "re");
    if (fp == nullptr) return false;
    char line[512];
    CfiShadowRange run, best;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        if (strstr(line, "[anon:cfi shadow]") == nullptr) continue;
        unsigned long start = 0, end = 0;
        if (sscanf(line, "%lx-%lx", &start, &end) != 2) continue;
        if (run.end != 0 && run.end == start) {
            run.end = end;
        } else {
            run.start = start;
            run.end = end;
        }
        if (run.end - run.start > best.end - best.start) best = run;
    }
    fclose(fp);
    if (best.end == 0) return false;
    *out = best;
    out->prot = PROT_READ;
    return true;
}

static bool sync_cfi_shadow(uintptr_t old_start, uintptr_t new_start, size_t size) {
    if (old_start == new_start || size == 0) return true;

    CfiShadowRange shadow;
    if (!find_cfi_shadow(&shadow)) return true;

    uintptr_t old_end = old_start + size - 1;
    uintptr_t new_end = new_start + size - 1;
    uintptr_t src = shadow.start + cfi_shadow_offset(old_start);
    uintptr_t src_end = shadow.start + cfi_shadow_offset(old_end) + kCfiShadowEntrySize;
    uintptr_t dst = shadow.start + cfi_shadow_offset(new_start);
    uintptr_t dst_end = shadow.start + cfi_shadow_offset(new_end) + kCfiShadowEntrySize;
    if (src < shadow.start || src_end > shadow.end || dst < shadow.start ||
        dst_end > shadow.end || src_end < src || dst_end < dst) {
        LOGE("cfi-shadow: range outside shadow map");
        return false;
    }

    size_t pg = page_size();
    uintptr_t prot_start = page_down(dst, pg);
    uintptr_t prot_end = page_up(dst_end, pg);
    bool reprotect = (shadow.prot & PROT_WRITE) == 0;
    if (reprotect &&
        mprotect(reinterpret_cast<void *>(prot_start), prot_end - prot_start,
                 shadow.prot | PROT_WRITE) != 0) {
        LOGE("cfi-shadow: make writable failed");
        return false;
    }
    memmove(reinterpret_cast<void *>(dst), reinterpret_cast<const void *>(src),
            dst_end - dst);
    if (reprotect &&
        mprotect(reinterpret_cast<void *>(prot_start), prot_end - prot_start, shadow.prot) != 0) {
        LOGE("cfi-shadow: restore protection failed");
        return false;
    }
    return true;
}

SavedCfiShadow backup_cfi_shadow(uintptr_t base, size_t size) {
    SavedCfiShadow saved;
    if (base == 0 || size == 0) return saved;

    CfiShadowRange shadow;
    if (!find_cfi_shadow(&shadow)) return saved;

    uintptr_t end = base + size - 1;
    uintptr_t src = shadow.start + cfi_shadow_offset(base);
    uintptr_t src_end = shadow.start + cfi_shadow_offset(end) + kCfiShadowEntrySize;
    if (src < shadow.start || src_end > shadow.end || src_end <= src) {
        return saved;
    }

    size_t byte_len = src_end - src;
    saved.dst_addr = src;
    saved.shadow_data.resize(byte_len);
    memcpy(saved.shadow_data.data(), reinterpret_cast<const void *>(src), byte_len);
    LOGV("cfi-shadow: backed up %zu bytes for [%p, %p]", byte_len,
         reinterpret_cast<void *>(base), reinterpret_cast<void *>(base + size));
    return saved;
}

bool restore_cfi_shadow(const SavedCfiShadow &saved) {
    if (saved.dst_addr == 0 || saved.shadow_data.empty()) return true;

    CfiShadowRange shadow;
    if (!find_cfi_shadow(&shadow)) return false;

    uintptr_t dst = saved.dst_addr;
    size_t byte_len = saved.shadow_data.size();
    uintptr_t dst_end = dst + byte_len;
    if (dst < shadow.start || dst_end > shadow.end) {
        LOGE("cfi-shadow: restore target outside shadow map");
        return false;
    }

    size_t pg = page_size();
    uintptr_t prot_start = page_down(dst, pg);
    uintptr_t prot_end = page_up(dst_end, pg);
    bool reprotect = (shadow.prot & PROT_WRITE) == 0;
    if (reprotect &&
        mprotect(reinterpret_cast<void *>(prot_start), prot_end - prot_start,
                 shadow.prot | PROT_WRITE) != 0) {
        LOGE("cfi-shadow: restore make writable failed");
        return false;
    }

    memcpy(reinterpret_cast<void *>(dst), saved.shadow_data.data(), byte_len);

    if (reprotect &&
        mprotect(reinterpret_cast<void *>(prot_start), prot_end - prot_start, shadow.prot) != 0) {
        LOGE("cfi-shadow: restore protection failed");
        return false;
    }
    LOGV("cfi-shadow: restored %zu bytes at %p", byte_len, reinterpret_cast<void *>(dst));
    return true;
}

void register_cfi_unchecked(uintptr_t base, size_t size) {
    if (base == 0 || size == 0) return;

    CfiShadowRange shadow;
    if (!find_cfi_shadow(&shadow)) return;  // device/process without cross-DSO CFI

    uintptr_t end = base + size - 1;
    uintptr_t dst = shadow.start + cfi_shadow_offset(base);
    uintptr_t dst_end = shadow.start + cfi_shadow_offset(end) + kCfiShadowEntrySize;
    if (dst < shadow.start || dst_end > shadow.end || dst_end <= dst) {
        LOGE("cfi-shadow: module range outside shadow map");
        return;
    }

    size_t pg = page_size();
    uintptr_t prot_start = page_down(dst, pg);
    uintptr_t prot_end = page_up(dst_end, pg);
    bool reprotect = (shadow.prot & PROT_WRITE) == 0;
    if (reprotect && mprotect(reinterpret_cast<void *>(prot_start), prot_end - prot_start,
                              shadow.prot | PROT_WRITE) != 0) {
        LOGE("cfi-shadow: make writable failed");
        return;
    }

    int changed = linker::CfiMarkUncheckedRange(shadow.start, shadow.end, base, size);

    if (reprotect)
        mprotect(reinterpret_cast<void *>(prot_start), prot_end - prot_start, shadow.prot);

    LOGV("cfi-shadow: marked %d granule(s) unchecked for [%p, %p]", changed,
         reinterpret_cast<void *>(base), reinterpret_cast<void *>(base + size));
}

struct MapRange {
    uintptr_t start = 0;
    uintptr_t end = 0;
    int prot = 0;
};

static int anonymize_ranges(const MapRange *ranges, int nr, bool clear_write_permission = false) {
    int done = 0;
    for (int i = 0; i < nr; ++i) {
        size_t size = ranges[i].end - ranges[i].start;
        if (size == 0) continue;
        void *addr = reinterpret_cast<void *>(ranges[i].start);

        // Final protection the target address should have once this call returns —
        // ranges[i].prot, minus the write bit when this range is RWX and the caller
        // asked to drop it (see below). Computed once so it can be applied to the
        // scratch copy BEFORE the mremap swap: the target then goes straight from its
        // old protection to this exact final one, with no intermediate state. An
        // earlier version of this function instead mmap'd the copy with every bit the
        // target would ever need (so an executable range's copy was RWX from the
        // start) and only narrowed it down with a *second* mprotect AFTER the mremap —
        // which left every executable range briefly simultaneously writable and
        // executable (W+X) for the few instructions between the swap and that
        // follow-up call. v2.4 never had this window; match it.
        const bool was_rwx = (ranges[i].prot & (PROT_READ | PROT_WRITE | PROT_EXEC)) ==
                            (PROT_READ | PROT_WRITE | PROT_EXEC);
        const int final_prot = (clear_write_permission && was_rwx)
                                   ? (ranges[i].prot & ~PROT_WRITE)
                                   : ranges[i].prot;

        // The scratch copy only needs RW to receive the memcpy below.
        void *copy = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (copy == MAP_FAILED) {
            LOGV("maps-spoof: mmap preflight failed for [%p, %p]", addr,
                 reinterpret_cast<void *>(ranges[i].end));
            continue;
        }

        bool added_read = (ranges[i].prot & PROT_READ) == 0;
        if (added_read && mprotect(addr, size, ranges[i].prot | PROT_READ) != 0) {
            PLOGE("maps-spoof: make source readable failed [%p, %p]", addr,
                  reinterpret_cast<void *>(ranges[i].end));
            munmap(copy, size);
            continue;
        }

        memcpy(copy, addr, size);

        if (added_read && mprotect(addr, size, ranges[i].prot) != 0) {
            PLOGE("maps-spoof: restore source protection failed [%p, %p]", addr,
                  reinterpret_cast<void *>(ranges[i].end));
            munmap(copy, size);
            continue;
        }

        // Apply the target's final permissions to the copy now, while it is still at
        // its own, harmless address — an execmem denial on an executable range
        // surfaces here, before the original mapping at `addr` is touched at all, same
        // safety property as the old preflight-on-mmap approach but without ever
        // creating an RWX mapping to get there. This also folds in the optional
        // write-bit drop: scoped to exactly the range this call already matched and is
        // about to anonymize anyway — never a fresh scan of /proc/self/maps for "any
        // RWX entry", which would also catch other subsystems' legitimate RWX mappings
        // (e.g. ART's JIT cache, a GPU shader compiler cache) that happen to exist in
        // this process and have nothing to do with our module. Downgrading one of
        // those breaks its owner the next time it writes to memory it still believes
        // is writable.
        if (mprotect(copy, size, final_prot) != 0) {
            PLOGE("maps-spoof: set replacement permissions failed [%p, %p]", addr,
                  reinterpret_cast<void *>(ranges[i].end));
            munmap(copy, size);
            continue;
        }

        if (mremap(copy, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, addr) == MAP_FAILED) {
            PLOGE("maps-spoof: mremap failed [%p, %p]", addr,
                  reinterpret_cast<void *>(ranges[i].end));
            munmap(copy, size);
            continue;
        }
        if (final_prot != ranges[i].prot) {
            LOGV("maps-spoof: cleared write permission for [%p, %p]", addr,
                 reinterpret_cast<void *>(ranges[i].end));
        }

        // Clear VMA anon name to make it pure anonymous (path in /proc/self/maps becomes empty).
        // Avoid setting "dalvik-DEX data", which is an immediate detection on executable pages.
        prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, size, nullptr);

        if (ranges[i].prot & PROT_EXEC) {
            sync_cfi_shadow(ranges[i].start, ranges[i].start, size);
            __builtin___clear_cache(reinterpret_cast<char *>(addr),
                                    reinterpret_cast<char *>(ranges[i].start + size));
        }

        ++done;
    }
    return done;
}

struct LoadedObjectScan {
    uintptr_t address = 0;
    MapRange ranges[64]{};
    int count = 0;
};

static void add_loaded_range(LoadedObjectScan *scan, uintptr_t start, uintptr_t end, int prot) {
    if (scan->count >= static_cast<int>(std::size(scan->ranges)) || end <= start) return;
    scan->ranges[scan->count++] = {start, end, prot};
}

static int collect_loaded_object(dl_phdr_info *info, size_t, void *data) {
    auto *scan = static_cast<LoadedObjectScan *>(data);
    const size_t pg = page_size();
    if (pg == 0) return 0;

    bool contains = false;
    for (size_t i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) &ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_LOAD) continue;
        uintptr_t start = elf_runtime_address(info->dlpi_addr, ph.p_vaddr);
        if (ph.p_memsz > UINTPTR_MAX - start) continue;
        if (scan->address >= start && scan->address < start + ph.p_memsz) {
            contains = true;
            break;
        }
    }
    if (!contains) return 0;

    uintptr_t relro_start = 0;
    uintptr_t relro_end = 0;
    for (size_t i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) &ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_GNU_RELRO) continue;
        uintptr_t start = elf_runtime_address(info->dlpi_addr, ph.p_vaddr);
        if (ph.p_memsz > UINTPTR_MAX - start ||
            start + ph.p_memsz > UINTPTR_MAX - (pg - 1))
            continue;
        relro_start = page_down(start, pg);
        relro_end = page_up(start + ph.p_memsz, pg);
        break;
    }

    for (size_t i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) &ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_LOAD || ph.p_filesz == 0) continue;
        uintptr_t file_start = elf_runtime_address(info->dlpi_addr, ph.p_vaddr);
        if (ph.p_filesz > UINTPTR_MAX - file_start ||
            file_start + ph.p_filesz > UINTPTR_MAX - (pg - 1))
            continue;
        uintptr_t start = page_down(file_start, pg);
        uintptr_t end = page_up(file_start + ph.p_filesz, pg);
        int prot = (ph.p_flags & PF_R ? PROT_READ : 0) |
                   (ph.p_flags & PF_W ? PROT_WRITE : 0) |
                   (ph.p_flags & PF_X ? PROT_EXEC : 0);

        uintptr_t protected_start = std::max(start, relro_start);
        uintptr_t protected_end = std::min(end, relro_end);
        if (relro_end <= relro_start || protected_end <= protected_start) {
            add_loaded_range(scan, start, end, prot);
            continue;
        }
        add_loaded_range(scan, start, protected_start, prot);
        add_loaded_range(scan, protected_start, protected_end, prot & ~PROT_WRITE);
        add_loaded_range(scan, protected_end, end, prot);
    }
    return 1;
}

static int normalize_loaded_ranges(MapRange *ranges, int count) {
    std::sort(ranges, ranges + count, [](const MapRange &a, const MapRange &b) {
        return a.start < b.start || (a.start == b.start && a.end < b.end);
    });
    int output = 0;
    for (int i = 0; i < count; ++i) {
        MapRange range = ranges[i];
        if (output > 0 && range.start < ranges[output - 1].end)
            range.start = ranges[output - 1].end;
        if (range.end <= range.start)
            continue;
        if (output > 0 && ranges[output - 1].end == range.start &&
            ranges[output - 1].prot == range.prot) {
            ranges[output - 1].end = range.end;
            continue;
        }
        ranges[output++] = range;
    }
    return output;
}

int spoof_loaded_object_maps(uintptr_t address, bool private_only) {
    (void) private_only;
    if (address == 0) return 0;
#if defined(__arm__)
    address &= ~static_cast<uintptr_t>(1);
#endif
    LoadedObjectScan scan;
    scan.address = address;
    if (dl_iterate_phdr(collect_loaded_object, &scan) == 0 || scan.count == 0)
        return 0;
    scan.count = normalize_loaded_ranges(scan.ranges, scan.count);
    int done = anonymize_ranges(scan.ranges, scan.count);
    LOGV("maps-spoof: anonymized %d/%d loaded-object segment(s) for addr %p", done,
         scan.count, reinterpret_cast<void *>(address));
    return done;
}

int spoof_fd_maps(int fd, bool private_only) {
    struct stat st{};
    if (fd < 0 || fstat(fd, &st) != 0) return 0;

    MapRange ranges[64];
    int nr = 0;
    FILE *fp = fopen("/proc/self/maps", "re");
    if (fp == nullptr) return 0;
    char line[512];
    while (nr < 64 && fgets(line, sizeof(line), fp) != nullptr) {
        unsigned long start = 0, end = 0;
        unsigned int dev_major = 0, dev_minor = 0;
        unsigned long inode = 0;
        char perms[5] = {};
        if (sscanf(line, "%lx-%lx %4s %*s %x:%x %lu", &start, &end, perms,
                   &dev_major, &dev_minor, &inode) != 6)
            continue;
        if (makedev(dev_major, dev_minor) != st.st_dev ||
            static_cast<ino_t>(inode) != st.st_ino)
            continue;
        if (private_only && perms[3] != 'p')
            continue;
        int prot = (perms[0] == 'r' ? PROT_READ : 0) |
                   (perms[1] == 'w' ? PROT_WRITE : 0) |
                   (perms[2] == 'x' ? PROT_EXEC : 0);
        ranges[nr++] = {start, end, prot};
    }
    fclose(fp);

    int done = anonymize_ranges(ranges, nr);
    LOGV("maps-spoof: anonymized %d/%d segment(s) for fd=%d", done, nr, fd);
    return done;
}

int spoof_virtual_maps(const char *path_substr, bool private_only, bool clear_write_permission) {
    if (path_substr == nullptr || path_substr[0] == '\0') return 0;
    MapRange ranges[64];
    int nr = 0;

    FILE *fp = fopen("/proc/self/maps", "re");
    if (fp == nullptr) return 0;
    char line[512];
    while (nr < 64 && fgets(line, sizeof(line), fp) != nullptr) {
        if (strstr(line, path_substr) == nullptr) continue;
        unsigned long start = 0, end = 0;
        char perms[5] = {};
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3) continue;
        if (private_only && perms[3] != 'p') continue;
        int prot = (perms[0] == 'r' ? PROT_READ : 0) |
                   (perms[1] == 'w' ? PROT_WRITE : 0) |
                   (perms[2] == 'x' ? PROT_EXEC : 0);
        ranges[nr++] = {start, end, prot};
    }
    fclose(fp);

    int done = anonymize_ranges(ranges, nr, clear_write_permission);
    LOGV("maps-spoof: anonymized %d/%d segment(s) matching '%s'", done, nr, path_substr);
    return done;
}


void spoof_module_maps(bool clear_write_permission) {
    // clear_write_permission is forwarded straight into the same anonymize pass that already
    // matched these paths, so the write bit is only ever dropped from a range we just verified
    // is actually one of our module's own (memfd-derived) mappings — never from a fresh,
    // unscoped /proc/self/maps rescan for "any RWX entry", which would also catch other
    // subsystems' legitimate RWX mappings that happen to exist in this process (ART's JIT
    // cache, a GPU shader compiler cache, ...) and have nothing to do with our module.
    constexpr std::array paths{"jit-cache-zygisk", "zygisk-module", "zn-module"};
    for (const char *path : paths) {
        spoof_virtual_maps(path, /*private_only=*/true, clear_write_permission);
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
