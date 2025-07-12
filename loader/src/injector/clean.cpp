#include <linux/mman.h>
#include <sys/mman.h>

#include <lsplt.hpp>
#include <vector>

#include "logging.hpp"
#include "solist.hpp"
#include "zygisk.hpp"

void clean_trace(const char *path, size_t load, size_t unload, bool spoof_maps) {
    LOGD("cleaning trace for path %s", path);

    if (load > 0 || unload > 0) SoList::resetCounters(load, unload);
    bool path_found = SoList::dropSoPath(path);
    if (!path_found || !spoof_maps) return;

    LOGD("spoofing virtual maps for %s", path);
    // spoofing map names is futile in Android, we do it simply
    // to avoid Zygisk detections based on string comparison
    for (auto &map : lsplt::MapInfo::Scan()) {
        if (strstr(map.path.c_str(), path)) {
            void *addr = (void *) map.start;
            size_t size = map.end - map.start;
            void *copy = mmap(nullptr, size, PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
            if (copy == MAP_FAILED) {
                LOGE("failed to backup block %s [%p, %p]", map.path.c_str(), addr,
                     (void *) map.end);
                continue;
            }

            if ((map.perms & PROT_READ) == 0) {
                mprotect(addr, size, PROT_READ);
            }
            memcpy(copy, addr, size);
            mremap(copy, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, addr);
            mprotect(addr, size, map.perms);
        }
    }
}

namespace SoList {

bool initialize() {
    SandHook::ElfImg linker("/linker");
    if (!ProtectedDataGuard::setup(linker)) return false;
    LOGD("found symbol ProtectedDataGuard");

    std::string_view somain_sym_name = linker.findSymbolNameByPrefix("__dl__ZL6somain");
    if (somain_sym_name.empty()) return false;
    LOGD("found symbol name %s", somain_sym_name.data());

    std::string_view soinfo_free_name =
        linker.findSymbolNameByPrefix("__dl__ZL11soinfo_freeP6soinfo");
    if (soinfo_free_name.empty()) return false;
    LOGD("found symbol name %s", soinfo_free_name.data());

    char llvm_sufix[llvm_suffix_length + 1];

    if (somain_sym_name.length() != strlen("__dl__ZL6somain")) {
        strncpy(llvm_sufix, somain_sym_name.data() + strlen("__dl__ZL6somain"), sizeof(llvm_sufix));
    } else {
        llvm_sufix[0] = '\0';
    }

    char solist_sym_name[sizeof("__dl__ZL6solist") + sizeof(llvm_sufix)];
    snprintf(solist_sym_name, sizeof(solist_sym_name), "__dl__ZL6solist%s", llvm_sufix);

    // the pointer solist is renamed to solist_head in Android 16
    char solist_head_sym_name[sizeof("__dl__ZL11solist_head") + sizeof(llvm_sufix)];
    snprintf(solist_head_sym_name, sizeof(solist_head_sym_name), "__dl__ZL11solist_head%s",
             llvm_sufix);

    char sonext_sym_name[sizeof("__dl__ZL6sonext") + sizeof(llvm_sufix)];
    snprintf(sonext_sym_name, sizeof(sonext_sym_name), "__dl__ZL6sonext%s", llvm_sufix);

    char vdso_sym_name[sizeof("__dl__ZL4vdso") + sizeof(llvm_sufix)];
    snprintf(vdso_sym_name, sizeof(vdso_sym_name), "__dl__ZL4vdso%s", llvm_sufix);

    solist = getStaticPointer<SoInfo>(linker, solist_sym_name);
    if (solist == nullptr) {
        solist = getStaticPointer<SoInfo>(linker, solist_head_sym_name);
        if (solist == nullptr) return false;
        LOGD("found symbol solist_head at %p", solist);
    } else {
        LOGD("found symbol solist at %p", solist);
    }

    auto *vdso = getStaticPointer<SoInfo>(linker, vdso_sym_name);
    if (vdso != nullptr) LOGD("found symbol vdso at %p", vdso);

    SoInfo::get_realpath_sym = reinterpret_cast<decltype(SoInfo::get_realpath_sym)>(
        linker.getSymbAddress("__dl__ZNK6soinfo12get_realpathEv"));
    if (SoInfo::get_realpath_sym != nullptr) LOGD("found symbol get_realpath_sym");

    SoInfo::soinfo_free =
        reinterpret_cast<decltype(SoInfo::soinfo_free)>(linker.getSymbAddress(soinfo_free_name));
    if (SoInfo::soinfo_free == nullptr) return false;
    LOGD("found symbol soinfo_free");

    g_module_load_counter = reinterpret_cast<decltype(g_module_load_counter)>(
        linker.getSymbAddress("__dl__ZL21g_module_load_counter"));
    if (g_module_load_counter != nullptr) LOGD("found symbol g_module_load_counter");

    g_module_unload_counter = reinterpret_cast<decltype(g_module_unload_counter)>(
        linker.getSymbAddress("__dl__ZL23g_module_unload_counter"));
    if (g_module_unload_counter != nullptr) LOGD("found symbol g_module_unload_counter");

    somain = getStaticPointer<SoInfo>(linker, somain_sym_name.data());
    if (somain == nullptr) return false;
    LOGD("found symbol somain at %p", somain);

    bool size_field_found = false;
    bool next_field_found = false;
    const size_t linker_realpath_size = linker.name().size();
    for (size_t i = 0; i < size_block_range / sizeof(void *); i++) {
        auto possible_size_of_somain =
            *reinterpret_cast<size_t *>(reinterpret_cast<uintptr_t>(somain) + i * sizeof(void *));
        if (!size_field_found && possible_size_of_somain < size_maximal &&
            possible_size_of_somain > size_minimal) {
            SoInfo::field_size_offset = i * sizeof(void *);
            LOGD("field_size_offset is %zu * %zu = %p", i, sizeof(void *),
                 (void *) SoInfo::field_size_offset);
            size_field_found = true;
        }

        auto possible_field = reinterpret_cast<uintptr_t>(solist) + i * sizeof(void *);
        if (!next_field_found &&
            (*reinterpret_cast<void **>(possible_field) == somain ||
             (vdso != nullptr && *reinterpret_cast<void **>(possible_field) == vdso))) {
            SoInfo::field_next_offset = i * sizeof(void *);
            LOGD("field_next_offset should be here %zu * %zu = %p", i, sizeof(void *),
                 (void *) SoInfo::field_next_offset);
            next_field_found = true;
            if (SoInfo::get_realpath_sym != nullptr) break;
        }

        if (size_field_found && next_field_found) {
            std::string *realpath = reinterpret_cast<std::string *>(
                reinterpret_cast<uintptr_t>(solist) + i * sizeof(void *));
            if (realpath->size() == linker_realpath_size) {
                char buffer[100];
                strncpy(buffer, realpath->c_str(), linker_realpath_size);
                buffer[linker_realpath_size] = '\0';
                if (strcmp(linker.name().c_str(), buffer) == 0) {
                    SoInfo::field_realpath_offset = i * sizeof(void *);
                    LOGD("field_realpath_offset is %zu * %zu = %p", i, sizeof(void *),
                         (void *) SoInfo::field_realpath_offset);
                    break;
                }
            }
        }
    }

    return size_field_found && next_field_found;
}

bool dropSoPath(const char *target_path) {
    bool path_found = false;
    if (solist == nullptr && !initialize()) {
        LOGE("failed to initialize solist before dropping paths");
        return path_found;
    }
    for (auto *iter = solist; iter; iter = iter->getNext()) {
        if (iter->getPath() && strstr(iter->getPath(), target_path)) {
            SoList::ProtectedDataGuard guard;
            LOGD("dropping solist record for %s with size %zu", iter->getPath(), iter->getSize());
            if (iter->getSize() > 0) {
                iter->setSize(0);
                SoInfo::soinfo_free(iter);
                path_found = true;
            }
        }
    }
    return path_found;
}

void resetCounters(size_t load, size_t unload) {
    if (solist == nullptr && !initialize()) {
        LOGE("failed to initialize solist before resetting counters");
        return;
    }
    if (g_module_load_counter == nullptr || g_module_unload_counter == nullptr) {
        LOGD("g_module counters not defined, skip reseting them");
        return;
    }
    auto loaded_modules = *g_module_load_counter;
    auto unloaded_modules = *g_module_unload_counter;
    if (loaded_modules >= load) {
        *g_module_load_counter = loaded_modules - load;
        LOGD("reset g_module_load_counter to %zu", (size_t) *g_module_load_counter);
    }
    if (unloaded_modules >= unload) {
        *g_module_unload_counter = unloaded_modules - unload;
        LOGD("reset g_module_unload_counter to %zu", (size_t) *g_module_unload_counter);
    }
}
}  // namespace SoList
