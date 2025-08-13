#include <linux/mman.h>
#include <sys/mman.h>

#include <lsplt.hpp>

#include "logging.hpp"
#include "solist.hpp"
#include "zygisk.hpp"

void clean_linker_trace(const char *path, size_t loaded_modules, size_t unloaded_modules,
                        bool unload_soinfo) {
    LOGD("cleaning linker trace for path %s", path);
    if (unload_soinfo) {
        SoList::resetCounters(loaded_modules, loaded_modules);
    } else {
        SoList::resetCounters(loaded_modules, unloaded_modules);
    }
    SoList::dropSoPath(path, unload_soinfo);
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

    std::string_view soinfo_unload_name =
        linker.findSymbolNameByPrefix("__dl__ZL13soinfo_unloadP6soinfo");
    if (soinfo_unload_name.empty()) return false;
    LOGD("found symbol name %s", soinfo_unload_name.data());

    char llvm_sufix[llvm_suffix_length + 1];

    if (somain_sym_name.length() != strlen("__dl__ZL6somain")) {
        strncpy(llvm_sufix, somain_sym_name.data() + strlen("__dl__ZL6somain"), sizeof(llvm_sufix));
    } else {
        llvm_sufix[0] = '\0';
    }

    char solinker_sym_name[sizeof("__dl__ZL8solinker") + sizeof(llvm_sufix)];
    snprintf(solinker_sym_name, sizeof(solinker_sym_name), "__dl__ZL8solinker%s", llvm_sufix);

    // for SDK < 36 (Android 16), the linker binary is loaded with name solist
    char solist_sym_name[sizeof("__dl__ZL6solist") + sizeof(llvm_sufix)];
    snprintf(solist_sym_name, sizeof(solist_sym_name), "__dl__ZL6solist%s", llvm_sufix);

    char sonext_sym_name[sizeof("__dl__ZL6sonext") + sizeof(llvm_sufix)];
    snprintf(sonext_sym_name, sizeof(sonext_sym_name), "__dl__ZL6sonext%s", llvm_sufix);

    char vdso_sym_name[sizeof("__dl__ZL4vdso") + sizeof(llvm_sufix)];
    snprintf(vdso_sym_name, sizeof(vdso_sym_name), "__dl__ZL4vdso%s", llvm_sufix);

    solinker = getStaticPointer<SoInfoWrapper>(linker, solinker_sym_name);
    if (solinker == nullptr) {
        solinker = getStaticPointer<SoInfoWrapper>(linker, solist_sym_name);
        if (solinker == nullptr) return false;
        LOGD("found symbol solist at %p", solinker);
    } else {
        LOGD("found symbol solinker at %p", solinker);
    }

    auto *vdso = getStaticPointer<SoInfoWrapper>(linker, vdso_sym_name);
    if (vdso != nullptr) LOGD("found symbol vdso at %p", vdso);

    SoInfoWrapper::get_realpath_sym = reinterpret_cast<decltype(SoInfoWrapper::get_realpath_sym)>(
        linker.getSymbAddress("__dl__ZNK6soinfo12get_realpathEv"));
    if (SoInfoWrapper::get_realpath_sym != nullptr) LOGD("found symbol get_realpath_sym");

    SoInfoWrapper::soinfo_free = reinterpret_cast<decltype(SoInfoWrapper::soinfo_free)>(
        linker.getSymbAddress(soinfo_free_name));
    if (SoInfoWrapper::soinfo_free == nullptr) return false;
    LOGD("found symbol soinfo_free");

    SoInfoWrapper::soinfo_unload = reinterpret_cast<decltype(SoInfoWrapper::soinfo_unload)>(
        linker.getSymbAddress(soinfo_unload_name));
    if (SoInfoWrapper::soinfo_unload == nullptr) return false;
    LOGD("found symbol soinfo_unload");

    g_module_load_counter = reinterpret_cast<decltype(g_module_load_counter)>(
        linker.getSymbAddress("__dl__ZL21g_module_load_counter"));
    if (g_module_load_counter != nullptr) LOGD("found symbol g_module_load_counter");

    g_module_unload_counter = reinterpret_cast<decltype(g_module_unload_counter)>(
        linker.getSymbAddress("__dl__ZL23g_module_unload_counter"));
    if (g_module_unload_counter != nullptr) LOGD("found symbol g_module_unload_counter");

    somain = getStaticPointer<SoInfoWrapper>(linker, somain_sym_name.data());
    if (somain == nullptr) return false;
    LOGD("found symbol somain at %p", somain);

    return findHeuristicOffsets(linker.name(), vdso);
}

bool findHeuristicOffsets(std::string linker_name, SoInfoWrapper *vdso) {
    LOGD("Offsets in header [size, next, constructor_called, realpath]: [%p, %p, %p, %p]",
         (void *) SoInfoWrapper::field_size_offset, (void *) SoInfoWrapper::field_next_offset,
         (void *) SoInfoWrapper::field_constructor_called_offset,
         (void *) SoInfoWrapper::field_realpath_offset);

    bool size_field_found = false;
    bool next_field_found = false;
    bool constructor_called_field_found = false;

    const size_t linker_realpath_size = linker_name.size();

    for (size_t i = 0; i < size_block_range / sizeof(void *); i++) {
        auto size_of_somain =
            *reinterpret_cast<size_t *>(reinterpret_cast<uintptr_t>(somain) + i * sizeof(void *));

        if (!size_field_found) {
            if (size_of_somain < size_maximal && size_of_somain > size_minimal) {
                SoInfoWrapper::field_size_offset = i * sizeof(void *);
                LOGD("heuristic field_size_offset is %zu * %zu = %p", i, sizeof(void *),
                     reinterpret_cast<void *>(SoInfoWrapper::field_size_offset));
                size_field_found = true;
                continue;
            }
        }
        if (!size_field_found) continue;

        auto field_of_solinker = reinterpret_cast<uintptr_t>(solinker) + i * sizeof(void *);

        if (!next_field_found) {
            auto next_of_solinker = *reinterpret_cast<void **>(field_of_solinker);
            if ((next_of_solinker == somain || (vdso != nullptr && next_of_solinker == vdso))) {
                SoInfoWrapper::field_next_offset = i * sizeof(void *);
                LOGD("heuristic field_next_offset is %zu * %zu = %p", i, sizeof(void *),
                     reinterpret_cast<void *>(SoInfoWrapper::field_next_offset));
                next_field_found = true;
                continue;
            }
        }
        if (!next_field_found) continue;

        if (!constructor_called_field_found) {
            auto link_map_head_of_solinker = reinterpret_cast<link_map *>(field_of_solinker);
            // Calculate the number of alignment blocks needed to hold the address,
            // then multiply by the alignment size to get the aligned address.
            // This is an integer-based way to round UP to the next alignment boundary.
            auto index_gap = (sizeof(link_map) + sizeof(void *) - 1) / sizeof(void *);
            uintptr_t look_forward = field_of_solinker + index_gap * sizeof(void *);
            bool *constructor_called_of_solinker = reinterpret_cast<bool *>(look_forward);
            if (*constructor_called_of_solinker == true && link_map_head_of_solinker->l_addr != 0 &&
                link_map_head_of_solinker->l_name != nullptr &&
                strcmp(linker_name.c_str(), link_map_head_of_solinker->l_name) == 0) {
                SoInfoWrapper::field_constructor_called_offset =
                    look_forward - reinterpret_cast<uintptr_t>(solinker);
                LOGD("heuristic field_constructor_called_offset is %p [link_map_head: %p]",
                     reinterpret_cast<void *>(SoInfoWrapper::field_constructor_called_offset),
                     reinterpret_cast<void *>(i * sizeof(void *)));
                constructor_called_field_found = true;
                i = i + index_gap;
                continue;
            }
        }
        if (!constructor_called_field_found) continue;

        if (SoInfoWrapper::get_realpath_sym != nullptr) break;

        std::string *realpath_of_solinker = reinterpret_cast<std::string *>(field_of_solinker);
        if (realpath_of_solinker->size() == linker_realpath_size) {
            if (strcmp(linker_name.c_str(), realpath_of_solinker->c_str()) == 0) {
                SoInfoWrapper::field_realpath_offset = i * sizeof(void *);
                LOGD("heuristic field_realpath_offset is %zu * %zu = %p", i, sizeof(void *),
                     reinterpret_cast<void *>(SoInfoWrapper::field_realpath_offset));
                break;
            }
        }
    }

    return size_field_found && next_field_found && constructor_called_field_found;
}

bool dropSoPath(const char *target_path, bool unload) {
    bool path_found = false;
    if (solinker == nullptr && !initialize()) {
        LOGE("failed to initialize solist before dropping paths");
        return path_found;
    }
    for (auto *iter = solinker; iter; iter = iter->getNext()) {
        if (iter->getPath() && strstr(iter->getPath(), target_path)) {
            SoList::ProtectedDataGuard guard;
            auto size = iter->getSize();
            LOGD("dropping solist record for %s [size %zu, constructor_called: %d]",
                 iter->getPath(), size, iter->getConstructorCalled());
            if (size > 0) {
                iter->setSize(0);
                if (unload) {
                    iter->setConstructorCalled(false);
                    SoInfoWrapper::soinfo_unload(iter);
                    iter->setConstructorCalled(true);
                } else {
                    SoInfoWrapper::soinfo_free(iter);
                    iter->setSize(size);
                }
                path_found = true;
            }
        }
    }
    return path_found;
}

void resetCounters(size_t load, size_t unload) {
    if (solinker == nullptr && !initialize()) {
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
