#include "solist.hpp"

#include "logging.hpp"

namespace Linker {

bool initialize() {
    ElfParser::ElfImage linker("/linker");
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

    solinker = ElfParser::resolveSymbolPointer<SoInfoWrapper>(linker, solinker_sym_name);
    if (solinker == nullptr) {
        solinker = ElfParser::resolveSymbolPointer<SoInfoWrapper>(linker, solist_sym_name);
        if (solinker == nullptr) return false;
        LOGD("found symbol solist at %p", solinker);
    } else {
        LOGD("found symbol solinker at %p", solinker);
    }

    auto *vdso = ElfParser::resolveSymbolPointer<SoInfoWrapper>(linker, vdso_sym_name);
    if (vdso != nullptr) LOGD("found symbol vdso at %p", vdso);

    SoInfoWrapper::get_realpath_sym =
        ElfParser::findDirectSymbol<decltype(SoInfoWrapper::get_realpath_sym)>(
            linker, "__dl__ZNK6soinfo12get_realpathEv");
    if (SoInfoWrapper::get_realpath_sym != nullptr) LOGD("found symbol get_realpath_sym");

    SoInfoWrapper::soinfo_free =
        ElfParser::findDirectSymbol<decltype(SoInfoWrapper::soinfo_free)>(linker, soinfo_free_name);
    if (SoInfoWrapper::soinfo_free == nullptr) return false;
    LOGD("found symbol soinfo_free");

    SoInfoWrapper::soinfo_unload =
        ElfParser::findDirectSymbol<decltype(SoInfoWrapper::soinfo_unload)>(linker,
                                                                            soinfo_unload_name);
    if (SoInfoWrapper::soinfo_unload == nullptr) return false;
    LOGD("found symbol soinfo_unload");

    g_module_load_counter =
        ElfParser::findDirectSymbol<uint64_t>(linker, "__dl__ZL21g_module_load_counter");
    if (g_module_load_counter != nullptr) LOGD("found symbol g_module_load_counter");

    g_module_unload_counter =
        ElfParser::findDirectSymbol<uint64_t>(linker, "__dl__ZL23g_module_unload_counter");
    if (g_module_unload_counter != nullptr) LOGD("found symbol g_module_unload_counter");

    somain = ElfParser::resolveSymbolPointer<SoInfoWrapper>(linker, somain_sym_name.data());
    if (somain == nullptr) return false;
    LOGD("found symbol somain at %p", somain);

    return findHeuristicOffsets(linker.getLibraryPath(), vdso);
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
            Linker::ProtectedDataGuard guard;
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
        LOGD("reset g_module_load_counter to [%zu -> %zu]", (size_t) loaded_modules,
             (size_t) *g_module_load_counter);
    }
    if (unloaded_modules >= unload) {
        *g_module_unload_counter = unloaded_modules - unload;
        LOGD("reset g_module_unload_counter [%zu -> %zu]", (size_t) unloaded_modules,
             (size_t) *g_module_unload_counter);
    }
}
}  // namespace Linker
