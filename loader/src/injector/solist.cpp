#include "solist.hpp"

#include <algorithm>
#include <vector>

#include "logging.hpp"

namespace Linker {

bool initialize() {
    ElfParser::ElfImage linker("/linker");
    if (!ProtectedDataGuard::setup(linker)) return false;
    LOGV("found symbol ProtectedDataGuard");

    std::string_view somain_sym_name = linker.findSymbolNameByPrefix("__dl__ZL6somain");
    if (somain_sym_name.empty()) return false;
    LOGV("found symbol name %s", somain_sym_name.data());

    std::string_view soinfo_free_name =
        linker.findSymbolNameByPrefix("__dl__ZL11soinfo_freeP6soinfo");
    if (soinfo_free_name.empty()) return false;
    LOGV("found symbol name %s", soinfo_free_name.data());

    std::string_view soinfo_unload_name =
        linker.findSymbolNameByPrefix("__dl__ZL13soinfo_unloadP6soinfo");
    if (soinfo_unload_name.empty()) return false;
    LOGV("found symbol name %s", soinfo_unload_name.data());

    // The .llvm.<hash> suffix has no fixed width; Android 17 ships a 26-character one.
    const std::string llvm_sufix(somain_sym_name.substr(strlen("__dl__ZL6somain")));

    const std::string solinker_sym_name = "__dl__ZL8solinker" + llvm_sufix;
    // for SDK < 36 (Android 16), the linker binary is loaded with name solist
    const std::string solist_sym_name = "__dl__ZL6solist" + llvm_sufix;
    const std::string sonext_sym_name = "__dl__ZL6sonext" + llvm_sufix;
    const std::string vdso_sym_name = "__dl__ZL4vdso" + llvm_sufix;

    solinker = ElfParser::resolveSymbolPointer<SoInfoWrapper>(linker, solinker_sym_name);
    if (solinker == nullptr) {
        solinker = ElfParser::resolveSymbolPointer<SoInfoWrapper>(linker, solist_sym_name);
        if (solinker == nullptr) return false;
        LOGV("found symbol solist at %p", solinker);
    } else {
        LOGV("found symbol solinker at %p", solinker);
    }

    auto *vdso = ElfParser::resolveSymbolPointer<SoInfoWrapper>(linker, vdso_sym_name);
    if (vdso != nullptr) LOGV("found symbol vdso at %p", vdso);

    SoInfoWrapper::get_realpath_sym =
        ElfParser::findDirectSymbol<decltype(SoInfoWrapper::get_realpath_sym)>(
            linker, "__dl__ZNK6soinfo12get_realpathEv");
    if (SoInfoWrapper::get_realpath_sym != nullptr) LOGV("found symbol get_realpath_sym");

    SoInfoWrapper::soinfo_free =
        ElfParser::findDirectSymbol<decltype(SoInfoWrapper::soinfo_free)>(linker, soinfo_free_name);
    if (SoInfoWrapper::soinfo_free == nullptr) return false;
    LOGV("found symbol soinfo_free");

    SoInfoWrapper::soinfo_unload =
        ElfParser::findDirectSymbol<decltype(SoInfoWrapper::soinfo_unload)>(linker,
                                                                            soinfo_unload_name);
    if (SoInfoWrapper::soinfo_unload == nullptr) return false;
    LOGV("found symbol soinfo_unload");

    g_module_load_counter =
        ElfParser::findDirectSymbol<uint64_t>(linker, "__dl__ZL21g_module_load_counter");
    if (g_module_load_counter != nullptr) LOGV("found symbol g_module_load_counter");

    g_module_unload_counter =
        ElfParser::findDirectSymbol<uint64_t>(linker, "__dl__ZL23g_module_unload_counter");
    if (g_module_unload_counter != nullptr) LOGV("found symbol g_module_unload_counter");

    somain = ElfParser::resolveSymbolPointer<SoInfoWrapper>(linker, somain_sym_name.data());
    if (somain == nullptr) return false;
    LOGV("found symbol somain at %p", somain);

    return findHeuristicOffsets(linker.getLibraryPath(), vdso);
}

bool findHeuristicOffsets(std::string linker_name, SoInfoWrapper *vdso) {
    LOGV("Offsets in header [size, next, constructor_called, realpath]: [%p, %p, %p, %p]",
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
                SoInfoWrapper::field_base_offset =
                    SoInfoWrapper::field_size_offset - sizeof(ElfW(Addr));
                LOGV("heuristic field_size_offset is %zu * %zu = %p (base at %p)", i,
                     sizeof(void *), reinterpret_cast<void *>(SoInfoWrapper::field_size_offset),
                     reinterpret_cast<void *>(SoInfoWrapper::field_base_offset));
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
                LOGV("heuristic field_next_offset is %zu * %zu = %p", i, sizeof(void *),
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
                LOGV("heuristic field_constructor_called_offset is %p [link_map_head: %p]",
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
                LOGV("heuristic field_realpath_offset is %zu * %zu = %p", i, sizeof(void *),
                     reinterpret_cast<void *>(SoInfoWrapper::field_realpath_offset));
                break;
            }
        }
    }

    return size_field_found && next_field_found && constructor_called_field_found;
}

void dumpSoPath(const char *needle, const char *when) {
    if (solinker == nullptr && !initialize()) return;
    size_t n = 0;
    for (auto *iter = solinker; iter; iter = iter->getNext()) {
        if (iter->getPath() && strstr(iter->getPath(), needle)) {
            LOGV("[%s] solist record %p size %zu for %s", when, (void *) iter, iter->getSize(),
                 iter->getPath());
            n++;
        }
    }
    LOGV("[%s] %zu record(s) matching \"%s\"", when, n, needle);
}

bool dropSoPath(const char *target_path, bool unload, uintptr_t *out_base, size_t *out_size) {
    bool path_found = false;
    if (solinker == nullptr && !initialize()) {
        LOGE("failed to initialize solist before dropping paths");
        return path_found;
    }

    // soinfo_free zeroes the block, so walking the list while dropping stops after the
    // first hit. Release highest block first: the allocator is LIFO, so that hands them
    // back in ascending order and the allocation sequence stays monotonic.
    std::vector<SoInfoWrapper *> targets;
    for (auto *iter = solinker; iter; iter = iter->getNext()) {
        if (iter->getPath() && strstr(iter->getPath(), target_path) && iter->getSize() > 0) {
            targets.push_back(iter);
        }
    }
    std::sort(targets.begin(), targets.end(), [](SoInfoWrapper *a, SoInfoWrapper *b) {
        return reinterpret_cast<uintptr_t>(a) > reinterpret_cast<uintptr_t>(b);
    });

    for (auto *target : targets) {
        // A previous unload may have taken this one with it; a double unload aborts.
        bool still_linked = false;
        for (auto *iter = solinker; iter; iter = iter->getNext()) {
            if (iter == target) {
                still_linked = true;
                break;
            }
        }
        if (!still_linked) {
            LOGV("solist record %p went away with an earlier unload", (void *) target);
            continue;
        }

        Linker::ProtectedDataGuard guard;
        auto size = target->getSize();
        if (size == 0) continue;
        LOGV("dropping solist record %p for %s [size %zu, constructor_called: %d]",
             (void *) target, target->getPath(), size, target->getConstructorCalled());
        if (out_base != nullptr && *out_base == 0) *out_base = target->getBase();
        if (out_size != nullptr && *out_size == 0) *out_size = size;
        target->setSize(0);
        if (unload) {
            target->setConstructorCalled(false);
            SoInfoWrapper::soinfo_unload(target);
            target->setConstructorCalled(true);
        } else {
            SoInfoWrapper::soinfo_free(target);
            target->setSize(size);
        }
        path_found = true;
    }
    return path_found;
}

void resetCounters(size_t load, size_t unload) {
    if (solinker == nullptr && !initialize()) {
        LOGE("failed to initialize solist before resetting counters");
        return;
    }
    if (g_module_load_counter == nullptr || g_module_unload_counter == nullptr) {
        LOGV("g_module counters not defined, skip reseting them");
        return;
    }
    auto loaded_modules = *g_module_load_counter;
    auto unloaded_modules = *g_module_unload_counter;
    if (loaded_modules >= load) {
        *g_module_load_counter = loaded_modules - load;
        LOGV("reset g_module_load_counter: [%zu -> %zu]", (size_t) loaded_modules,
             (size_t) *g_module_load_counter);
    }
    if (unloaded_modules >= unload) {
        *g_module_unload_counter = unloaded_modules - unload;
        LOGV("reset g_module_unload_counter: [%zu -> %zu]", (size_t) unloaded_modules,
             (size_t) *g_module_unload_counter);
    }
}
}  // namespace Linker
