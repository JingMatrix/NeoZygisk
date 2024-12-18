#pragma once

#include <string>

#include "elf_util.h"
#include "logging.h"

namespace SoList {
class SoInfo {
public:
#ifdef __LP64__
    inline static size_t solist_size_offset = 0x18;
    inline static size_t solist_next_offset = 0x28;
    inline static size_t solist_realpath_offset = 0x1a8;
#else
    inline static size_t solist_size_offset = 0x90;
    inline static size_t solist_next_offset = 0xa4;
    inline static size_t solist_realpath_offset = 0x174;
#endif

    inline static const char *(*get_realpath_sym)(SoInfo *) = nullptr;
    inline static const char *(*get_soname_sym)(SoInfo *) = nullptr;
    inline static void (*soinfo_free)(SoInfo *) = nullptr;

    inline SoInfo *getNext() {
        return *reinterpret_cast<SoInfo **>(reinterpret_cast<uintptr_t>(this) + solist_next_offset);
    }

    inline size_t getSize() {
        return *reinterpret_cast<size_t *>(reinterpret_cast<uintptr_t>(this) + solist_size_offset);
    }

    inline const char *getPath() {
        if (get_realpath_sym) return get_realpath_sym(this);

        return (reinterpret_cast<std::string *>(reinterpret_cast<uintptr_t>(this) +
                                                solist_realpath_offset))
            ->c_str();
    }

    inline const char *getName() {
        if (get_soname_sym) return get_soname_sym(this);

        return (reinterpret_cast<std::string *>(reinterpret_cast<uintptr_t>(this) +
                                                solist_realpath_offset - sizeof(void *)))
            ->c_str();
    }

    void setNext(SoInfo *info) {
        *reinterpret_cast<SoInfo **>(reinterpret_cast<uintptr_t>(this) + solist_next_offset) = info;
    }

    void setSize(size_t size) {
        *reinterpret_cast<size_t *>(reinterpret_cast<uintptr_t>(this) + solist_size_offset) = size;
    }
};

class ProtectedDataGuard {
public:
    ProtectedDataGuard() {
        if (ctor != nullptr) (this->*ctor)();
    }

    ~ProtectedDataGuard() {
        if (dtor != nullptr) (this->*dtor)();
    }

    static bool setup(const SandHook::ElfImg &linker) {
        ctor = MemFunc{.data = {.p = reinterpret_cast<void *>(
                                    linker.getSymbAddress("__dl__ZN18ProtectedDataGuardC2Ev")),
                                .adj = 0}}
                   .f;
        dtor = MemFunc{.data = {.p = reinterpret_cast<void *>(
                                    linker.getSymbAddress("__dl__ZN18ProtectedDataGuardD2Ev")),
                                .adj = 0}}
                   .f;
        return ctor != nullptr && dtor != nullptr;
    }

    ProtectedDataGuard(const ProtectedDataGuard &) = delete;

    void operator=(const ProtectedDataGuard &) = delete;

private:
    using FuncType = void (ProtectedDataGuard::*)();

    inline static FuncType ctor = nullptr;
    inline static FuncType dtor = nullptr;

    union MemFunc {
        FuncType f;

        struct {
            void *p;
            std::ptrdiff_t adj;
        } data;
    };
};

static SoInfo *solist = nullptr;
static SoInfo *somain = nullptr;
static SoInfo **sonext = nullptr;

static uint64_t *g_module_load_counter = nullptr;
static uint64_t *g_module_unload_counter = nullptr;

const size_t size_block_range = 1024;
const size_t size_maximal = 0x100000;
const size_t size_minimal = 0x100;
const size_t llvm_suffix_length = 25;

template <typename T>
inline T *getStaticPointer(const SandHook::ElfImg &linker, const char *name) {
    auto *addr = reinterpret_cast<T **>(linker.getSymbAddress(name));

    return addr == nullptr ? nullptr : *addr;
}

static bool initialize() {
    SandHook::ElfImg linker("/linker");
    if (!ProtectedDataGuard::setup(linker)) return false;
    LOGD("found symbol ProtectedDataGuard");

    std::string_view solist_sym_name = linker.findSymbolNameByPrefix("__dl__ZL6solist");
    if (solist_sym_name.empty()) return false;
    LOGD("found symbol name %s", solist_sym_name.data());

    std::string_view soinfo_free_name =
        linker.findSymbolNameByPrefix("__dl__ZL11soinfo_freeP6soinfo");
    if (soinfo_free_name.empty()) return false;
    LOGD("found symbol name %s", soinfo_free_name.data());

    char llvm_sufix[llvm_suffix_length + 1];

    if (solist_sym_name.length() != strlen("__dl__ZL6solist")) {
        strncpy(llvm_sufix, solist_sym_name.data() + strlen("__dl__ZL6solist"), sizeof(llvm_sufix));
    } else {
        llvm_sufix[0] = '\0';
    }

    solist = getStaticPointer<SoInfo>(linker, solist_sym_name.data());
    if (solist == nullptr) return false;
    LOGD("found symbol solist");

    char somain_sym_name[sizeof("__dl__ZL6somain") + sizeof(llvm_sufix)];
    snprintf(somain_sym_name, sizeof(somain_sym_name), "__dl__ZL6somain%s", llvm_sufix);

    char sonext_sym_name[sizeof("__dl__ZL6sonext") + sizeof(llvm_sufix)];
    snprintf(sonext_sym_name, sizeof(somain_sym_name), "__dl__ZL6sonext%s", llvm_sufix);

    char vdso_sym_name[sizeof("__dl__ZL4vdso") + sizeof(llvm_sufix)];
    snprintf(vdso_sym_name, sizeof(vdso_sym_name), "__dl__ZL4vdso%s", llvm_sufix);

    somain = getStaticPointer<SoInfo>(linker, somain_sym_name);
    if (somain == nullptr) return false;
    LOGD("found symbol somain");

    sonext = linker.getSymbAddress<SoInfo **>(sonext_sym_name);
    if (sonext == nullptr) return false;
    LOGD("found symbol sonext");

    auto *vdso = getStaticPointer<SoInfo>(linker, vdso_sym_name);
    if (vdso != nullptr) LOGD("found symbol vdso");

    SoInfo::get_realpath_sym = reinterpret_cast<decltype(SoInfo::get_realpath_sym)>(
        linker.getSymbAddress("__dl__ZNK6soinfo12get_realpathEv"));
    if (SoInfo::get_realpath_sym == nullptr) return false;
    LOGD("found symbol get_realpath_sym");

    SoInfo::get_soname_sym = reinterpret_cast<decltype(SoInfo::get_soname_sym)>(
        linker.getSymbAddress("__dl__ZNK6soinfo10get_sonameEv"));
    if (SoInfo::get_soname_sym == nullptr) return false;
    LOGD("found symbol get_soname_sym");

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

    for (size_t i = 0; i < size_block_range / sizeof(void *); i++) {
        auto possible_field = reinterpret_cast<uintptr_t>(solist) + i * sizeof(void *);
        auto possible_size_of_somain =
            *reinterpret_cast<size_t *>(reinterpret_cast<uintptr_t>(somain) + i * sizeof(void *));
        if (possible_size_of_somain < size_maximal && possible_size_of_somain > size_minimal) {
            SoInfo::solist_size_offset = i * sizeof(void *);
            LOGD("solist_size_offset is %zu * %zu = %p", i, sizeof(void *),
                 (void *) SoInfo::solist_size_offset);
        }
        if (*reinterpret_cast<void **>(possible_field) == somain ||
            (vdso != nullptr && *reinterpret_cast<void **>(possible_field) == vdso)) {
            SoInfo::solist_next_offset = i * sizeof(void *);
            LOGD("solist_next_offset is %zu * %zu = %p", i, sizeof(void *),
                 (void *) SoInfo::solist_next_offset);
            break;
        }
    }

    return true;
}

static bool dropSoPath(const char *target_path) {
    bool path_found = false;
    if (solist == nullptr && !initialize()) {
        LOGE("failed to initialize solist");
        return path_found;
    }
    for (auto *iter = solist; iter; iter = iter->getNext()) {
        if (iter->getName() && iter->getPath() && strstr(iter->getPath(), target_path)) {
            SoList::ProtectedDataGuard guard;
            LOGI("dropping solist record for %s loaded at %s with size %zu", iter->getName(),
                 iter->getPath(), iter->getSize());
            if (iter->getSize() > 0) {
                iter->setSize(0);
                SoInfo::soinfo_free(iter);
                path_found = true;
            }
        }
    }
    return path_found;
}

static void resetCounters(size_t load, size_t unload) {
    if (solist == nullptr && !initialize()) {
        LOGE("failed to initialize solist");
        return;
    }
    if (g_module_load_counter == nullptr || g_module_unload_counter == nullptr) {
        LOGI("g_module counters not defined, skip reseting them");
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
