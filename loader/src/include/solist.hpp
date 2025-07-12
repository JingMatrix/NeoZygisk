#pragma once

#include <string>

#include "elf_util.hpp"

namespace SoList {
class SoInfo {
public:
#ifdef __LP64__
    inline static size_t field_size_offset = 0x18;
    inline static size_t field_next_offset = 0x28;
    inline static size_t field_realpath_offset = 0x1a0;
#else
    inline static size_t field_size_offset = 0x90;
    inline static size_t field_next_offset = 0xa4;
    inline static size_t field_realpath_offset = 0x17c;
#endif

    inline static const char *(*get_realpath_sym)(SoInfo *) = nullptr;
    inline static void (*soinfo_free)(SoInfo *) = nullptr;

    inline SoInfo *getNext() {
        return *reinterpret_cast<SoInfo **>(reinterpret_cast<uintptr_t>(this) + field_next_offset);
    }

    inline size_t getSize() {
        return *reinterpret_cast<size_t *>(reinterpret_cast<uintptr_t>(this) + field_size_offset);
    }

    inline const char *getPath() {
        if (get_realpath_sym) return get_realpath_sym(this);

        return (reinterpret_cast<std::string *>(reinterpret_cast<uintptr_t>(this) +
                                                field_realpath_offset))
            ->c_str();
    }

    void setNext(SoInfo *info) {
        *reinterpret_cast<SoInfo **>(reinterpret_cast<uintptr_t>(this) + field_next_offset) = info;
    }

    void setSize(size_t size) {
        *reinterpret_cast<size_t *>(reinterpret_cast<uintptr_t>(this) + field_size_offset) = size;
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

bool initialize();
bool dropSoPath(const char *target_path);
void resetCounters(size_t load, size_t unload);

}  // namespace SoList
