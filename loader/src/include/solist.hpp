#pragma once

#include <string>

#include "elf_parser.hpp"
#include "linker_soinfo.h"

namespace Linker {
class SoInfoWrapper {
public:
    inline static size_t field_size_offset = soinfo::get_size_offset();
    inline static size_t field_next_offset = soinfo::get_next_offset();
    inline static size_t field_constructor_called_offset = soinfo::get_constructors_called_offset();
    inline static size_t field_realpath_offset = soinfo::get_realpath_offset();

    inline static const char *(*get_realpath_sym)(SoInfoWrapper *) = nullptr;
    inline static void (*soinfo_free)(SoInfoWrapper *) = nullptr;
    inline static void (*soinfo_unload)(SoInfoWrapper *) = nullptr;

    inline size_t getSize() {
        return *reinterpret_cast<size_t *>(reinterpret_cast<uintptr_t>(this) + field_size_offset);
    }

    inline SoInfoWrapper *getNext() {
        return *reinterpret_cast<SoInfoWrapper **>(reinterpret_cast<uintptr_t>(this) +
                                                   field_next_offset);
    }

    inline bool getConstructorCalled() {
        return *reinterpret_cast<bool *>(reinterpret_cast<uintptr_t>(this) +
                                         field_constructor_called_offset);
    }

    inline const char *getPath() {
        if (get_realpath_sym) return get_realpath_sym(this);

        return (reinterpret_cast<std::string *>(reinterpret_cast<uintptr_t>(this) +
                                                field_realpath_offset))
            ->c_str();
    }

    void setSize(size_t size) {
        *reinterpret_cast<size_t *>(reinterpret_cast<uintptr_t>(this) + field_size_offset) = size;
    }

    void setNext(SoInfoWrapper *info) {
        *reinterpret_cast<SoInfoWrapper **>(reinterpret_cast<uintptr_t>(this) + field_next_offset) =
            info;
    }

    void setConstructorCalled(bool called) {
        *reinterpret_cast<size_t *>(reinterpret_cast<uintptr_t>(this) +
                                    field_constructor_called_offset) = called;
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

    static bool setup(const ElfParser::ElfImage &linker) {
        ctor = MemFunc{.data = {.p = reinterpret_cast<void *>(
                                    linker.findSymbolAddress("__dl__ZN18ProtectedDataGuardC2Ev")),
                                .adj = 0}}
                   .f;
        dtor = MemFunc{.data = {.p = reinterpret_cast<void *>(
                                    linker.findSymbolAddress("__dl__ZN18ProtectedDataGuardD2Ev")),
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

static SoInfoWrapper *solinker = nullptr;
static SoInfoWrapper *somain = nullptr;

static uint64_t *g_module_load_counter = nullptr;
static uint64_t *g_module_unload_counter = nullptr;

const size_t size_block_range = 1024;
const size_t size_maximal = 0x100000;
const size_t size_minimal = 0x100;
const size_t llvm_suffix_length = 25;

bool initialize();
bool findHeuristicOffsets(std::string linker_name, SoInfoWrapper *vdso);
bool dropSoPath(const char *target_pathn, bool unload);
void resetCounters(size_t load, size_t unload);

}  // namespace Linker
