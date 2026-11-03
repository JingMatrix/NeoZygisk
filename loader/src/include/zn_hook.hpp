#pragma once

#include <android/log.h>
#include <sys/types.h>

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#if defined(__riscv)
#include <dobby_compat.h>
#else
#include <dobby.h>
#include <bytehook.h>
#endif

#include <lsplt.hpp>
#include "elf_util.h"
#include "logging.hpp"

namespace zn::hook {

enum class PltEngine { kByteHook, kLsplt };

inline PltEngine g_plt_engine = PltEngine::kByteHook;
inline bool g_plt_engine_initialized = false;

inline void setPltEngine(PltEngine e) {
    g_plt_engine = e;
    g_plt_engine_initialized = true;
}

inline void initPltEngineFromConfig() {
    FILE* fp = fopen("/data/adb/nyazygisk/config.prop", "r");
    if (!fp) return;
    char line[128];
    while (fgets(line, sizeof(line), fp)) {
        char* end = line + strlen(line);
        while (end > line && (end[-1] == '\n' || end[-1] == '\r' || end[-1] == ' ' || end[-1] == '\t')) {
            *--end = '\0';
        }
        if (strcmp(line, "plt_engine=lsplt") == 0) {
            g_plt_engine = PltEngine::kLsplt;
            break;
        } else if (strcmp(line, "plt_engine=bytehook") == 0) {
            g_plt_engine = PltEngine::kByteHook;
            break;
        }
    }
    fclose(fp);
    g_plt_engine_initialized = true;
    LOGI("ZN hook: selected PLT engine: %s", g_plt_engine == PltEngine::kByteHook ? "ByteHook" : "LSPlt");
}

inline PltEngine getPltEngine() {
    if (!g_plt_engine_initialized) {
        initPltEngineFromConfig();
    }
    return g_plt_engine;
}

#ifndef __riscv
inline std::once_flag g_bytehook_init_once;
inline int g_bytehook_init_result = -1;
inline std::mutex g_bytehook_mutex;
inline std::map<std::string, bytehook_stub_t> g_bytehook_stubs;
inline std::map<std::string, void*> g_bytehook_originals;

inline bool bytehookInit() {
    std::call_once(g_bytehook_init_once, [] {
        g_bytehook_init_result = bytehook_init(BYTEHOOK_MODE_MANUAL, false);
    });
    if (g_bytehook_init_result != 0) {
        LOGE("ZN hook: bytehook_init failed: %d", g_bytehook_init_result);
        return false;
    }
    LOGI("ZN hook: ByteHook engine initialized successfully");
    return true;
}

extern "C" {
static void bytehookHookedCallback(bytehook_stub_t stub, int status_code,
                                   const char* caller_path_name, const char* sym_name,
                                   void* new_func, void* prev_func, void* arg) {
    (void)stub;
    (void)caller_path_name;
    (void)sym_name;
    (void)new_func;
    if (status_code == 0 && prev_func) {
        auto* out = static_cast<void**>(arg);
        if (out && *out == nullptr) *out = prev_func;
    }
}
}

inline bool bytehookHook(const std::string& caller_path, const char* symbol, void* replacement,
                         void** original) {
    if (!bytehookInit()) return false;

    const std::string key = caller_path + "\x01" + symbol;
    {
        std::lock_guard<std::mutex> lk(g_bytehook_mutex);
        auto stub_it = g_bytehook_stubs.find(key);
        if (stub_it != g_bytehook_stubs.end()) {
            if (replacement == g_bytehook_originals[key]) {
                if (bytehook_unhook(stub_it->second) != 0) {
                    LOGE("ZN pltHook %s: bytehook_unhook failed", symbol);
                    return false;
                }
                if (original) *original = g_bytehook_originals[key];
                g_bytehook_originals.erase(key);
                g_bytehook_stubs.erase(stub_it);
                return true;
            }
            LOGW("ZN pltHook %s: %s already hooked with different handler", symbol, caller_path.c_str());
            return false;
        }
    }

    void* backup = nullptr;
    const bytehook_stub_t stub =
        bytehook_hook_single(caller_path.c_str(), nullptr, symbol, replacement,
                             bytehookHookedCallback, &backup);
    if (!stub) {
        LOGE("ZN pltHook %s: bytehook_hook_single failed for %s", symbol, caller_path.c_str());
        return false;
    }
    if (!backup) {
        LOGE("ZN pltHook %s: no matching relocation found in %s", symbol, caller_path.c_str());
        bytehook_unhook(stub);
        return false;
    }

    {
        std::lock_guard<std::mutex> lk(g_bytehook_mutex);
        g_bytehook_stubs[key] = stub;
        g_bytehook_originals[key] = backup;
    }
    if (original) *original = backup;
    return true;
}
#endif

inline bool lspltHook(dev_t dev, ino_t inode, const char* symbol, void* replacement,
                      void** original) {
    void* backup = nullptr;
    if (!lsplt::RegisterHook(dev, inode, symbol, replacement, &backup)) {
        LOGE("ZN pltHook %s: RegisterHook failed", symbol);
        return false;
    }
    if (!lsplt::CommitHook()) {
        LOGE("ZN pltHook %s: CommitHook failed", symbol);
        return false;
    }
    if (!backup) {
        LOGE("ZN pltHook %s: symbol not found in PLT", symbol);
        return false;
    }
    if (original) *original = backup;
    return true;
}

inline const znn::MapEntry* findTargetEntry(const std::vector<znn::MapEntry>& maps, uintptr_t base) {
    const znn::MapEntry* hit = nullptr;
    for (const auto& m : maps) {
        if (m.inode == 0) continue;
        if ((base >= m.start && base < m.end) || (m.start >= m.offset && base == m.start - m.offset)) {
            hit = &m;
            break;
        }
    }
    if (!hit) return nullptr;
    // Prefer offset 0 mapping for file identity
    for (const auto& m : maps) {
        if (m.dev == hit->dev && m.inode == hit->inode && m.offset == 0) return &m;
    }
    return hit;
}

inline bool pltHook(void* base, const char* symbol, void* hook, void** original) {
    if (!base || !symbol || !hook) return false;

    const uintptr_t b = reinterpret_cast<uintptr_t>(base);
    const auto maps = znn::parseMaps("self");
    const znn::MapEntry* entry = findTargetEntry(maps, b);
    if (!entry) {
        LOGE("ZN pltHook %s: base %p not found in maps", symbol, base);
        return false;
    }

    LOGI("ZN pltHook base=%p symbol=%s (path=%s)", base, symbol, entry->path.c_str());

#ifndef __riscv
    if (getPltEngine() == PltEngine::kByteHook) {
        if (bytehookHook(entry->path, symbol, hook, original)) {
            return true;
        }
        LOGW("ZN pltHook %s: ByteHook failed, falling back to LSPlt", symbol);
    }
#endif

    return lspltHook(entry->dev, entry->inode, symbol, hook, original);
}

inline bool inlineHook(void* target, void* addr, void** original) {
    if (!target || !addr) return false;
    return DobbyHook(target, reinterpret_cast<dobby_dummy_func_t>(addr),
                     reinterpret_cast<dobby_dummy_func_t*>(original)) == RT_SUCCESS;
}

inline bool inlineUnhook(void* target) {
    if (!target) return false;
    return DobbyDestroy(target) == RT_SUCCESS;
}

}  // namespace zn::hook
