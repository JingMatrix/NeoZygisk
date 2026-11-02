#pragma once

#include <jni.h>
#include <sys/types.h>

#include <cstdint>
#include <string>
#include <vector>

struct mount_info {
    unsigned int id;
    unsigned int parent;
    dev_t device;
    std::string root;
    std::string target;
    std::string vfs_options;
    std::string type;
    std::string source;
    std::string fs_options;
    std::string raw_info;
};

void hook_entry(void *start_addr, size_t block_size);

void hookJniNativeMethods(JNIEnv *env, const char *clz, JNINativeMethod *methods, int numMethods);

void clean_libc_trace();

void clean_linker_trace(const char *path, size_t loaded_modules, size_t unloaded_modules,
                        bool unload_soinfo, uintptr_t *out_base = nullptr,
                        size_t *out_size = nullptr);

bool is_anonymous_memory_enabled();
bool is_custom_linker_enabled();
bool is_lsplt_engine_configured();

struct SavedCfiShadow {
    uintptr_t dst_addr = 0;
    std::vector<uint8_t> shadow_data;
};

SavedCfiShadow backup_cfi_shadow(uintptr_t base, size_t size);
bool restore_cfi_shadow(const SavedCfiShadow &saved);

// Mark [base, base+size) as kUncheckedShadow in the CFI shadow, so cross-DSO CFI
// checks that land in a module we mapped ourselves (which bionic never
// registered) are allowed instead of aborting. No-op when no CFI shadow exists.
void register_cfi_unchecked(uintptr_t base, size_t size);

int spoof_virtual_maps(const char *path_substr, bool private_only = true,
                       bool clear_write_permission = false);
int spoof_fd_maps(int fd, bool private_only = true);
int spoof_loaded_object_maps(uintptr_t address, bool private_only = true);

void spoof_module_maps(bool clear_write_permission);

void spoof_zygote_fossil(char *search_from, char *search_to, const char *anchor);

void send_seccomp_event_if_needed();

void trigger_zygote_hooks();

std::vector<mount_info> check_zygote_traces(uint32_t info_flags, size_t round);
