#pragma once

#include <jni.h>
#include <sys/types.h>

#include <string>

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

void clean_linker_trace(const char *path, size_t loaded_modules, size_t unloaded_modules,
                        bool unload_soinfo);

void spoof_virtual_maps(const char *path, bool clear_write_permission);

void spoof_zygote_fossil(char *search_from, char *search_to, const char *anchor);

void send_seccomp_event_if_needed();

std::vector<mount_info> check_zygote_traces(uint32_t info_flags);
