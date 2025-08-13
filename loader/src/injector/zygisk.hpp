#pragma once

#include <jni.h>
#include <sys/types.h>

void hook_entry(void *start_addr, size_t block_size);

void hookJniNativeMethods(JNIEnv *env, const char *clz, JNINativeMethod *methods, int numMethods);

void clean_linker_trace(const char *path, size_t loaded_modules, size_t unloaded_modules,
                        bool unload_soinfo);

void spoof_virtual_maps(const char *path, bool clear_write_permission);

void send_seccomp_event_if_needed();
