#pragma once

#include <jni.h>

namespace selinux_filter {

bool is_app_zygote_process(const char *process, bool is_child_zygote);
void hook_check_access(JNIEnv *env);

}  // namespace selinux_filter
