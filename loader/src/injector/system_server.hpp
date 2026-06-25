#pragma once

#include <cstdint>
/**
 * @brief Triggers Zygisk module hooks for system_server in late-injection scenarios.
 *
 * Dynamically reconstructs the JNI environment and process state parameters
 * (UID, GID, capabilities) required to fulfill the Zygisk API contract for
 * system_server_specialize.
 */
void trigger_system_server_hooks();

enum RuntimeFlags : uint32_t {
    // Safely out of the way of AOSP's flags (Bits 0, 14-26)
    // https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/jni/com_android_internal_os_Zygote.cpp;
    LATE_INJECT = 1 << 30,
};
