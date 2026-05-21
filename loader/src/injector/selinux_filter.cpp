#include "selinux_filter.hpp"

#include <string.h>

#include <atomic>

#include "logging.hpp"
#include "module.hpp"

namespace selinux_filter {

using CheckSELinuxAccessFn = jboolean (*)(JNIEnv *, jclass, jstring, jstring, jstring, jstring);

static std::atomic_bool hook_in_progress{false};
static std::atomic<CheckSELinuxAccessFn> orig_check_selinux_access{nullptr};

struct ScopedStringChars {
    JNIEnv *env = nullptr;
    jstring str = nullptr;
    const jchar *value = nullptr;
    jsize length = 0;

    ScopedStringChars(JNIEnv *env, jstring str, jsize known_length = -1) : env(env), str(str) {
        if (env != nullptr && str != nullptr) {
            length = known_length >= 0 ? known_length : env->GetStringLength(str);
            value = env->GetStringChars(str, nullptr);
            if (value == nullptr && env->ExceptionCheck()) env->ExceptionClear();
        }
    }

    ~ScopedStringChars() {
        if (env != nullptr && str != nullptr && value != nullptr) {
            env->ReleaseStringChars(str, value);
        }
    }

    bool valid() const { return value != nullptr; }
};

static bool same_cached_ref(JNIEnv *env, jstring str, const std::atomic<jobject> &cached) {
    jobject ref = cached.load(std::memory_order_acquire);
    return ref != nullptr && env->IsSameObject(str, ref);
}

static void cache_ref(JNIEnv *env, jstring str, std::atomic<jobject> &cached) {
    if (cached.load(std::memory_order_acquire) != nullptr) return;

    jobject global = env->NewGlobalRef(str);
    if (global == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return;
    }

    jobject expected = nullptr;
    if (!cached.compare_exchange_strong(expected, global, std::memory_order_release,
                                        std::memory_order_relaxed)) {
        env->DeleteGlobalRef(global);
    }
}

bool is_app_zygote_process(const char *process, bool is_child_zygote) {
    return is_child_zygote || (process != nullptr && strstr(process, "app_zygote") != nullptr);
}

static bool chars_equal_ascii(const jchar *chars, jsize length, const char *ascii,
                              jsize ascii_len) {
    if (chars == nullptr || ascii == nullptr) return false;
    if (ascii_len != length) return false;

    for (jsize i = 0; i < length; ++i) {
        if (chars[i] != static_cast<jchar>(static_cast<unsigned char>(ascii[i]))) return false;
    }
    return true;
}

struct CachedAsciiMatcher {
    const char *ascii;
    jsize length;
    std::atomic<jobject> cached;

    CachedAsciiMatcher(const char *ascii, jsize length)
        : ascii(ascii), length(length), cached(nullptr) {}

    bool matches(JNIEnv *env, jstring str, jsize known_length = -1) {
        if (env == nullptr || str == nullptr) return false;
        if (same_cached_ref(env, str, cached)) return true;

        jsize str_len = known_length >= 0 ? known_length : env->GetStringLength(str);
        if (str_len != length) return false;

        ScopedStringChars chars(env, str, str_len);
        if (!chars.valid() || !chars_equal_ascii(chars.value, chars.length, ascii, length)) {
            return false;
        }

        cache_ref(env, str, cached);
        return true;
    }
};

struct ContextTypeMatcher {
    const char *type;
    jsize length;
    std::atomic<jobject> cached;

    ContextTypeMatcher(const char *type, jsize length)
        : type(type), length(length), cached(nullptr) {}

    bool matches(JNIEnv *env, jstring context, jsize known_length = -1);
};

static bool context_type_eq_ascii(const ScopedStringChars &context, const char *type,
                                  jsize type_len) {
    if (!context.valid() || type == nullptr) return false;
    if (chars_equal_ascii(context.value, context.length, type, type_len)) return true;

    int colons = 0;
    jsize type_start = -1;
    for (jsize i = 0; i < context.length; ++i) {
        if (context.value[i] != ':') continue;
        if (++colons == 2) {
            type_start = i + 1;
            break;
        }
    }
    if (type_start < 0 || type_start >= context.length) return false;

    jsize type_end = type_start;
    while (type_end < context.length && context.value[type_end] != ':') {
        type_end++;
    }

    return chars_equal_ascii(context.value + type_start, type_end - type_start, type, type_len);
}

bool ContextTypeMatcher::matches(JNIEnv *env, jstring context, jsize known_length) {
    if (env == nullptr || context == nullptr) return false;
    if (same_cached_ref(env, context, cached)) return true;

    jsize context_len = known_length >= 0 ? known_length : env->GetStringLength(context);
    if (context_len < length || (context_len != length && context_len < length + 7)) {
        return false;
    }

    ScopedStringChars chars(env, context, context_len);
    if (!context_type_eq_ascii(chars, type, length)) return false;

    cache_ref(env, context, cached);
    return true;
}

static jboolean new_check_selinux_access(JNIEnv *env, jclass clazz, jstring scon, jstring tcon,
                                         jstring tclass, jstring perm) {
#define ASCII_LEN(STR) static_cast<jsize>(sizeof(STR) - 1)
    static CachedAsciiMatcher process("process", ASCII_LEN("process"));
    static CachedAsciiMatcher transition("transition", ASCII_LEN("transition"));
    static CachedAsciiMatcher binder("binder", ASCII_LEN("binder"));
    static CachedAsciiMatcher call("call", ASCII_LEN("call"));
    static CachedAsciiMatcher capability("capability", ASCII_LEN("capability"));
    static CachedAsciiMatcher sys_admin("sys_admin", ASCII_LEN("sys_admin"));
    static ContextTypeMatcher shell("shell", ASCII_LEN("shell"));
    static ContextTypeMatcher su("su", ASCII_LEN("su"));
    static ContextTypeMatcher adbd("adbd", ASCII_LEN("adbd"));
    static ContextTypeMatcher adbroot("adbroot", ASCII_LEN("adbroot"));
    static ContextTypeMatcher fsck_untrusted_source("fsck_untrusted", ASCII_LEN("fsck_untrusted"));
    static ContextTypeMatcher fsck_untrusted_target("fsck_untrusted", ASCII_LEN("fsck_untrusted"));
#undef ASCII_LEN
    jsize class_len = tclass != nullptr ? env->GetStringLength(tclass) : -1;
    jsize perm_len = perm != nullptr ? env->GetStringLength(perm) : -1;

    enum DirtyRule {
        DIRTY_NONE,
        DIRTY_SHELL_SU_TRANSITION,
        DIRTY_ADBD_ADBROOT_BINDER,
        DIRTY_FSCK_SYS_ADMIN,
    } rule = DIRTY_NONE;

    if (class_len == process.length && perm_len == transition.length &&
        process.matches(env, tclass, class_len) && transition.matches(env, perm, perm_len)) {
        rule = DIRTY_SHELL_SU_TRANSITION;
    } else if (class_len == binder.length && perm_len == call.length &&
               binder.matches(env, tclass, class_len) && call.matches(env, perm, perm_len)) {
        rule = DIRTY_ADBD_ADBROOT_BINDER;
    } else if (class_len == capability.length && perm_len == sys_admin.length &&
               capability.matches(env, tclass, class_len) && sys_admin.matches(env, perm, perm_len)) {
        rule = DIRTY_FSCK_SYS_ADMIN;
    }

    if (rule != DIRTY_NONE) {
        bool filtered = false;

        switch (rule) {
        case DIRTY_SHELL_SU_TRANSITION:
            filtered = shell.matches(env, scon) && su.matches(env, tcon);
            break;
        case DIRTY_ADBD_ADBROOT_BINDER:
            filtered = adbd.matches(env, scon) && adbroot.matches(env, tcon);
            break;
        case DIRTY_FSCK_SYS_ADMIN:
            filtered =
                fsck_untrusted_source.matches(env, scon) && fsck_untrusted_target.matches(env, tcon);
            break;
        case DIRTY_NONE:
            break;
        }

        if (filtered) {
            LOGI("filtered SELinux.checkSELinuxAccess rule %d", rule);
            return JNI_FALSE;
        }
    }

    CheckSELinuxAccessFn orig = orig_check_selinux_access.load(std::memory_order_acquire);
    if (orig == nullptr) return JNI_FALSE;
    return orig(env, clazz, scon, tcon, tclass, perm);
}

void hook_check_access(JNIEnv *env) {
    if (orig_check_selinux_access.load(std::memory_order_acquire) != nullptr) return;

    bool expected = false;
    if (!hook_in_progress.compare_exchange_strong(expected, true, std::memory_order_acq_rel,
                                                  std::memory_order_acquire)) {
        return;
    }

    JNINativeMethod method = {
        "checkSELinuxAccess",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z",
        reinterpret_cast<void *>(new_check_selinux_access),
    };

    g_hook->hook_jni_methods(env, "android/os/SELinux", {&method, 1});
    CheckSELinuxAccessFn orig = reinterpret_cast<CheckSELinuxAccessFn>(method.fnPtr);
    if (orig != nullptr && orig != new_check_selinux_access) {
        orig_check_selinux_access.store(orig, std::memory_order_release);
        LOGI("hooked android.os.SELinux.checkSELinuxAccess for app_zygote");
    } else {
        LOGW("failed to hook android.os.SELinux.checkSELinuxAccess");
        hook_in_progress.store(false, std::memory_order_release);
    }
}

}  // namespace selinux_filter
