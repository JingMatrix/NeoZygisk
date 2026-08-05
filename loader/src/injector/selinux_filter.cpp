#include "selinux_filter.hpp"

#include <errno.h>
#include <string.h>

#include <atomic>

#include "logging.hpp"
#include "module.hpp"

namespace selinux_filter {

using CheckSELinuxAccessFn = jboolean (*)(JNIEnv *, jclass, jstring, jstring, jstring, jstring);

static std::atomic_bool hook_in_progress{false};
static std::atomic<CheckSELinuxAccessFn> orig_check_selinux_access{nullptr};

// LSPosed's AppZygote detector probes for adb_root by writing directly to
// selinuxfs via Os.write, bypassing android.os.SELinux.checkSELinuxAccess.
// i.c("u:r:adbroot:s0") walks a three-step fallback ladder, each step an
// Os.write to a different node:
//
//   step 1  /sys/fs/selinux/context          "u:r:adbroot:s0"                       (15 bytes)
//   step 2  /sys/fs/selinux/access           "u:r:adbroot:s0 u:r:adbroot:s0 0"      (33 bytes)
//   step 3  /proc/self/attr/current          "u:r:adbroot:s0"                       (15 bytes, setcon)
//
// Step 1 already fails with EINVAL on a real device (adbroot is not a context
// you can validate), so the detector falls into step 2 regardless of us. Step 2
// is the actual signal: the 33-byte "scon tcon perm" payload to the access
// node succeeds iff the adbroot domain exists in the loaded policy. To hide
// adb_root we must make step 2 fail with EINVAL too, which then drives the
// detector into step 3 (setcon) — and that also returns EINVAL — so i.c()
// ultimately returns false and "found adb_root" is never appended.
//
// We hook libcore.io.Linux.write(FileDescriptor, byte[], int, int) and fake
// EINVAL when the payload matches either the 15-byte context literal or the
// 33-byte access-node composite. Fast path: a single length dispatch.
using OsWriteBytesFn = jint (*)(JNIEnv *, jclass, jobject, jobject, jint, jint);
static std::atomic<OsWriteBytesFn> orig_os_write{nullptr};
static std::atomic_bool os_write_hook_in_progress{false};

// Cached JNI references for android.system.ErrnoException, resolved ONCE at
// hook-install time and reused on the hot path. Os.write is one of the most
// frequently called JNI methods in app_zygote (IPC, logging, sockets), so
// calling FindClass/GetMethodID inside the hook proper would dominate the
// cost of the entire write and (under contention on the class-loading lock)
// can stall app_zygote initialization long enough to exceed the detector's
// 5s bindIsolatedService timeout, surfacing as "app zygote crashed?".
// GlobalRefs are valid for the lifetime of the process and survive the
// fork from zygote into app_zygote, so caching is safe here.
static std::atomic<jclass> errno_exception_class{nullptr};
static std::atomic<jmethodID> errno_exception_ctor{nullptr};

// Reentrancy guard: in principle the hook does no I/O of its own, but JNI
// calls can themselves take locks that race with logging threads issuing
// Os.write. A thread-local flag is essentially free and turns any such
// accidental recursion into a passthrough.
static thread_local bool in_os_write_hook = false;

constexpr const char kAdbrootPayload[] = "u:r:adbroot:s0";
constexpr jsize kAdbrootPayloadLen = static_cast<jsize>(sizeof(kAdbrootPayload) - 1);
// Composite payload written to /sys/fs/selinux/access: "<ctx> <ctx> <perm>"
// where ctx == "u:r:adbroot:s0" and perm == "0" (the int i.c passes in).
constexpr const char kAdbrootAccessPayload[] = "u:r:adbroot:s0 u:r:adbroot:s0 0";
constexpr jsize kAdbrootAccessPayloadLen = static_cast<jsize>(sizeof(kAdbrootAccessPayload) - 1);

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

// Hook for libcore.io.Linux.writeBytes(FileDescriptor, Object, int, int).
//
// Safety is the priority here: Os.write is one of the hottest syscalls in
// app_zygote (IPC, logging, sockets, ...), so the hook must NEVER perturb a
// write that isn't the adbroot probe. Three layers of gating, cheapest first:
//
//   1. Length prefilter: only byteCount == 15 or 33 are even candidates.
//      Everything else (the overwhelming majority) falls straight through.
//   2. Safe buffer read: validate the array length, use GetByteArrayRegion
//      (which never throws on in-bounds reads but does set a pending exception
//      on type/length mismatch), and bail to the original on ANY anomaly.
//   3. Exact content match against the constant payload.
//
// Only if all three gates pass do we synthesize EINVAL. This guarantees we
// cannot accidentally throw on an unrelated 15/33-byte write (the bug that
// previously crashed app_zygote and triggered the "Service connection timedout"
// warning).
static jint new_os_write(JNIEnv *env, jclass clazz, jobject fd, jobject buffer, jint byte_offset,
                         jint byte_count) {
    // Guard against accidental reentry from any JNI internal logging.
    if (__builtin_expect(in_os_write_hook, 0)) {
        OsWriteBytesFn orig = orig_os_write.load(std::memory_order_acquire);
        return orig ? orig(env, clazz, fd, buffer, byte_offset, byte_count) : -1;
    }

    do {
        if (__builtin_expect(byte_offset != 0, 1)) break;  // common: offset != 0
        if (buffer == nullptr) break;
        const char *match = nullptr;
        jsize match_len = 0;
        if (byte_count == kAdbrootPayloadLen) {
            match = kAdbrootPayload;
            match_len = kAdbrootPayloadLen;
        } else if (byte_count == kAdbrootAccessPayloadLen) {
            match = kAdbrootAccessPayload;
            match_len = kAdbrootAccessPayloadLen;
        } else {
            break;
        }

        // writeBytes' Object arg is, by contract in libcore.io.Linux, only ever
        // a byte[] (its public `write` wrapper accepts byte[] and forwards it).
        // So no IsInstanceOf / FindClass("[B") is needed here — a big win on
        // the hot path. We still bound the region read defensively.
        jsize arr_len = env->GetArrayLength(static_cast<jbyteArray>(buffer));
        if (arr_len < match_len) break;

        jbyte buf[33];
        env->GetByteArrayRegion(static_cast<jbyteArray>(buffer), 0, match_len, buf);
        if (__builtin_expect(env->ExceptionCheck(), 0)) {
            env->ExceptionClear();
            break;
        }
        if (memcmp(buf, match, match_len) != 0) break;

        // All gates passed: this is the adbroot probe. Synthesize EINVAL using
        // the cached class/method (no FindClass on this path).
        jclass ex_class = errno_exception_class.load(std::memory_order_acquire);
        jmethodID ctor = errno_exception_ctor.load(std::memory_order_acquire);
        if (ex_class == nullptr || ctor == nullptr) break;

        in_os_write_hook = true;
        jstring sys = env->NewStringUTF("write");
        jobject ex = env->NewObject(ex_class, ctor, sys, EINVAL);
        in_os_write_hook = false;

        if (ex == nullptr) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            break;
        }
        env->Throw(reinterpret_cast<jthrowable>(ex));
        LOGI("filtered adbroot probe (%d bytes)", match_len);
        return -1;
    } while (false);

    OsWriteBytesFn orig = orig_os_write.load(std::memory_order_acquire);
    if (orig == nullptr) {
        // Hook was never installed successfully; surface EBADF just like Os.write
        // does when called with an invalid descriptor, rather than crashing.
        jclass ex_class = errno_exception_class.load(std::memory_order_acquire);
        if (ex_class != nullptr) {
            env->ThrowNew(ex_class, "write");
        }
        return -1;
    }
    return orig(env, clazz, fd, buffer, byte_offset, byte_count);
}

static void hook_os_write(JNIEnv *env) {
    if (orig_os_write.load(std::memory_order_acquire) != nullptr) return;

    bool expected = false;
    if (!os_write_hook_in_progress.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel, std::memory_order_acquire)) {
        return;
    }

    // Resolve android.system.ErrnoException and its (String, int) ctor ONCE,
    // pinning them as GlobalRefs for the hot path. Doing FindClass inside
    // new_os_write would dominate the cost of every matching Os.write and
    // risk contention on the class-loading lock during app_zygote init.
    if (errno_exception_class.load(std::memory_order_acquire) == nullptr) {
        jclass local = env->FindClass("android/system/ErrnoException");
        if (local == nullptr) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            LOGW("failed to find android/system/ErrnoException");
            os_write_hook_in_progress.store(false, std::memory_order_release);
            return;
        }
        jobject global = env->NewGlobalRef(local);
        env->DeleteLocalRef(local);
        if (global == nullptr) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            LOGW("failed to pin ErrnoException global ref");
            os_write_hook_in_progress.store(false, std::memory_order_release);
            return;
        }
        jclass expected_null = nullptr;
        if (!errno_exception_class.compare_exchange_strong(expected_null,
                static_cast<jclass>(global), std::memory_order_release,
                std::memory_order_acquire)) {
            env->DeleteGlobalRef(global);  // another thread won the race
        }

        jmethodID ctor = env->GetMethodID(static_cast<jclass>(global),
                                          "<init>", "(Ljava/lang/String;I)V");
        if (ctor == nullptr) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            LOGW("failed to find ErrnoException ctor");
            os_write_hook_in_progress.store(false, std::memory_order_release);
            return;
        }
        errno_exception_ctor.store(ctor, std::memory_order_release);
    }

    // The native backing of android.system.Os.write is
    // libcore.io.Linux.writeBytes(FileDescriptor, Object, int, int), NOT
    // "write" (which is a plain Java wrapper and would be skipped by
    // hook_jni_methods' NATIVE modifier check, leaving fnPtr null and the
    // hook silently uninstalled). The buffer arg is typed Object in the JNI
    // signature but in practice always a byte[]; we treat it as jbyteArray.
    JNINativeMethod method = {
        "writeBytes",
        "(Ljava/io/FileDescriptor;Ljava/lang/Object;II)I",
        reinterpret_cast<void *>(new_os_write),
    };

    g_hook->hook_jni_methods(env, "libcore/io/Linux", {&method, 1});
    OsWriteBytesFn orig = reinterpret_cast<OsWriteBytesFn>(method.fnPtr);
    if (orig != nullptr && orig != new_os_write) {
        orig_os_write.store(orig, std::memory_order_release);
        LOGI("hooked libcore.io.Linux.writeBytes for app_zygote");
    } else {
        LOGW("failed to hook libcore.io.Linux.writeBytes");
        os_write_hook_in_progress.store(false, std::memory_order_release);
    }
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

    // LSPosed's detector reaches selinuxfs directly via Os.write, which the
    // SELinux.checkSELinuxAccess hook above cannot observe. Install the
    // Os.write hook as well so the adbroot probe can be filtered.
    hook_os_write(env);
}

}  // namespace selinux_filter
