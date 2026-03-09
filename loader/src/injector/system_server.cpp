#include "system_server.hpp"

#include <dlfcn.h>
#include <jni.h>
#include <linux/capability.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstring>
#include <vector>

#include "logging.hpp"
#include "module.hpp"

namespace {

/**
 * @brief RAII wrapper to safely obtain JNIEnv and manage thread attachment lifecycle.
 */
class JniAttachment {
public:
    JniAttachment() {
        // auto cached_map_infos = lsplt::MapInfo::Scan();
        // void* libart;
        // for (auto& map : cached_map_infos) {
        //     if (map.path.ends_with("/libart.so")) {
        //         LOGV("found path %s", map.path.data());
        //         libart = dlopen(map.path.data(), RTLD_NOLOAD | RTLD_NOW);
        //         if (!libart) {
        //             libart = dlopen("libart.so", RTLD_NOW);
        //         }
        //         break;
        //     }
        // }

        // if (!libart) {
        //     LOGE("failed to get libart.so handle");
        //     return;
        // }

        using JNI_GetCreatedJavaVMs_t = jint (*)(JavaVM**, jsize, jsize*);

        // Pass RTLD_DEFAULT instead of a specific library handle
        auto get_vms =
            reinterpret_cast<JNI_GetCreatedJavaVMs_t>(dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs"));

        if (!get_vms) {
            LOGE("failed to find JNI_GetCreatedJavaVMs in libart");
            return;
        }

        jsize num_vms = 0;
        if (get_vms(&vm_, 1, &num_vms) != JNI_OK || num_vms == 0 || !vm_) {
            LOGE("failed to get created JavaVM");
            return;
        }

        jint env_res = vm_->GetEnv(reinterpret_cast<void**>(&env_), JNI_VERSION_1_6);
        if (env_res == JNI_EDETACHED) {
            LOGI("current thread is detached from JVM, attaching temporarily...");
            JavaVMAttachArgs args{JNI_VERSION_1_6, "NeoZygisk-Injector", nullptr};
            if (vm_->AttachCurrentThread(&env_, &args) == JNI_OK) {
                attached_ = true;
            } else {
                LOGE("failed to attach current thread to JavaVM");
                env_ = nullptr;
            }
        }
    }

    ~JniAttachment() {
        if (attached_ && vm_) {
            LOGV("detaching temporary injector thread from JVM");
            vm_->DetachCurrentThread();
        }
    }

    JNIEnv* get_env() const { return env_; }

private:
    JavaVM* vm_ = nullptr;
    JNIEnv* env_ = nullptr;
    bool attached_ = false;
};

/**
 * @brief Retrieves current process capabilities and maps them to jlong.
 */
void fetch_capabilities(jlong& permitted, jlong& effective) {
    struct __user_cap_header_struct capheader;
    struct __user_cap_data_struct capdata[2];
    memset(&capheader, 0, sizeof(capheader));
    memset(&capdata, 0, sizeof(capdata));
    capheader.version = _LINUX_CAPABILITY_VERSION_3;  // 64-bit caps
    capheader.pid = 0;                                // Self

    if (syscall(__NR_capget, &capheader, &capdata) == 0) {
        permitted = (static_cast<jlong>(capdata[1].permitted) << 32) | capdata[0].permitted;
        effective = (static_cast<jlong>(capdata[1].effective) << 32) | capdata[0].effective;
    } else {
        LOGW("failed to read capabilities via capget, using 0");
        permitted = 0;
        effective = 0;
    }
}

/**
 * @brief Retrieves current supplementary groups and allocates a JNI IntArray.
 */
jintArray fetch_gids(JNIEnv* env) {
    int count = getgroups(0, nullptr);
    if (count <= 0) {
        return env->NewIntArray(0);
    }

    std::vector<gid_t> gids(count);
    getgroups(count, gids.data());

    // Convert gid_t (usually 32-bit unsigned) to jint (32-bit signed)
    std::vector<jint> j_gids(count);
    for (int i = 0; i < count; ++i) {
        j_gids[i] = static_cast<jint>(gids[i]);
    }

    jintArray array = env->NewIntArray(count);
    if (array) {
        env->SetIntArrayRegion(array, 0, count, j_gids.data());
    }
    return array;
}

}  // anonymous namespace

void trigger_system_server_hooks() {
    LOGI("preparing to invoke modules for system_server");

    // 1. Initialize JVM Context via RAII
    JniAttachment jni;
    JNIEnv* env = jni.get_env();
    if (!env) {
        LOGE("aborting system_server specialization: failed to obtain JNIEnv");
        return;
    }

    // 2. Prepare JNI-compliant variables
    jint uid = static_cast<jint>(getuid());
    jint gid = static_cast<jint>(getgid());
    jintArray gids = fetch_gids(env);
    jint runtime_flags = 0;
    jlong permitted_capabilities = 0;
    jlong effective_capabilities = 0;

    fetch_capabilities(permitted_capabilities, effective_capabilities);

    // 3. Construct the API contract using exact references
    ServerSpecializeArgs_v1 args(uid, gid, gids, runtime_flags, permitted_capabilities,
                                 effective_capabilities);
    ZygiskContext ctx(env, &args);

    // 4. Trigger the Zygisk API lifecycle
    LOGV("triggering server_specialize_pre");
    ctx.flags |= SERVER_FORK_AND_SPECIALIZE;
    ctx.server_specialize_pre();

    LOGV("triggering server_specialize_post");
    ctx.server_specialize_post();

    // 5. Clean up the local JNI reference to prevent memory leaks in the ART
    // if (gids) {
    //     env->DeleteLocalRef(gids);
    // }
}
