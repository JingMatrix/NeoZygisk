#include "daemon.hpp"
#include "logging.hpp"
#include "zygisk.hpp"

using namespace std;

extern "C" [[gnu::visibility("default")]]
void entry(void *addr, size_t size, const char *path) {
    LOGI("Zygisk library injected, version %s", ZKSU_VERSION);

    zygiskd::Init(path);

    if (!zygiskd::PingHeartbeat()) {
        LOGE("Zygisk daemon is not running");
        return;
    }

    LOGI("Start hooking");
    hook_entry(addr, size);
    send_seccomp_event_if_needed();
}
