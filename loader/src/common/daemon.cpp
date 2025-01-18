#include "daemon.hpp"

#include <linux/un.h>
#include <sys/socket.h>
#include <unistd.h>

#include "logging.hpp"
#include "socket_utils.hpp"

namespace zygiskd {
static std::string TMP_PATH;
void Init(const char *path) { TMP_PATH = path; }

std::string GetTmpPath() { return TMP_PATH; }

int Connect(uint8_t retry) {
    int fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un addr{
        .sun_family = AF_UNIX,
        .sun_path = {0},
    };
    auto socket_path = TMP_PATH + kCPSocketName;
    strcpy(addr.sun_path, socket_path.c_str());
    socklen_t socklen = sizeof(addr);

    while (retry--) {
        int r = connect(fd, reinterpret_cast<struct sockaddr *>(&addr), socklen);
        if (r == 0) return fd;
        if (retry) {
            PLOGE("Retrying to connect to zygiskd, sleep 1s");
            sleep(1);
        }
    }

    close(fd);
    return -1;
}

bool PingHeartbeat() {
    UniqueFd fd = Connect(5);
    if (fd == -1) {
        PLOGE("Connect to zygiskd");
        return false;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::PingHeartbeat);
    return true;
}

uint32_t GetProcessFlags(uid_t uid) {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("GetProcessFlags");
        return 0;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::GetProcessFlags);
    socket_utils::write_u32(fd, uid);
    return socket_utils::read_u32(fd);
}

void CacheMountNamespace(pid_t pid) {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("CacheMountNamespace");
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::CacheMountNamespace);
    socket_utils::write_u32(fd, (uint32_t) pid);
}

std::string UpdateMountNamespace(MountNamespace type) {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("UpdateMountNamespace");
        return "";
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::UpdateMountNamespace);
    socket_utils::write_u8(fd, (uint8_t) type);
    uint32_t target_pid = socket_utils::read_u32(fd);
    int target_fd = (int) socket_utils::read_u32(fd);
    if (target_fd == 0) return "";
    return "/proc/" + std::to_string(target_pid) + "/fd/" + std::to_string(target_fd);
}

std::vector<Module> ReadModules() {
    std::vector<Module> modules;
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("ReadModules");
        return modules;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::ReadModules);
    size_t len = socket_utils::read_usize(fd);
    for (size_t i = 0; i < len; i++) {
        std::string name = socket_utils::read_string(fd);
        int module_fd = socket_utils::recv_fd(fd);
        modules.emplace_back(name, module_fd);
    }
    return modules;
}

int ConnectCompanion(size_t index) {
    int fd = Connect(1);
    if (fd == -1) {
        PLOGE("ConnectCompanion");
        return -1;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::RequestCompanionSocket);
    socket_utils::write_usize(fd, index);
    if (socket_utils::read_u8(fd) == 1) {
        return fd;
    } else {
        close(fd);
        return -1;
    }
}

int GetModuleDir(size_t index) {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("GetModuleDir");
        return -1;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::GetModuleDir);
    socket_utils::write_usize(fd, index);
    return socket_utils::recv_fd(fd);
}

void ZygoteRestart() {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        if (errno == ENOENT) {
            LOGD("Could not notify ZygoteRestart (maybe it hasn't been created)");
        } else {
            PLOGE("Could not notify ZygoteRestart");
        }
        return;
    }
    if (!socket_utils::write_u8(fd, (uint8_t) SocketAction::ZygoteRestart)) {
        PLOGE("Failed to request ZygoteRestart");
    }
}

void SystemServerStarted() {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("Failed to report system server started");
    } else {
        if (!socket_utils::write_u8(fd, (uint8_t) SocketAction::SystemServerStarted)) {
            PLOGE("Failed to report system server started");
        }
    }
}
}  // namespace zygiskd
