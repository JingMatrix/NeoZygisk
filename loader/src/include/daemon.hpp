#pragma once

#include <unistd.h>

#include <string>
#include <string_view>
#include <vector>

#if defined(__LP64__)
#define LP_SELECT(lp32, lp64) lp64
#else
#define LP_SELECT(lp32, lp64) lp32
#endif

constexpr auto kCPSocketName = "/" LP_SELECT("cp32", "cp64") ".sock";

// The zygote this build injects. A device gets one ABI's tracer and injector, the 64-bit
// ones wherever they run at all, so this is the only zygote it can attach.
constexpr auto kZygoteProgram = "/system/bin/app_process" LP_SELECT("32", "64");

class UniqueFd {
    using Fd = int;

public:
    UniqueFd() = default;

    UniqueFd(Fd fd) : fd_(fd) {}

    ~UniqueFd() {
        if (fd_ >= 0) close(fd_);
    }

    // Disallow copy
    UniqueFd(const UniqueFd&) = delete;

    UniqueFd& operator=(const UniqueFd&) = delete;

    // Allow move
    UniqueFd(UniqueFd&& other) { std::swap(fd_, other.fd_); }

    UniqueFd& operator=(UniqueFd&& other) {
        std::swap(fd_, other.fd_);
        return *this;
    }

    // Implict cast to Fd
    operator const Fd&() const { return fd_; }

private:
    Fd fd_ = -1;
};

namespace zygiskd {

struct Module {
    std::string name;
    UniqueFd memfd;

    inline explicit Module(std::string name, int memfd) : name(name), memfd(memfd) {}
};

enum class SocketAction {
    PingHeartbeat,
    GetProcessFlags,
    CacheMountNamespace,
    UpdateMountNamespace,
    ReadModules,
    RequestCompanionSocket,
    GetModuleDir,
    ZygoteRestart,
    SystemServerStarted,
    RefreshModules,
};

enum class MountNamespace { Clean, Root };

void Init(const char* path);

std::string GetTmpPath();

int Connect(uint8_t retry);

bool PingHeartbeat();

std::vector<Module> ReadModules();

uint32_t GetProcessFlags(uid_t uid);

void CacheMountNamespace(pid_t pid);

int UpdateMountNamespace(MountNamespace type);

int ConnectCompanion(size_t index);

int GetModuleDir(size_t index);

void ZygoteRestart();

void SystemServerStarted();

/// Asks the daemon to rebuild its module snapshot from disk, and waits for the result.
/// Synchronous on purpose: the rearm path must not inject against a stale snapshot. The
/// flag travels with the request, so it holds for this daemon's later rescans as well.
bool RefreshModules(bool ignore_disable);
}  // namespace zygiskd
