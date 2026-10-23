#include "zygote_abi.hpp"

#include <sys/wait.h>
#include <unistd.h>

#include <climits>
#include <csignal>

#include "daemon.hpp"
#include "logging.hpp"
#include "monitor.hpp"
#include "utils.hpp"

// Directory holding our own executable, e.g. /data/adb/modules/zygisksu/bin.
static std::string resolve_bin_dir() {
    char buf[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len <= 0) {
        PLOGE("readlink /proc/self/exe");
        return "./bin";
    }
    std::string path(buf, len);
    auto slash = path.rfind('/');
    return slash == std::string::npos ? "./bin" : path.substr(0, slash);
}

ZygoteAbiManager::ZygoteAbiManager(AppMonitor& monitor, bool is_64bit)
    : abi_name_(is_64bit ? "64" : "32"),
      program_path_(is_64bit ? "/system/bin/app_process64" : "/system/bin/app_process32"),
      bin_dir_(resolve_bin_dir()),
      tracer_path_(bin_dir_ + (is_64bit ? "/zygisk-ptrace64" : "/zygisk-ptrace32")),
      monitor_(monitor) {}

const Status& ZygoteAbiManager::get_status() const { return status_; }

void ZygoteAbiManager::notify_injected() { status_.zygote_injected = true; }

void ZygoteAbiManager::set_daemon_info(std::string_view info) { status_.daemon_info = info; }

void ZygoteAbiManager::set_daemon_crashed(std::string_view error) {
    status_.daemon_running = false;
    status_.daemon_error_info = error;
}

bool ZygoteAbiManager::is_in_crash_loop() {
    struct timespec now{};
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec - counter.last_start_time.tv_sec < ZygoteAbiManager::CRASH_LOOP_WINDOW_SECONDS) {
        counter.count++;
    } else {
        counter.count = 1;
    }
    counter.last_start_time = now;
    return counter.count >= ZygoteAbiManager::CRASH_LOOP_RETRY_COUNT;
}

bool ZygoteAbiManager::ensure_daemon_created() {
    status_.zygote_injected = false;
    if (status_.daemon_pid == -1) {
        auto pid = fork();
        if (pid < 0) {
            PLOGE("create daemon (abi=%s)", abi_name_);
            return false;
        }
        if (pid == 0) {
            std::string daemon_name = bin_dir_ + "/zygiskd";
            daemon_name += abi_name_;
            execl(
                daemon_name.c_str(),
                daemon_name.c_str(),
                "--workdir",
                zygiskd::GetTmpPath().c_str(),
                nullptr
            );
            PLOGE("exec daemon %s", daemon_name.c_str());
            exit(1);
        }
        status_.supported = true;
        status_.daemon_pid = pid;
        status_.daemon_running = true;
    }
    return status_.daemon_running;
}

const char* ZygoteAbiManager::check_and_prepare_injection() {
    if (is_in_crash_loop()) {
        monitor_.request_stop("zygote crashed");
        return nullptr;
    }
    if (!ensure_daemon_created()) {
        monitor_.request_stop("daemon not running");
        return nullptr;
    }
    return tracer_path_.c_str();
}

bool ZygoteAbiManager::handle_daemon_exit_if_match(int pid, int process_status) {
    if (status_.supported && pid == status_.daemon_pid) {
        auto status_str = parse_status(process_status);
        LOGW("ZygoteAbiManager: daemon%s (pid %d) exited: %s", abi_name_, pid, status_str.c_str());
        status_.daemon_running = false;
        if (status_.daemon_error_info.empty()) {
            status_.daemon_error_info = status_str;
        }
        monitor_.update_status();
        return true;
    }
    return false;
}
