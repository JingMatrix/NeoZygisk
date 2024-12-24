#include <fcntl.h>
#include <mntent.h>
#include <sys/mount.h>

#include "daemon.hpp"
#include "files.hpp"
#include "logging.hpp"
#include "misc.hpp"
#include "module.hpp"
#include "zygisk.hpp"

using namespace std::string_view_literals;

namespace {
constexpr auto MODULE_DIR = "/data/adb/modules";
constexpr auto KSU_OVERLAY_SOURCE = "KSU";
const std::vector<std::string> KSU_PARTITIONS{"/system",     "/vendor", "/product",
                                              "/system_ext", "/odm",    "/oem"};

void lazy_unmount(const char* mountpoint) {
    if (umount2(mountpoint, MNT_DETACH) != -1) {
        LOGD("Unmounted (%s)", mountpoint);
    } else {
#ifndef NDEBUG
        PLOGE("Unmount (%s)", mountpoint);
#endif
    }
}
}  // namespace

void unmount_root(uint32_t flags, bool skip_modules) {
    std::vector<std::string> targets;

    if (flags & PROCESS_ROOT_IS_KSU) {
        std::string ksu_loop;
        auto mount_info = parse_mount_info("self");

        for (auto& info : mount_info) {
            if (info.target == MODULE_DIR) {
                ksu_loop = info.source;
                continue;
            }

            // Unmount everything mounted to /data/adb
            if (info.target.starts_with(MODULE_DIR)) {
                targets.emplace_back(info.target);
                continue;
            }

            // Unmount ksu overlays
            if (info.type == "overlay" && info.source == KSU_OVERLAY_SOURCE &&
                std::find(KSU_PARTITIONS.begin(), KSU_PARTITIONS.end(), info.target) !=
                    KSU_PARTITIONS.end()) {
                targets.emplace_back(info.target);
                continue;
            }

            // Unmount temp dir
            if (info.type == "tmpfs" && info.source == KSU_OVERLAY_SOURCE) {
                targets.emplace_back(info.target);
                continue;
            }
        }

        for (auto& info : mount_info) {
            // Unmount everything from ksu loop except ksu module dir
            if (info.source == ksu_loop && info.target != MODULE_DIR) {
                targets.emplace_back(info.target);
            }
        }

    } else if (flags & PROCESS_ROOT_IS_MAGISK) {
        for (auto& info : parse_mount_info("self")) {
            if (info.root.starts_with("/adb/modules")) {
                if (!skip_modules) targets.emplace_back(info.target);
                continue;
            }

            // magisktmp tmpfs
            if (info.source == "magisk" || info.source == "worker") {
                targets.push_back(info.target);
                continue;
            }

            // Unmount everything mounted to /data/adb
            if (info.target.starts_with("/data/adb")) {
                targets.emplace_back(info.target);
            }
        }
    }

    // Do unmount
    for (auto& s : reversed(targets)) {
        lazy_unmount(s.data());
    }
}

bool clean_mnt_ns(pid_t pid) {
    if (pid < 0) {
        LOGD("clean mount namespace with an invalid pid");
        return false;
    }

    std::string ns_path = zygiskd::GetCleanMountNamespace(pid);
    if (!ns_path.starts_with("/proc/")) {
        LOGD("unable to get a clean mount namespace");
        return false;
    }

    auto clean_ns = open(ns_path.data(), O_RDONLY);
    LOGD("denylist: set to clean ns [%s] fd=[%d]\n", ns_path.data(), clean_ns);
    if (clean_ns >= 0) {
        setns(clean_ns, CLONE_NEWNS);
    }
    close(clean_ns);
    return true;
}
