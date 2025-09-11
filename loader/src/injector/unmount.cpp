#include <sys/sysmacros.h>  // For makedev
#include <sys/types.h>

#include <algorithm>  // For std::sort
#include <cerrno>     // For errno
#include <cstdio>     // For sscanf
#include <cstring>    // For strerror
#include <fstream>    // For std::ifstream
#include <sstream>    // For std::stringstream
#include <string>
#include <vector>

#include "logging.hpp"
#include "module.hpp"
#include "zygisk.hpp"

std::vector<mount_info> parse_mount_info(const char* pid) {
    std::string path = "/proc/";
    path += pid;
    path += "/mountinfo";

    std::ifstream file(path);
    if (!file.is_open()) {
        PLOGE("open %s", path.c_str());
        return {};
    }

    std::vector<mount_info> result;
    std::string line;
    while (std::getline(file, line)) {
        // The " - " separator is the only guaranteed, unambiguous delimiter on a valid line.
        size_t separator_pos = line.find(" - ");
        if (separator_pos == std::string::npos) {
            LOGE("malformed line (no ' - ' separator): %s", line.c_str());
            continue;
        }

        // Split the line into the part before the separator and the part after.
        std::string part1_str = line.substr(0, separator_pos);
        std::string part2_str = line.substr(separator_pos + 3);

        std::stringstream p1_ss(part1_str);
        mount_info info = {};
        std::string device_str;

        // 1. Parse the fixed-format fields from the first part of the line.
        p1_ss >> info.id >> info.parent >> device_str >> info.root >> info.target;
        if (p1_ss.fail()) {
            LOGE("malformed line (failed parsing first section): %s", line.c_str());
            continue;
        }

        // 2. Parse the "major:minor" string.
        // sscanf is ideal for this fixed format and returns the number of items matched.
        unsigned int maj = 0, min = 0;
        if (sscanf(device_str.c_str(), "%u:%u", &maj, &min) != 2) {
            LOGE("malformed line (invalid device format): %s", line.c_str());
            continue;
        }
        info.device = makedev(maj, min);

        // 3. The remainder of the first part is the vfs_options.
        // We use getline to consume everything left in the stream.
        std::string remaining_vfs;
        std::getline(p1_ss, remaining_vfs);
        if (!remaining_vfs.empty() && remaining_vfs.front() == ' ') {
            info.vfs_options = remaining_vfs.substr(1);  // Trim leading space
        }

        // 4. Parse the second part of the line.
        std::stringstream p2_ss(part2_str);
        p2_ss >> info.type >> info.source;
        if (p2_ss.fail()) {
            LOGE("malformed line (failed parsing type/source): %s", line.c_str());
            continue;
        }

        // 5. The remainder of the second part is the fs_options.
        std::string remaining_fs;
        std::getline(p2_ss, remaining_fs);
        if (!remaining_fs.empty() && remaining_fs.front() == ' ') {
            info.fs_options = remaining_fs.substr(1);  // Trim leading space
        }

        info.raw_info = line;
        result.push_back(std::move(info));
    }
    return result;
}

std::vector<mount_info> check_zygote_traces(uint32_t info_flags) {
    std::vector<mount_info> traces;

    auto mount_infos = parse_mount_info("self");
    if (mount_infos.empty()) {
        // This is not an error if the parsing simply found no mounts.
        // It could be an error if parsing failed, which is logged in the function itself.
        LOGV("mount info is empty or could not be parsed.");
        return traces;
    }

    const char* mount_source_name = nullptr;
    bool is_kernelsu = false;

    if (info_flags & PROCESS_ROOT_IS_APATCH) {
        mount_source_name = "APatch";
    } else if (info_flags & PROCESS_ROOT_IS_KSU) {
        mount_source_name = "KSU";
        is_kernelsu = true;
    } else if (info_flags & PROCESS_ROOT_IS_MAGISK) {
        mount_source_name = "magisk";
    } else {
        LOGE("could not determine root implementation, aborting unmount.");
        return traces;
    }

    std::string kernel_su_module_source;
    if (is_kernelsu) {
        for (const auto& info : mount_infos) {
            if (info.target == "/data/adb/modules" && info.source.starts_with("/dev/block/loop")) {
                kernel_su_module_source = info.source;
                LOGV("detected KernelSU loop device module source: %s",
                     kernel_su_module_source.c_str());
                break;
            }
        }
    }

    for (const auto& info : mount_infos) {
        const bool should_unmount =
            info.root.starts_with("/adb/modules") || info.target.starts_with("/data/adb/modules") ||
            (info.source == mount_source_name) ||
            (!kernel_su_module_source.empty() && info.source == kernel_su_module_source);

        if (should_unmount) {
            traces.push_back(info);
        }
    }

    if (traces.empty()) {
        LOGV("no relevant mount points found to unmount.");
        return traces;
    }

    // Sort the collected traces by mount ID in descending order for safe unmounting
    std::sort(traces.begin(), traces.end(),
              [](const mount_info& a, const mount_info& b) { return a.id > b.id; });

    LOGV("found %zu mounting traces in zygote.", traces.size());

    return traces;
}
