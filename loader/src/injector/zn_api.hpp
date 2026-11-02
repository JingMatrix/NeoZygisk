#pragma once

#include "zygisk_next_api.h"
#include <string>

namespace zn {

struct ZnModuleHandle {
    std::string lib_path;
    bool companion = false;
    int target_api_version = 0;
};

const ZygiskNextAPI* getApiForVersion(int target_api_version);

// Initialize hook engine based on config.prop
void initHookEngine();

// HyperOS Runtime support
bool isHyosSpawner();
void initHyosRuntime();
bool isHyosRuntime();

}  // namespace zn
