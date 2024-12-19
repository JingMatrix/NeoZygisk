#pragma once

#include <jni.h>

#include "files.hpp"

extern void* start_addr;
extern size_t block_size;

void clean_trace(const char* path, size_t load = 1, size_t unload = 0, bool spoof_maps = false);

void hook_functions();

void revert_unmount_ksu(std::vector<mount_info>& mount_infos);

void revert_unmount_magisk(std::vector<mount_info>& mount_infos);
