#!/usr/bin/env python3
"""Compile the actual unshare hook body against syscall/daemon test doubles."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'loader/src/injector/hook.cpp').read_text()
start = source.index('DCL_HOOK_FUNC(static int, unshare, int flags) {')
end = source.index('\nDCL_HOOK_FUNC(', start + 1)
body = source[start:end]
prefix = r'''
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <string>
#include <vector>
#include <sched.h>
#include <sys/mount.h>
constexpr uint32_t SERVER_FORK_AND_SPECIALIZE=1, DO_REVERT_UNMOUNT=2;
constexpr uint32_t PROCESS_IS_MANAGER=1, PROCESS_GRANTED_ROOT=2;
namespace zygiskd { enum class MountNamespace { Root, Clean }; }
struct mount_info { std::string target; };
int unshares, scans, detaches, slave_calls, root_switches, clean_switches;
bool unshare_fail, slave_fail, detach_fail, cache_available;
std::vector<mount_info> traces;
std::vector<std::string> detached;
struct ZygiskContext {
    uint32_t flags=0, info_flags=0;
    static bool update_mount_namespace(zygiskd::MountNamespace ns) {
        if (ns == zygiskd::MountNamespace::Root) ++root_switches;
        else ++clean_switches;
        return cache_available;
    }
};
struct HookContext { bool zygote_unmounted=false; };
ZygiskContext ctx, *g_ctx=&ctx;
HookContext hook, *g_hook=&hook;
std::vector<mount_info> check_zygote_traces(uint32_t) { ++scans; return traces; }
int old_unshare(int) { ++unshares; return unshare_fail ? -1 : 0; }
int fake_mount(const char*,const char* path,const char*,unsigned long flags,const void*) {
    assert(std::string(path)=="/"); assert(flags==(MS_SLAVE|MS_REC));
    ++slave_calls; return slave_fail ? -1 : 0;
}
int fake_umount2(const char* target, int flags) {
    assert(flags==MNT_DETACH); ++detaches;
    detached.emplace_back(target);
    if (detach_fail) { errno=EPERM; return -1; }
    traces.clear(); return 0;
}
#define mount fake_mount
#define umount2 fake_umount2
#define PLOGE(...) ((void)0)
#define DCL_HOOK_FUNC(ret, name, ...) ret new_##name(__VA_ARGS__)
'''
suffix = r'''
void reset() {
    unshares=scans=detaches=slave_calls=root_switches=clean_switches=0;
    unshare_fail=slave_fail=detach_fail=false; cache_available=true;
    ctx={DO_REVERT_UNMOUNT,0}; hook={true}; g_ctx=&ctx; g_hook=&hook;
    detached.clear();
    traces={{"/product/app/Test/file"},{"/product/app/Test"}};
}
int main() {
    reset(); assert(new_unshare(CLONE_NEWNS)==0);
    assert(scans==2 && detaches==2 && slave_calls==1 && clean_switches==0);
    assert(detached[0]=="/product/app/Test/file" && detached[1]=="/product/app/Test");
    // A stale clean flag must not suppress live inspection (including USAP).
    reset(); hook.zygote_unmounted=false; assert(new_unshare(CLONE_NEWNS)==0);
    assert(scans==2 && detaches==2);
    reset(); traces.clear(); assert(new_unshare(CLONE_NEWNS)==0);
    assert(scans==1 && detaches==0 && slave_calls==0 && clean_switches==0);
    for (auto exempt : {PROCESS_IS_MANAGER,PROCESS_GRANTED_ROOT}) {
        reset(); ctx.info_flags=exempt; assert(new_unshare(CLONE_NEWNS)==0);
        assert(root_switches==1 && scans==0 && detaches==0);
    }
    reset(); ctx.flags=0; assert(new_unshare(CLONE_NEWNS)==0);
    assert(root_switches==1 && scans==0);
    reset(); ctx.flags=SERVER_FORK_AND_SPECIALIZE|DO_REVERT_UNMOUNT;
    assert(new_unshare(CLONE_NEWNS)==0); assert(scans==0 && root_switches==0);
    reset(); g_ctx=nullptr; assert(new_unshare(CLONE_NEWNS)==0); assert(scans==0);
    reset(); assert(new_unshare(CLONE_FILES)==0); assert(scans==0);
    reset(); unshare_fail=true; assert(new_unshare(CLONE_NEWNS)==-1);
    assert(scans==0 && detaches==0 && clean_switches==0);
    reset(); slave_fail=true; assert(new_unshare(CLONE_NEWNS)==0);
    assert(detaches==0 && clean_switches==1 && unshares==2);
    reset(); detach_fail=true; assert(new_unshare(CLONE_NEWNS)==0);
    assert(scans==2 && clean_switches==1 && unshares==2);
    reset(); detach_fail=true; cache_available=false;
    assert(new_unshare(CLONE_NEWNS)==0); assert(clean_switches==1 && unshares==1);
}
'''
with tempfile.TemporaryDirectory(prefix='neozygisk-hook-') as directory:
    test = Path(directory) / 'test.cpp'
    test.write_text(prefix + body + suffix)
    binary = Path(directory) / 'test'
    subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++20', '-Wall', '-Wextra',
                    '-fsanitize=address,undefined', str(test), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('PASS: actual unshare hook control flow (ASan/UBSan, syscall doubles)')
