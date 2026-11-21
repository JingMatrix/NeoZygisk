#!/usr/bin/env python3
"""Linux mount-propagation regression test. Run in an unshared user/mount namespace.

    unshare --user --map-root-user --mount python3 tests/late-mount-namespace.py

Uses only a temporary tmpfs. No system mounts are detached.
"""
import ctypes
import os
import tempfile

libc = ctypes.CDLL(None, use_errno=True)
MS_BIND, MS_REC = 4096, 16384
MS_PRIVATE, MS_SLAVE, MS_SHARED = 1 << 18, 1 << 19, 1 << 20
CLONE_NEWNS, MNT_DETACH = 0x20000, 2


def call(name, *args):
    if getattr(libc, name)(*args) != 0:
        raise OSError(ctypes.get_errno(), name)


def mount(source, target, flags=0, filesystem=None):
    call("mount", source, os.fsencode(target), filesystem, flags, None)


def mounted(target):
    with open("/proc/self/mountinfo") as stream:
        return any(line.split()[4] == target for line in stream)


def child_test(parent):
    ready_read, ready_write = os.pipe()
    go_read, go_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            call("unshare", CLONE_NEWNS)
            # The daemon's clean cache must not receive subsequent shared binds.
            mount(None, "/", MS_PRIVATE | MS_REC)
            os.write(ready_write, b"1")
            os.read(go_read, 1)
            assert not mounted(parent + "/target"), "late mount entered clean cache"
            os._exit(0)
        except BaseException:
            import traceback
            traceback.print_exc()
            os._exit(1)
    os.read(ready_read, 1)
    mount(os.fsencode(parent + "/source"), parent + "/target", MS_BIND)
    mount(os.fsencode(parent + "/patched"), parent + "/target/file", MS_BIND)
    os.write(go_write, b"1")
    assert os.waitpid(pid, 0)[1] == 0

    pid = os.fork()
    if pid == 0:
        try:
            call("unshare", CLONE_NEWNS)
            assert mounted(parent + "/target"), "late mount not inherited"
            # The loader must detach in the child's namespace without affecting
            # the root-retaining parent. Include a nested file bind.
            mount(None, "/", MS_SLAVE | MS_REC)
            call("umount2", os.fsencode(parent + "/target/file"), MNT_DETACH)
            call("umount2", os.fsencode(parent + "/target"), MNT_DETACH)
            assert not mounted(parent + "/target")
            assert not mounted(parent + "/target/file")
            assert open(parent + "/target/file").read() == "factory"
            os._exit(0)
        except BaseException:
            import traceback
            traceback.print_exc()
            os._exit(1)
    assert os.waitpid(pid, 0)[1] == 0
    assert mounted(parent + "/target"), "child detached parent's directory"
    assert mounted(parent + "/target/file"), "child detached parent's file"
    assert open(parent + "/target/file").read() == "patched"


with open("/proc/self/uid_map") as stream:
    if stream.read().split() == ["0", "0", "4294967295"]:
        raise SystemExit("Use an unshared user namespace as documented")

mount(None, "/", MS_PRIVATE | MS_REC)
with tempfile.TemporaryDirectory(prefix="neozygisk-mount-test-") as root:
    mount(b"tmpfs", root, filesystem=b"tmpfs")
    try:
        for name in ("source", "target"):
            os.mkdir(root + "/" + name)
            with open(root + "/" + name + "/file", "w") as stream:
                stream.write("factory")
        with open(root + "/patched", "w") as stream:
            stream.write("patched")
        mount(None, root, MS_SHARED)
        child_test(root)
        print("PASS: clean cache isolated; child cleaned; parent mounts preserved")
    finally:
        call("umount2", os.fsencode(root), MNT_DETACH)
