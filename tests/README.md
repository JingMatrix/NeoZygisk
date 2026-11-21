# Mount propagation regression check

On a Linux host with unprivileged user namespaces enabled:

```sh
unshare --user --map-root-user --mount python3 tests/late-mount-namespace.py
```

The check creates a temporary tmpfs and simulates both namespace paths:

1. A cached clean namespace is recursively private. A later shared directory
   bind and nested file bind in its parent must not appear in that cache.
2. An app namespace inherits those late binds. After making propagation slave
   and detaching child before parent, it must see the original backing file.
3. The parent's mounts and patched file must remain intact.

This is a Linux syscall/propagation regression check, not an execution of the
Android PLT hook. It does not test Android external storage or the daemon
fallback. Device tests must additionally cover fork-and-specialize and USAP
specialization, root-retaining apps, denylisted apps, module callbacks, and
external storage. Magisk and APatch need separate device coverage.
