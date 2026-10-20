# Pod rootfs: findings from the first implementation pass

The first agent in this lane reproduced the failure and settled the
mechanism experimentally, but was cut off before it wrote any code. Its
findings are recorded here so the next pass starts from them instead of
re-deriving them.

## The failure, reproduced

With the pod's `libc.so.6` on the loader path and the HOST's loader
resolving it, `cc1` dies on `__pointer_chk_guard`. The gcc driver itself
survives, because it is reached through the `cc` shim's loader search.
`cc1` is a child process, and a child cannot inherit the loader its
parent was started with. That is the whole shape of the bug.

The driver, `cc1` and `cc1plus` live in the gcc extension at:

```
extensions/gcc/usr/usr/libexec/gcc/x86_64-linux-gnu/16/cc1
extensions/gcc/usr/usr/libexec/gcc/x86_64-linux-gnu/16/cc1plus
```

The glibc extension carries the loader and the C library together:

```
extensions/glibc/usr/lib64/ld-linux-x86-64.so.2
extensions/glibc/usr/lib64/libc.so.6
```

## The pod loader's search path

The source-built glibc was configured with `slibdir=/lib64` and
`libdir=/usr/lib64`, so its default system search path is `/lib64` and
`/usr/lib64`. Read it out of the loader itself:

```
$G/extensions/glibc/usr/lib64/ld-linux-x86-64.so.2 --help
```

The loader searches `LD_LIBRARY_PATH` before its own default paths, so
the pod's `libc.so.6` is found by name from the loader path, while the
loader itself is chosen by the kernel from `PT_INTERP` inside the mount
namespace. That is the matched pair.

## The mount plan, verified

This invocation was tested and works on this host:

```
bwrap --bind / /
      --tmpfs /usr
      --ro-bind /usr/bin /usr/bin
      --ro-bind /usr/local /usr/local
      --ro-bind <gather>/usr/lib /usr/lib
      --ro-bind <gather>/usr/lib64 /usr/lib64
      --ro-bind <gather>/usr/lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu
      --tmpfs /lib64
      --ro-bind <loader> /lib64/ld-linux-x86-64.so.2
      <app> ...
```

Notes on the shape:

- bwrap resolves a bind SOURCE in the original root, so `--ro-bind
  /usr/bin /usr/bin` still finds the host's `/usr/bin` after `--tmpfs
  /usr` replaced the directory. That was measured, not assumed.
- A bind DESTINATION that does not exist is created on the host root, and
  that fails with `Permission denied` for a non-root user. Every
  destination must already exist, or be created inside a tmpfs the
  invocation owns (`/usr` and `/lib64` are both tmpfs first).
- `--bind / /` keeps the host's filesystem reachable, which is what
  decision four wants for everything outside the gathered positions.
- The host's `/usr` children other than `lib` and `lib64` are preserved
  by binding each one back. Enumerate them at emit and skip the gathered
  positions.
- `/lib64` is tmpfs first, so the host's loader cannot leak in, then the
  pod's loader is bound over the interpreter slot. If the gather carries
  a `lib64` position, stack it under the tmpfs and bind the loader over
  that.

## The gather

The gathered tree is a directory of symlinks into the extension trees,
not a copy. The extension's `usr` prefix is the payload root, so the
FHS position for a library is the extension's path with that prefix
stripped.

- `extensions/glibc/usr/lib64/libc.so.6` is the payload's `lib64` half
  and the FHS position is `lib64`.
- `extensions/gcc/usr/usr/lib/x86_64-linux-gnu/libisl.so.23` is the
  payload's `usr/lib/x86_64-linux-gnu` half and the FHS position is
  `usr/lib/x86_64-linux-gnu`.

Symlinks resolve inside the namespace because the extension trees are on
the host filesystem, which the namespace keeps. A symlink farm costs no
space and never goes stale, because it points at the generation's own
extensions.

The conflict rule is the build prefix's, already implemented and already
fail-closed: the same path from two packages with different content is a
hard error naming both. Identical content dedupes. Per-package packaging
metadata is excluded, the same way the prefix merge excludes it.

## Where the bwrap path comes from

The farm's wrapper is a `/bin/sh` script and the farm runs under the
caller's PATH, which may not have bwrap. Bake the resolved absolute path
into the wrapper at emit time. The emit runs on the host that owns the
pod's state, so the resolution is local and correct.

`nau_infra::tools::resolve(nau_infra::tools::ToolName::Bwrap)` is the
resolver the pod surface already uses. The wrapper writer should take the
resolved path as a parameter, `Option<&Path>`, so a test can pass a fake
or `None` instead of embedding a host-specific path in a fixture.

If bwrap is missing at run time, the wrapper's exec fails loudly. That
is the intended behavior: the pod's binaries cannot run correctly without
the namespace, and a silent fallback to the host loader reintroduces the
bug.

## The farm's integration point

`run_command` never sets `LD_LIBRARY_PATH` and resolves the farm entry,
so `nau run --pod X -- gcc` execs the farm symlink, which is the LD
wrapper. The namespace therefore belongs in the wrapper, and every path
that reaches a farm entry picks it up, including the arbitrary-command
form.

`ld_wrappers_dir` is private in `farm.rs` and the tests reference it. If
the wrapper writer moves to a new module, that helper moves with it and
the tests follow.
