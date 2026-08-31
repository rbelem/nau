# shuttle — Snap Package Builder

A Rust CLI tool that builds Snap packages from Lua declarations.
Replaces Snapcraft YAML with a programmable, composable Lua DSL.

## Quick Reference

```bash
shuttle build shuttle.lua          # build snaps from source
shuttle image shuttle.lua          # build bootable disk image
shuttle deps <pkg> --recursive  # dependency tree
shuttle build --order            # print build order
shuttle index add <name>         # register in package index
shuttle index resolve            # resolve store pins
shuttle doctor                   # system readiness check
```

## Package Index

105 packages at `pkgs/` — Ubuntu pool convention:

```
pkgs/<first-letter>/<name>.lua        # single-file package (most)
pkgs/<first-letter>/<name>/init.lua   # multi-file package (with helpers)
pkgs/s/systemd.lua          # systemd init (single file)
pkgs/g/gcc.lua              # GCC compiler (single file)
pkgs/j/jq/init.lua          # jq (multi-file, has lib.lua)
```

Every package defines `type`, `requires`, and optionally `aliases`:

```lua
snap {
    name = "mpfr", version = "4.2.1",
    type = "source",           -- source | meta | store
    requires = { "gmp" },      -- build order dependencies
    source = { url = "..." },
    build = "./configure ...",
}
```

## DSL Reference

| Function | Purpose | Fields |
|---|---|---|
| `snap{...}` | Declare a snap package | name, version, type, requires, aliases, source, build, apps |
| `app{...}` | Declare an app within a snap | command, daemon, plugs, slots |
| `image{...}` | Declare a bootable system image | base, kernel, gadget, disk, bootloader, sysctl |
| `pin(name, opts)` | Pin a store snap | revision, sha3-384 |
| `index(name)` | Look up in package index | — |
| `merge(a, b)` | Deep-merge two tables | — |

The `snap()` function validates all fields at eval time (ADR-0002).

## Toolchain Naming

GNU target triplet convention: `toolchain-<compiler>-<libc>-<arch>`

```
toolchain-gcc-gnu-x86_64        # aliases: toolchain, toolchain-x86_64
toolchain-clang-gnu-x86_64
toolchain-gcc-musl-x86_64       # future
```

Meta-packages: `build-deps` (alias `build-essential`).

## Image Assembly

The `image()` DSL composes multiple snaps into a bootable disk:

```lua
return { ["system"] = image {
    base = pin("glibc"),
    kernel = merge(pin("pc-kernel"), {
        params = { "quiet", "console=ttyS0" },
        modules = { "virtio" },
    }),
    gadget = pin("pc-gadget"),
    snaps = { pin("systemd"), pin("bash") },
    disk = { label = "gpt", partitions = {
        { name = "esp",  size = "256M", fs = "vfat", mount = "/boot" },
        { name = "root", size = "0",    fs = "ext4", mount = "/" },
    }},
    bootloader = { type = "systemd-boot", timeout = 3 },
    sysctl = { "vm.swappiness=10" },
}}
```

## Source Map

| File | Role |
|---|---|
| `src/main.rs` | CLI dispatch (build, image, index, deps, doctor) |
| `src/cli.rs` | Clap derive structs |
| `src/lua.rs` | Lua DSL eval + `index()` global |
| `src/snap.rs` | `SnapMeta` struct, YAML serialization, source build |
| `src/dsl/init.lua` | Injected globals: snap, app, image, pin, merge |
| `src/image.rs` | Image declaration, rootfs build, disk image build |
| `src/index.rs` | `PackageIndex`, entry resolution, store lookups |
| `src/store.rs` | Snap Store API v2 client |
| `src/deps.rs` | Dependency graph resolution, topological sort |
| `src/lock.rs` | Lockfile (source + snap pins) |
| `src/doctor.rs` | System readiness checks |

## Common Tasks for AI Agents

**Add a new package definition (single file):**
```bash
vim pkgs/<first-letter>/<name>.lua
```

**Add a new package definition (multi-file, with helpers):**
```bash
mkdir pkgs/<first-letter>/<name>
vim pkgs/<first-letter>/<name>/init.lua
```

**Resolve dependencies:** `shuttle deps pkgs/g/gcc --recursive --flat`

**Check build order:** `shuttle build --order --file examples/full-system/system-base/shuttle.lua`

**Register in index:** `shuttle index add <name> --alias <alias>`

**Test:** `devbox run test` (93 tests, clippy clean)

**Commit format:** conventional commits (`feat:`, `fix:`, `refactor:`, `docs:`)
