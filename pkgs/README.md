# pkgs — shuttle package index

Ubuntu-style pool layout for Snap package definitions.
Inspired by https://archive.ubuntu.com/ubuntu/ubuntu/pool/main/

## Layout

```
pkgs/
  <first-letter>/        # First letter of package name
    <package-name>.lua   # Single-file package (most common)
    <package-name>/      # Multi-file package directory
      init.lua           # Required: package definition
      lib.lua            # Optional: package-specific Lua helpers
  ...
  lib/                   # Shared Lua modules
    cli.lua              # CLI app template
    daemon.lua           # Daemon/service template
    desktop.lua          # Desktop app template
  README.md
```

Each package is either:
- **Single file**: `pkgs/<letter>/<name>.lua` containing the full definition
- **Directory**: `pkgs/<letter>/<name>/init.lua` + optional helpers (`lib.lua`, etc.)

## Finding packages

```
pkgs/j/jq/init.lua          # package: jq (multi-file, has lib.lua helper)
pkgs/h/hello.lua            # package: hello (single file)
pkgs/s/systemd.lua          # package: systemd (single file)
pkgs/o/openssl.lua          # package: openssl (single file)
```

## Usage with the index

The `shuttle index` command can scan `pkgs/` to build `package-index.json`,
which the `index()` DSL function uses at require time.

## Adding a package

For a simple package (single file):
```bash
vim pkgs/<first-letter>/<name>.lua
```

For a package with helper files:
```bash
mkdir pkgs/<first-letter>/<name>
vim pkgs/<first-letter>/<name>/init.lua
vim pkgs/<first-letter>/<name>/lib.lua
```

## Version lines

One recipe owns every version line of its name. The recipe declares a
`lines` table (line → `{version, url, sha256}`) and the pod's declared
constraint selects the line; no constraint means the current line.
`@` is the constraint sigil (`parse_pod_package`, `src/pod.rs`), so
`node@22` is the only spelling of "node 22" that exists — a name like
`node22` is a different package sharing the prefix, not a version
selection (and the lint warns on the shape; see the anti-pattern
below). Policy and rationale:
[ADR-0047](../docs/adr/0047-version-coexistence.md); vocabulary: the
*Package line* entry in [CONTEXT.md](../CONTEXT.md).

> **Status:** live. The policy is ratified (ADR-0047); the machinery
> landed via #278 — the `constraint` eval global, the `lines` table,
> refusal of a constraint naming no declared line — and #260 — the
> eval lint on suffixed sibling names and the doctor cross-pod line
> report.

### The rules

- **One version of a name per pod, permanently.** Two lines of one
  package never share a pod: the farm warns on binary collisions but
  the loader first-matches sonames silently, so same-name multiplicity
  would make incidental PATH/load order load-bearing (ADR-0047 D2).
- **Coexistence is cross-pod only.** Each pod pins its own line and
  resolves against its own farm. `pod add node@22` into a pod already
  holding node 26 is a **replace** — the pin moves, a new generation
  is emitted, nothing is silently shadowed (ADR-0047 D3).
- **Constraints are dotted prefixes, not ranges.** `node@22` and
  `node@22.2` select; `node@>=22` never will — the grammar does not
  grow without a deliberate ADR amendment.
- **Line selection is reproducible.** No `fetch()` at selection: the
  line is derived from the lockfile pin, never re-resolved against a
  live network index at eval time (ADR-0047 D4).

### Worked example — `pkgs/n/node.lua`

The reference shape, as the shipped recipe declares it:

```lua
local lines = {
    ["26"] = {
        version = "26.7.0",
        url = "https://nodejs.org/dist/v26.7.0/node-v26.7.0-linux-x64.tar.xz",
        sha256 = "982aa24dd8be4c889c6a8ab337ddff3b0896645b20f4239356e80552c16277ee",
    },
    ["22"] = {
        version = "22.21.1",
        url = "https://nodejs.org/dist/v22.21.1/node-v22.21.1-linux-x64.tar.xz",
        sha256 = "<sha256 of the 22 artifact>",
    },
}

-- `constraint` is injected at eval time (DSL global, same pattern as
-- fetch()/inputs); absent or unknown means the current line.
local line = lines[constraint] or lines["26"]

return {
    default = snap {
        name = "node",
        version = line.version,
        source = { url = line.url, sha256 = line.sha256 },
        -- build, apps, ... unchanged across lines
    },
}
```

Consumers never rename anything: a pod that needs node 22 declares
`node@22` in its own pod — same package name, same apps, and dependent
recipes that exec `node` via `interpreter = "node"` need no changes.

### Interpreter apps: the npm/npx shape

The interpreter-wrapper pass rewrites command files in place,
*following relative symlinks* — wrapping `bin/npm` (a symlink into
`lib/node_modules/npm/bin/npm-cli.js`) would clobber the real script.
Stage real copies first: `rm` the symlinks, **then** `cp -L` (rm
precedes cp because cp follows an existing destination link and would
write through it), and declare the apps with `interpreter = "node"`.
Unsuffixed apps bind to the pod's selected line (ADR-0047 D7).

### The anti-pattern: suffixed names

`node22` — a `<base><digits>` sibling renaming every app (`node22`,
`npm22`, `npx22`) to dodge its own sibling — is the documented
anti-pattern (ADR-0047 D5): every consumer of the line must rename its
world, and the rename leaks into every dependent recipe. The eval lint
(#260) warns on the shape and points at `name@constraint`. The escape
hatch is for genuinely different products only — two distributions of
one upstream are one package name with two lines, selected per pod —
and an author who takes it owns the costs knowingly.

## Held ports

(none — the last hold, `valkey-search` 1.2.1, un-held: it builds
offline through upstream's system-modules path
(`-DWITH_SUBMODULES_SYSTEM=ON`) over the pool grpc chain
(abseil-cpp, c-ares, googletest, google-benchmark, highwayhash,
protobuf, re2, grpc, libgomp — each pinned to grpc 1.70.1's own
dependency manifest, the version valkey-search pins); see
pkgs/v/valkey-search.lua and pkgs/v/valkey/init.lua for the wired
`--loadmodule`.)

