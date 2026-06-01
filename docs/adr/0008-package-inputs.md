# Runtime package inputs (inspired by Nix flake inputs)

Packages are fetched at runtime from declared input sources, not compiled into the binary.

## Status

Accepted

## Context

The original design compiled the entire `pkgs/` directory into the binary via `rust-embed` at compile time. This made the binary self-contained but coupled package updates to binary releases — adding or fixing a package required recompiling and redistributing the binary.

A parallel experiment added Nix flake files (`flake.nix`, `nix/package.nix`, `nix/shell.nix`) to build shoot itself with Nix. This never worked: `rust-embed`'s `#[folder = "pkgs/"]` failed during Nix builds because `sourceByRegex` filtered out the `pkgs/` directory.

## Decision

Replace both `rust-embed` and the Nix build system with a runtime input system inspired by Nix flake inputs:

1. **Remove `rust-embed`** from Cargo.toml and delete `src/embedded.rs`.
2. **Remove all Nix files** (`flake.nix`, `nix/package.nix`, `nix/shell.nix`).
3. **Create `src/pkg_source.rs`** — a new module for runtime package resolution.

### URL schemes

- `github:user/repo[/branch]` — shallow-clone from GitHub into `~/.cache/shoot/inputs/<hash>/`
- `path:/local/dir` — use a local filesystem path directly

### Resolution order

1. If the name is a direct filesystem path, use it.
2. Check local `pkgs/<letter>/<name>.lua` (working directory override).
3. Check each initialized input source's `pkgs/` directory.
4. Return NotFound.

### Input declaration

Global inputs are declared as a Lua global before the `return` statement in `shoot.lua`:

```lua
inputs = {
    packages = { url = "github:rbelem/shoot/main" },
}
```

Per-snap inputs are declared on individual `snap()` tables. Both global and per-snap inputs use the same `PackageInput { url: String }` struct.

### Default input

If no inputs are declared and no `shoot.lua` exists, the default `github:rbelem/shoot/main` is auto-fetched on first build. This preserves the out-of-the-box experience that `rust-embed` provided while keeping the resolution dynamic.

### Cache management

- `~/.cache/shoot/inputs/<sha256-prefix>/` — shallow clones, refreshed via `shoot index update`
- `shoot index update` re-clones cached GitHub inputs; local paths are read-only and skip caching

### NixInput → PackageInput

The existing `NixInput` struct (added as working-tree-only, never committed) was renamed to `PackageInput` and the Nix-specific `flake` field was removed.

## Consequences

### Positive

- Package updates no longer require a binary release — `shoot index update` pulls the latest definitions from the configured input.
- The binary is smaller without `rust-embed` compile-time bundling.
- No more Nix build conflict with `rust-embed`.
- Users can point to custom repos or local directories for their own package index.
- Auto-fetch provides the same zero-config experience as before.

### Negative

- First build requires network access (unless a local `pkgs/` is present or caching from a previous run).
- `git` must be installed for GitHub URL resolution.
- Shallow clone cache adds ~200KB per input on disk (vs. zero with compile-time embedding).

### Neutral

- The `pkgs/` directory is still present in the repo (as the canonical package index). It's used as a working-directory fallback during development.
