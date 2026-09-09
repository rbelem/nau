# Multi-source build inputs (`sources` map, named build trees)

A `snap()` may declare more than one pinned build source, each materialized into its own named tree under the build root, addressed by the build script as `$SRC/<name>/`.

## Status

Accepted (2026-09-09). Issue #41. Extends ADR-0008 (single `source.url`) and the build-tree layout from the parts work. Naming invariant per ADR-0013 applies.

## Context

Several package targets need more than one downloaded/build input per snap, which today's single `source` cannot express:

- **valkey-search**: vsearch + highwayhash + a deps `.deb` (three inputs, one CMake build).
- **beads**: a `bd` binary + a `dolt` companion (two artifacts, one PATH wrapper).
- **anydoc**: an npm tarball + a napi-rs `.node` (two fetches).

Each is currently skip-recorded. The natural alternatives were (a) a `sources` map materialized into named subdirectories of the build tree, or (b) an extension of the existing `inputs` machinery.

## Decision

Declare a **`sources` map** — `sources = { <name> = { url, sha256 }, ... }` — on the `snap()` declaration. The DSL shape was chosen over extending `inputs` because:

- `inputs` (ADR-0008) is runtime package-index resolution (where package *definitions* come from), a distinct concept from per-snap *build inputs* (what a single package's build fetches). Overloading it conflates two lifetimes and two fetch policies.
- The map shape reads as "multiple sources for this one snap," matching the single `source = { url, sha256 }` table that already exists.
- A name per source gives the build script a stable, declarative address (`$SRC/<name>`), which the multi-artifact drivers (beads, anydoc) need.

### Rules

1. **Mutually exclusive with single `source`.** Declaring both is an error. A build tree is either one tree at the build root (`source`) or named trees under the build root (`sources`) — never both.
2. **`sha256` is REQUIRED per entry** — no TOFU for multi-source. Multi-source builds are explicit by nature; every input is pinned. The single `source` path keeps its existing optional-hash TOFU behavior (a legacy convenience unchanged).
3. **Name hygiene**: each name becomes a directory name under the build tree, so it must be a plain name (no `/`, `.`, `..`), never `source` (reserved for the parts-mode shared source dir), and never a `parts` name (source trees and part work dirs share the build tree). Enforced in the Lua DSL and re-checked at the Rust parse boundary and at build dispatch.
4. **`adopt-info` is rejected with `sources`.** The adoption ladder (`extract_adopted_meta`) reads ONE pinned source tree; with named sources there is no single tree to read, so it fails closed rather than guessing.
5. **`deps` (ADR-0017) requires single `source`** unchanged — a lockfile resolves from one source tree. This rule already rejects `deps` without `source`; `sources` has no single tree for a lockfile, so it is not a substitute.

### Materialization

Each entry downloads with `curl -fsSL`, verifies its pinned SHA-256 (hard error naming the source and the mismatch), then lands the tree at `<build-root>/<name>/`. Tarballs extract with the same single-top-level-dir flattening the single-source path applies via `find_source_root`, so `foo-1.2.tar.gz` under source name `foo` puts its contents at `$SRC/foo/` — not `$SRC/foo/foo-1.2/`. Non-tarball entries (a `.deb`, a bare binary) land as the file `$SRC/<name>` addressable by its declared name.

`$SRC` points at the build root in multi-source mode, so the build script addresses each tree at `$SRC/<name>`. `cwd` is the build root for the single-`build` form, matching the single-source contract. Parts mode runs parts in their own work dirs (siblings of the source trees); every part sees the same `$SRC`.

### Store / closure addressing

Each named source's identity (name + url + pinned sha256) participates in the cache key. `source_identity_hash` folds every `name=url:sha256` into the identity string (sorted, BTreeMap order), and the canonical closure JSON carries an explicit per-source list (sorted by name) so a key diff is legible. Single-source packages keep byte-identical keys (the explicit list is omitted when empty, and the single `source` identity hash is unchanged). The content hash is pinned in `shuttle.lock` and verified at download time, so the cache key never needs the download itself.

Lockfile pinning records one `SourceInfo { url, sha256 }` per materialized source (all pinned), and multi-source builds report every source in JSON output under a `sources` array (single-source builds keep the flat `sha256` field).

## Consequences

### Positive

- The three driver packages (valkey-search, beads, anydoc) become expressible.
- Hash-pin per source is enforced structurally — no unpinned multi-source build can be declared.
- Named trees give build scripts stable, declarative addresses with no collision with parts.

### Negative

- An extra parse/validation surface in both the DSL and the Rust boundary.
- Multi-source snaps cannot use `adopt-info` or `deps` until a single-tree extension exists.
- The cache key grows with the number of sources (negligible).

### Neutral

- Single-source packages are unaffected: `source` keeps its exact shape and behavior; the closure key stays byte-identical for them.
- `inputs` remains the package-index resolution mechanism, unchanged.
