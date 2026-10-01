# ADR-0053: Crate-extraction seam rulings (phase: nau-chart)

## Status

Accepted. Ratified 2026-10-01 by the operator during #326 PR 1 (the
`nau-chart` extraction): the two ownership questions below re-allocate
assets that ADR-0051 named explicitly, which is above the ticket's
"budget the vendored-path reconciliation" delegation — hence this ADR
rather than a silent amendment. ADR-0052 stays reserved for the
package-freshness design (pod lane).

## Context

The #326 recon (module map + dependency edges at `f4a420d`) put every
analyzer consumer in the chart domain — `commands.rs:736` (check
handler), `lua.rs:6/731/816`, `isolate.rs` (the strict-analyzer worker
stage); `snap.rs`/`build_orch` never link it — while ADR-0051 Decision 2
allocated "the vendored analyzer + `build.rs`" to `nau-build` "and ONLY
here". PR 1 moves `analysis.rs` into `nau-chart`, so `cargo test -p
nau-chart` must link the FFI symbols from the crate's own static lib.
The same recon showed all nine future domain crates need `output::*`
and `tools::ensure`, which live in the root crate and cannot be
imported across the split (a domain crate cannot depend on the root).

## Decision

1. **The vendored analyzer + `build.rs` live in `nau-chart`.** Amends
   ADR-0051 Decision 2's nau-build allocation on consumption evidence:
   the analyzer is definition-analysis machinery (chart domain), not
   build machinery. Root `build.rs` is DELETED, not copied — keeping
   both would recompile Analysis into the final link and re-trigger the
   issue-#230 duplicate-symbol deaths. `shim/` and the vendored Luau
   tarball move with it; the root `[build-dependencies]` section moves
   to `nau-chart`. `nau-build`'s defining act (PR 2) becomes extracting
   the build machinery itself.
2. **`nau-infra` — a non-domain leaf crate.** Hosts `output` (terminal
   presentation) and `tools` (external-tool provisioning), moved whole;
   the root re-exports both, so every `crate::output`/`crate::tools`
   path survives. Charter: *non-domain leaf; may be depended on by any
   crate; depends on nothing in-workspace.* Down-moving them into
   `nau-core` was rejected: it would void nau-core's explicit charter
   (`crates/nau-core/Cargo.toml` — no presentation, miette without
   "fancy") by dragging indicatif/owo-colors/ureq into the spine.
   Parameterizing was rejected: the same seam re-churns at every one of
   the nine domain boundaries. ADR-0051's "never sideways" rule forbids
   *domain-to-domain* edges; an infra leaf sits below domains, beside
   `nau-core`.
3. **Shared vocabulary moves DOWN into `nau-core`** (Decision 3 of
   ADR-0051, itemized for PR 1):
   - `nau_core::channels` — `base_track`, `channel_on_track`,
     `image_snap_channel`, `BOOTLOADER_PIBOOT` (chart checks consume
     the channel math; image staging re-exports).
   - `nau_core::units` — the pure unit planner (`spec_from_snap_app`,
     `plan_app`, `apply_plugs`, and friends); the image-side
     payload/emit halves stay root until the `nau-image` PR.
   - `nau_core::cache_key` — `RequiresMember`, `BuildClosure`,
     `SourceClosureMember`, `canonical_parts_json`, `sha256_hex` (eval
     computes the key, build consumes it — textbook R1 vocabulary).
   - `MAX_PARALLEL_BUILD_WORKERS` (single pool-budget constant).
   - `nau_core::plugins` — the plugin registry moved WHOLESALE
     (as-landed correction to the draft "names-only const" ruling):
     `PLUGINS`, `PLUGIN_NAMES`, `REGISTRY_VERSION`, `plugin_names`,
     `is_known_plugin`, `expand`, `extract_versions`.
     `SnapMeta::from_lua_table` (chart) calls `plugins::expand` at
     parse time — a compile-forced chart→build edge — and the registry
     is std+miette-only (R4 intact, no mlua), so the ADR-0051 R3 rule
     ("shared vocabulary moves DOWN") applied to the whole module.
     Root `src/plugins.rs` is a `pub use nau_core::plugins::*` shim
     plus the mandated drift-guard test (twin test inside nau-core);
     `nau-build`'s future scope narrows accordingly.
   - `nau_core::blob_store::BlobStore` — `blob_path`/`write_blob` with
     the atomic tmp+rename; `RuntimeStore::blob_path` delegates.
     `dep_fetch` takes `&BlobStore` instead of reaching into the
     runtime domain (the one wrong-way edge in the chart module set).
4. **Sanctioned temporary edge: build-side mlua constructors point at
   `nau-chart`.** The `FromLua*`/`FromPinTable` extension traits and
   their impls for core types move into `nau-chart` (orphan rule: the
   crate defining a trait implements it for core types). Root-side
   re-exports keep `crate::snap::FromLuaTable` resolving. When
   `nau-build` extracts (PR 2) it will need these traits — a latent
   build→chart edge. Ruled acceptable for PRs 1..n; the FINAL
   reconciliation PR dissolves it by moving the traits + impls into
   `nau-core` behind an off-by-default `mlua` feature, at which point
   they become plain impls and the extension traits disappear. Do not
   re-litigate this in PR 2; the commitment lives here.
5. **Dep-direction enforcement lands in PR 1**, not at gate day: a
   `scripts/gate.sh` section asserts `nau-core`/`nau-infra` depend on
   no workspace crate and `nau-chart` depends only on
   {`nau-core`, `nau-infra`}, failing with the offending edge named.
   This is the first slice of ADR-0051 Decision 5's budget.

## Security

- Deleting root `build.rs` (Decision 1) removes the duplicate-analyzer
  link hazard; exactly one cc invocation compiles the vendored C++.
- No discovery rules change: `chart eval-worker`/`check-worker` remain
  self-re-exec'd via `current_exe()` with no env override (ADR-0049's
  isolation posture); workers move source-home only.
- `nau-infra` adds no network or subprocess capability beyond what
  `tools.rs`/`output.rs` already had at root (ureq tls feature carries
  over unchanged).
- Boot units untouched: the pinned `/usr/bin/nau` ExecStart contract is
  unaffected — the root package still ships the only binary.

## Migration map

- **PR 1 (this ADR):** `nau-infra` lands; `nau-chart` lands with the
  definition/eval module set (dsl, lua, isolate, analysis, checks,
  lint, audit, lock, index, deps, dep_fetch, pkg_source, manifest,
  the chart handler block of `commands.rs`) plus the analyzer build;
  the §3 down-moves land in `nau-core`; root `build.rs` deleted;
  dep-direction gate lands.
- **As-landed notes (PR 1):** `BOOTLOADER_PIBOOT` actually lived in
  `src/image/piboot.rs`, not staging — moved to `nau_core::channels`
  as ratified (plain `&'static str`). Five thin cross-domain
  orchestrators stayed root (`cmd_deps_fetch`, `cmd_lint`,
  `cmd_eval` + manifest signing, `cmd_index` + the store-bound
  resolver): each composes a non-chart domain, and moving them would
  need root deps inside `nau-chart` or churn against the cli/main
  freeze — the domain logic itself is fully in chart. The unused
  `vendor/luau-0.663.tar.gz` stays (unratified deletion avoided);
  only the build-referenced `luau-0.736.tar.gz` moved.
- **PRs 2–9:** one domain crate per PR per #326; each consumes
  `nau-core` + `nau-infra` per §2's charter; `nau-build` (PR 2) takes
  the build machinery — the analyzer is already gone from its scope.
- **Final PR:** the §4 trait dissolution into `nau-core` (mlua
  feature), plus dedupe of the test-only `ENV_LOCK` helper copied into
  `nau-chart`; extraction declared complete, #325 closed.

## Consequences

**Positive:** PR 1 compiles green without injected entry points or
sideways edges; the seam every later PR needs (`nau-infra`) exists
before the second domain crate, so no double churn; the analyzer's
ownership finally matches its consumption; the graph assertion makes
R1 compiler- and CI-checked from day one instead of gate day.

**Negative:** PR 1 ships two crates, bending "one crate per PR" —
defended as one *domain* crate plus its seam scaffolding; the mlua
extension traits make build→chart a temporary legal edge (dissolution
committed in §4); the plugins registry now lives in `nau-core`, so the
"plugins" name in `nau-build`'s future scope is gone and the root shim
is pure re-export (the drift-guard tests are the residue);
`LOCKFILE`-adjacent vocabulary (`pinned_member`) rides in `nau-chart`
until `LockFile` itself moves DOWN (~10 domains consume it — a later
ruling).

## References

- ADR-0051 (crate modularity — the rules this ADR amends/extends)
- ADR-0049 (CLI domain namespacing — the domain seams)
- #326 (extraction tickets), #325 (workspace skeleton, `f4a420d`)
- #316/#317 (module seams — re-export preservation precedent)
- issue #230 (duplicate-symbol link deaths — why root `build.rs` is
  deleted, not copied)
