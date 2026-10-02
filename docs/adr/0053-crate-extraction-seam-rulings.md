# ADR-0053: Crate-extraction seam rulings (phase: nau-chart)

## Status

Accepted. Ratified 2026-10-01 by the operator during #326 PR 1 (the
`nau-chart` extraction): the two ownership questions below re-allocate
assets that ADR-0051 named explicitly, which is above the ticket's
"budget the vendored-path reconciliation" delegation — hence this ADR
rather than a silent amendment. ADR-0052 stays reserved for the
package-freshness design (pod lane).

Amended 2026-10-01 (council, 4 seats; same day, before PR 2):

1. **Gate scope (§5 extended):** all gate axes are workspace-scoped —
   `cargo test --workspace`, `clippy --workspace --all-targets`,
   `fmt --workspace --check` in `gate.sh` AND `devbox.json`. Plain
   invocations at a non-virtual workspace root select the root package
   only, which silently amputated the moved crates' ~340 unit tests
   from every pre-amendment green run.
2. **§4 mechanism replaced, timeline accelerated:** the nau-core
   off-by-default `mlua` feature plan is STRUCK — under `resolver = "2"`
   feature unification it would link mlua + the vendored Luau into
   every crate touching the spine, defeating the spine charter and the
   gate's own dev-edge assertion. Instead: the cross-domain-needed
   constructors become free functions in `nau-chart` (e.g.
   `image_declaration_from_lua`, `snap_ref_from_pin`, mirroring the
   existing `confinement_from_lua`), so the final-PR "dissolution"
   becomes a deletion. Deadline: before `nau-image` (PR 3) extracts;
   earliest sensible slot is PR 2's first commit.
3. **Second-spine down-moves pre-ratified:** `lock` (+`pinned_member`)
   and `index` move DOWN to `nau-core` before/with PR 2 (both depend
   only on std+serde+`nau_core::snap_types` — pure moves); `manifest`
   follows before PR 4. `pkg_source`'s `GLOBAL_PATHS` process-global
   gets an explicit ruling before PR 2 (down-move or chart-as-injected-
   service) — never a silent build→chart runtime coupling.
4. **Dep-direction enforcement grows with the graph:** the gate's
   hand-enumerated crate list must gain a row in the SAME commit that
   adds a crate (missing row = FAIL), and the assertion must reach CI
   (extract `scripts/dep-direction.sh`; strict normal+build allowlist
   vs named, expiring sanctioned dev edges).
5. **§2 charter note:** `nau-infra` owns mechanism (modes, spinner,
   record emission); domain record shapes (`*Json` structs) move with
   their owning domain, not into the leaf.
6. **ENV_LOCK:** per-crate test copies are accepted (lock serializes
   within one test binary); copies verbatim, recover with
   `into_inner()`, never cross-crate dev-deps for this. The final-PR
   "dedupe" is dropped.
7. **Amended 2026-10-01 (PR 3, operator-granted #326 run):** the
   `nau-infra` charter tightens from "depends on nothing in-workspace"
   to **"depends only on `nau-core`"** — mechanism consuming vocabulary
   is the honest layering, and `store` (the snap-store client: curl
   subprocess via CommandRunner, sha3 digests, plus its ADR-0011
   assertion-verification gate slice) lands in nau-infra rather than
   the spine; ADR-0051's "store" sketch line moves to nau-infra
   accordingly, and the infra dep-direction row becomes
   `{nau-core}`. The `sign` split follows ADR-0051's own spine text:
   the generic keychain + ceremony ledger + the serde-only Provenance
   envelope/verify cluster live in `nau-core::sign`; the
   chart-coupled attest/cosign/rotate/ledger-verification half and the
   pgp sysupdate half stay root until their domains extract, except
   the release-flow-only sysupdate-pgp helpers which land in
   nau-image (pgp never enters the spine). The units payload
   vocabulary (`classify`, `spec_from_payload_app`, `PayloadSnap/App/
   Plug`, `RuntimeClass`) and `ResolvedSnap` move DOWN into
   `nau-core::{units, store}`; runtime's default-path consts
   (`DEFAULT_STATE_DIR`, `DEFAULT_EXTENSIONS_LINK_DIR`) likewise, with
   runtime re-exporting.
8. **Amended 2026-10-01 (PR 5, operator-granted #326 run):** the
   amendment-3 records pattern repeats ahead of the consuming crate:
   `InstalledPackage`, `Generation`, and `farm::ClaimLayer` move DOWN
   into `nau_core::pkg_manifest` (peer consumes them; nau-runtime
   extracts later and keeps root re-exports), together with the
   pkg_manifest mint half (`mint_manifest`, `load_signing_key`,
   `union_inbox`, `inbox_manifests`) — the root file becomes a pure
   re-export shim. The pod layout grammar (`DEFAULT_POD`, `pod_dir`,
   `validate_pod_name`, `resolve_pod_dir_under`) lands in
   `nau_core::paths`; the env-reading `pod_root` STAYS root until the
   pod PR rules it (same shape as amendment 3's GLOBAL_PATHS ruling —
   recorded here so it is not decided silently). `DEFAULT_SERVE_ADDRESS`
   moves to `nau_core::paths` with chart re-exporting (chart has no
   business owning a serve default). The runtime generation-read seam
   is completed per the design note already in `runtime.rs`:
   `nau_core::generation_view` owns `generation_dir`/`active_generation`
   verbatim, `RuntimeStore` delegates, and peer's serve/export take
   `(state_root, &BlobStore)` — the `<state-root>/store` pairing
   invariant is documented at both construction sites; promote the pair
   to a struct if more consumers appear.
9. **Amended 2026-10-01 (PR 6, operator-granted #326 run):** the
   `nau-pod` extraction's seven ruling-level deviations, verified
   forced by the reviewer: (a) `services.rs` STAYS ROOT — `&RuntimeTools`
   systemctl actuation in four production fns plus
   `resolve_service_options` (root pod-grammar validation, pinned
   STAY ROOT); the `farm::emit`→`services::emit` chain is replaced by
   the root `emit_pod_surfaces` orchestrator (composition order
   verified unobservable — services consumes only `units.json` recorded
   at install); (b) `secrets.rs` SPLITS — the resolve half (providers,
   envfile layer, `SecretSource`) moves to nau-pod, the verb layer
   (eval-coupled via `load_declaration`, RuntimeTools-coupled via
   refresh) stays root with its 61-test suite driving crate internals
   through a doc-hidden seam; (c) the loader seam:
   `PodDeclLoader<'a> = &dyn Fn(&str) -> Result<PodDeclaration>` is
   injected into the moved loads/folds so eval stays root without
   duplicating the walks — the §4-style alternative (down-move
   `PodDeclaration`/`SecretSource` to core, eval to nau-chart) remains
   a DEFERRED slot, not a rejection; (d) `list_packages`/`PodListEntry`
   stay root (eval + `load_spec_meta` coupled); (e)
   `split_version_suffix` down-moves chart::lint → `nau_core::snap_types`
   (farm's collision classifier consumes it); (f) the zero-churn rule
   is amended: no semantic test changes, but seam-forced mechanical
   call-site adaptations in tests/ are sanctioned under review (PR 6:
   4 lines, `&store` → `&store.store_view()`); (g) the root-suite
   doc-hidden `pub` surface on nau-pod is 20 items (re-privatize at the
   final reconciliation). Pre-moves recorded: `SANDBOX_RO_ROOTS` →
   `nau_core::snap_types`; `generation_view` promoted to
   `StoreView { state_root, blob_store }` (amendment 8's promotion,
   now consumer-justified) with `RuntimeStore::store_view()` as the
   adapter; ureq/dbus-secret-service follow their consumer into
   nau-pod (dbus as root dev-dep for the live-D-Bus gated test).
   Known pre-existing flake candidate (not this diff): doctor's bwrap
   probe can hit an ETXTBSY spawn race under parallel load.
10. **Amended 2026-10-01 (PRs 7-8, operator-granted #326 run):**
   (a) `RuntimeStore` moves INTO nau-runtime as the domain type — its
   impl is the mutation machinery, and the adapter's consumer set was
   empty post-PR-6; layout truth stays `nau-core` (every read path
   delegates to `StoreView`/BlobStore), root keeps the
   `pod_store`/`resolve_pod_store` glue ctors, and `RuntimeTools`
   moves with it (amendment 9a stands: services stays root and
   consumes it through the root re-export). (b) The ADR-0011
   eval-manifest gate inside `install_batch` is injected as
   `VerifySignatures<'_> = &dyn Fn(&[u8], &BTreeMap<String, Value>) ->
   Result<Option<String>>` (the 9c precedent) — the verify cluster
   stayed root through PR 7 and moved to `nau_trust::verify` in PR 8
   with the root re-export keeping every call site byte-identical.
   (c) PR 7 pre-moves: `DesktopSource`/`parse_source` +
   the launcher sibling trio → `nau_core::{pkg_manifest, snap_types}`;
   `SignatureEnvelope` → `nau_core::sign`; the device GUID trio →
   `nau_core::channels`; `SYSUPDATE_DIR` → `nau_core::paths`.
   (d) PR 8: `eval_manifest_canonical_bytes` → `nau_core::manifest_ir`
   (the ImageDeclaration twin — trust consumes only the eval OUTPUT
   schema, never eval machinery, so no injection was needed); the
   OpenPGP primitives (`import_pubring_pgp` + packet machinery) move
   to `nau_infra::pgp` — CORRECTING amendment 7's "release-flow-only"
   premise, which broke when #290 gave the rotation ceremony its
   fragment half; the policy/assembly fns stay in
   `nau-image::sysupdate` re-exporting the primitives ("pgp never
   enters the spine" unchanged — nau-infra is not the spine); `ca.rs`
   (the SSH host-CA ceremony) and the ledger-policy cluster land in
   nau-trust; the two eval-coupled fixture clusters (runtime's
   divergent-materials test, sign's build_manifest flow) stay root;
   no dev-edges in either PR.
11. **Amended 2026-10-02 (PR 9, operator-granted #326 run):** nau-pool
   takes the farm TRANSPORT+MACHINES plane: `ssh_exec` and
   `build_sched` whole, the `worker` wire half (`JobManifest`/
   `CapabilityDoc`/`JobResult`/`ClosureObject`/`SourcePin`/`Artifact`,
   `WORKER_PROTOCOL_VERSION`, `canonical_manifest_bytes`, the `jm1:`
   identity + purpose grammar), and `provision` (verb bodies with
   scalar args + `publish` + the five providers) — dep row
   `nau-pool {nau-core nau-infra}`. (a) `coordinator.rs`, the
   `worker.rs` execution half, and `farm_dispatch.rs` STAY ROOT: the
   coordinator's vocabulary is build-planning (`SnapMeta`,
   `PackageCache`, closure assembly, `deps::*`), the verbs run real
   builds (nau-build + root-only `listings_for_build`), and
   farm_dispatch wraps root `cli`/`build_orch` — the trust
   eval-coupled stay-root precedent, one door. (b) CA material
   primitives move to `nau_infra::ssh_ca` (`CaInfo`, the three path
   fns, `inspect`, `key_fingerprint`/`parse_fingerprint_line`,
   `validate_public_key_line` + `HOST_KEY_TYPES`/`is_base64_char`) —
   extending amendment 10's primitives-to-infra pattern; trust
   re-exports them (issuance policy stays `nau-trust::ca`), pool
   consumes infra. (c) `host_arch`/`triplet_arch` move to
   `nau_core::snap_types` beside `resolve_archs`; `WorkersConfig`/
   `WorkerConfig` move to `nau_core::worker_types` (chart keeps the
   `FromLua` extraction; `from_lua_value` became a chart-local free
   fn — orphan rule). (d) Provision verb dispatch follows the
   nau-chart commands precedent: the clap match stays root,
   `workers_main`'s signature is unchanged, bodies move with scalar
   args; burst sizing splits (`resolve_burst_count` stays root beside
   `farm_dispatch`; `burst_auto_count`/`refuse_burst_above_max` move
   to pool). (e) The root provision shim re-exports via an explicit
   glob (`pub use nau_pool::provision::*`) — bounded: Rust
   explicit-defeats-glob, two-glob conflicts error loudly. (f) Zero
   integration-test churn; every wire surface (protocol const, digest
   input, serde attrs, remote verbs, managed-block literals) moved
   byte-identically behind re-exports.

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
