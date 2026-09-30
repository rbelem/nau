# ADR 0048: Pod reuse layers — loaded-member holds, a pinned source cache, and the v5 artifact path

## Status

Proposed (2026-09-30). Drafted after the 2026-09-29 opencode-bin refresh incident.
Four-seat council review on drafting day: unanimous on E-first, on C's
restricted pinned-only form, and on all four rejections; beta's C-first
ordering is the recorded minority (3-1, rationale below). Landed with this
ADR: Phases 1 and 2 in full, plus one Phase 5 item pulled forward —
loaded members resolve their deps pin from the declaring pod's lockfile
(Decision 1's residual refusal is therefore reachable only when no
declaring pin exists). The gate rerun on the landed tree is green
(all axes). Phases 3 and 4 are specified here and scheduled, not
implemented.

## Context

An operator refreshed pod member `opencode-bin` (an always-latest recipe:
resolve the upstream channel, download a 90 MB prebuilt tarball, run one
`install`, no compilation). Three things went wrong, and code reading shows
they are one root-cause family: **the pod path has no reuse layer at any
level.**

1. **No source cache exists anywhere.** `run_build` curls every source into
   a throwaway tempdir on every build (`src/snap.rs:4881-4902`). The same
   90 MB tarball downloaded by a repo-root `nau build` hours earlier was
   downloaded again by the pod build. Verified: there is no source cache on
   any path, repo or pod.
2. **Pod member builds never consult the binary cache.** `build_pending_snap`
   (`src/pod.rs:5951`) calls `crate::snap::build_snap`
   (`src/snap.rs:4561`) directly. `PackageCache` (the v4: closure-keyed
   store at `~/.cache/nau/pkgs`) is wired only into the pool/dep path
   (`src/main.rs:987-991`, `:1041-1046`); top-level outputs never store
   (`src/main.rs:1396-1481`) and `init_pkg_cache` returns `None` unless
   `--all`/`--cache` was passed (`src/main.rs:798-806`). The repo build of
   the afternoon left nothing the pod build of the evening could reuse, and
   could not have: both halves of the handoff are missing.
3. **Loaded members rebuild unconditionally, and one failure aborts the
   verb.** `collect_loaded_packages` (`src/pod.rs:4880-4929`) has no hold
   check at all — own packages hold via `held_at_content`
   (`src/pod.rs:3635-3647`, issue #113); loaded members never did. It
   passes `deps_pin: None` (`:4925`), so `build_pending_snap` bails at the
   closure gate (`:5963-5968`) for any loaded member declaring `deps`. The
   gate is unreachable-success for the loaded layer: no pod-side lockfile
   state can satisfy it. Tonight that bail (for the loaded subpod's
   codegraph) blocked a refresh of an unrelated member that declares no
   deps.

Adjacent ratified machinery this ADR builds on, not against:

- The v4: cache key does not cover environment, apps, hooks, toolchain, or
  compression, so two byte-different builds can share a key
  (ADR-0040 Decision 6); v5 unification is that ADR's recorded revisit
  trigger. `SnapMeta::build_input_digest` (`src/snap.rs:791-823`) already
  hashes the missing recipe-side surface and deliberately excludes
  compression (`:789`).
- Own packages already hold when the installed `build_input_digest`
  matches (issue #113); `pod refresh` deliberately bypasses holds
  (issue #142) and a post-build churn guard keeps store content on
  byte-identical rebuilds. Floating sources must observe upstream drift
  (`src/snap.rs:4751-4756`, `src/pod.rs:3639-3641`).
- `pod add --snap` sideloads a payload as a blob pin; blob-pinned members
  refuse refresh by design (the payload is their content).
- The pod already carries an ad-hoc payload shortcut keyed
  `name_version_arch` (`src/pod.rs:6076-6084`), existence-only and
  closure-blind, weaker than every ratified validation precedent.
- `.planning/build-perf-plan.md` (v3, 4/4 council, 2026-09-27) already
  prescribes the v5 key, the source blob cache, and pod downloads-dir
  hardening. This ADR adopts those prescriptions into the ratified ADR
  set; it introduces no contradiction with the plan.

Constraints carried unchanged: ADR-0039 (the build sandbox is offline and
unconditional), ADR-0018 Decision 3 (the leak-scan guarantee), ADR-0024
posture (trust is never acquired silently; content claims are re-hashed
before trust, `pull_peer.rs` precedent), minimal new crates, config in Lua.

## Decision

### 1. Loaded-member content holds (Phase 1, ships first)

`collect_loaded_packages` gains the issue #113 hold before its
`build_pending_snap` call (`src/pod.rs:4924`). Hold when ALL of:

```
installed.version == contributed.version
∧ installed.meta_digest == meta.build_input_digest()
∧ member ∉ refresh_members
∧ member ∉ recipe_drift_members
∧ ¬meta.floating
```

Held members materialize claims from the installed record at
`ClaimLayer::Loaded`. `hold_style_skip_claims` (`src/pod.rs:3589-3603`)
hardcodes `ClaimLayer::Own`; it is parameterized, not duplicated.

The closure gate (`:5963-5968`) then fires only for a loaded member that
genuinely needs a rebuild without a resolvable pin. Its error is improved
to name the declaring pod and the remedy (`nau pod sync <pod>`) instead of
the generic "no closure pin exists for it here". Fail-loud stays: a
drifted, deps-declaring loaded member is never silently skipped into a new
generation (council 3-1; delta's skip-keep alternative is recorded in
Alternatives).

Two structural repairs ride in the same wave:

- **Containment**: one member's build failure no longer aborts the
  reconcile for siblings (the issue #177 hostage shape,
  `src/pod.rs:3496-3499`). Non-deps build failures are contained per
  member; the deps-gate refusal remains a named, whole-verb failure.
- **The `declared_names` trap** (implementation-mandatory): every skipped
  or held member is still inserted into `build.declared_names`, or
  `remove_undeclared` (`src/pod.rs:5135-5150`) wipes its store content.
  A dedicated test pins this.

For held members carrying deps pins, the closure blob is re-verified
where resolvable (the `verify_held_deps_blob` shape,
`src/pod.rs:3678-3703`) so corruption cannot ride a hold.

Known accepted trade-off: `build_input_digest` hashes toolchain
selectors, not tool bytes (`src/snap.rs:786-787`). A hold can skip when a
true rebuild is needed. This is issue #113's ratified trade-off extended
one layer; the exclusions above are its boundary.

### 2. A content-addressed source cache, pinned sources only (Phase 2, parallel)

Layout: `~/.cache/nau/src/<sha256[0:2]>/<sha256>`. Key = the pin's
expected content sha256, known before download for every locked source.
Write path: `.tmp` download → `verify_source_download` passes → atomic
rename (`pkg_source.rs:56-97` precedent). Read path: digest-on-read
serving; a mismatched entry is evicted, never served.

Eligibility is content identity, nothing else:

- Serve only when `expected_sha256()` is `Some`.
- **Floating sources never serve**: re-observing upstream drift is their
  semantics (issue #175).
- **Unpinned sources never serve**: `verify_source_download` performs no
  check for an `Unverified` source (`src/snap.rs:4738-4746`); a URL-keyed
  memo would silently convert an unpinned source into a pinned one. That
  is a semantics change, rejected here (see Revisit triggers).
- **Refresh targets never serve**: a `pod refresh` of a member is a
  drift-observation fetch — the ratified contract (issue #175's
  counterfactual test, `refresh_locked_source_still_refuses_moved_bytes`)
  requires the network round-trip so moved upstream bytes refuse with a
  named mismatch. A cache hit keyed by the expected hash would mask that
  detection and exit 0 on a moved source. The bypass is threaded as a
  per-fetch flag set only for `refresh_members`; plain builds and sync
  rebuilds keep the dedup. `store` stays active on the bypass path: a
  download that verifies against the pin is correct cache content.
  Discovered by the gate during this ADR's landing wave; the rule is
  structural, not incidental: skipping the network and detecting upstream
  drift are mutually exclusive, and the refresh verb's semantics choose
  detection.

Wired as one helper around the existing fetch at `src/snap.rs:4881-4912`,
shared by repo builds, pod builds, and requires-closure member builds.
Disk lifecycle folds into the existing `nau cache` verb surface
(follow-up; not in the landing wave).

Honest scope note: C does not rescue the incident recipe by itself.
`opencode-bin` is unpinned-not-floating with no pod-side pin today, so an
always-latest refresh cannot know the bytes are unchanged without
downloading. The operator action that makes it cheap is pinning the
recipe's source (or version); Phase 5's pod-side pin recording is the
structural version of the same relief.

### 3. Store wiring, hardening, and the escape hatch (Phase 3)

- The plain/repo path (`build_one_arch`, `src/main.rs:1740-1829`) performs
  `PackageCache::lookup` before build and `store` after, and
  `init_pkg_cache` stops gating on `--all`/`--cache` for it. Prerequisite,
  not optimization: until this lands, no pod-side change can reuse a repo
  build.
- Same-wave hardening: temp-then-rename writes; size + digest validation
  on read (`src/cache.rs:365-382` is existence-only, `:412` is a plain
  copy). The field-proven corruption class (truncated artifacts served
  after a partial write) is closed here, before any of it is reachable
  from pods.
- Per-verb escape hatch, never ambient: `pod refresh --rebuild` sets
  `force_build`. `pod refresh` is the operator's prove-my-recipe-builds
  verb; defaulting it to cache-consult would turn a would-fail rebuild
  into a green refresh.
- **Serve-enable precondition**: the host-toolchain-leak fix
  (build-perf-plan item 1a, the nix gcc-wrapper incident) lands
  fail-closed before any cache serving goes live. Until then Phase 3
  ships populate-only: store, don't serve. Rationale in Risk 1.

### 4. v5 keys, pod consult/populate, and the shared-flavor sidecar (Phase 4)

v5 key: sha256 over the canonical serialization of

```
{ v: 5,
  build_input_digest,
  compression, compression_level,
  source_date_epoch,
  packer_identity,
  context: "repo" | "pod" }
```

`build_input_digest` wholesale closes the ADR-0040 D6 aliasing list for
env/apps/hooks/toolchain. Compression is added because
`build_input_digest` deliberately excludes it. `source_date_epoch` is
recorded, not ambient: `set_pod_build_epoch` (`src/pod.rs:5914-5929`)
stamps only when unset, so a pod artifact and a repo artifact are not
byte-comparable unless both ran at the same epoch. `packer_identity`
captures the mksquashfs version and compression selection. The format
bump follows the move-together rule (`src/cache.rs:54-67`) and cold-misses
v4 once, by design.

Both `build_pending_snap` and `ensure_pod_dep_payload` consult and
populate, mirroring `ensure_dep_payload` (`src/main.rs:987-991`,
`:1041-1046`, `CACHE_STORE_LOCK` included). The `name_version_arch`
shortcut (`src/pod.rs:6076-6084`) is subsumed and removed: it is
closure-blind and existence-only, strictly weaker than what replaces it.

Pod-only extras are recorded at store time in a sidecar:
`{context, repairs: n, wrappers: n, sha3_384, size}`. The repair count
already exists (`repair_elf_for_portability` returns it; the call site at
`src/snap.rs:4586` discards it today). Wrapper emissions are counted
(`emit_build_wrappers` returns `()`; ~10 lines).

Serve rules:

- Exact v5 hit serves after sha3-384 + size re-validation against the
  sidecar; mismatch evicts and rebuilds (self-healing preserved).
- Cross-context serve (a repo-built entry feeding a pod build) requires
  the sidecar to record `repairs == 0 ∧ wrappers == 0` AND the static
  conjuncts (`deps.is_none()`, no non-ELF script commands, no confined
  apps, no interpreter). No-op-ness is **recorded, never predicted**: it
  is not decidable from meta alone (repair inspects actual ELF bytes,
  `src/snap.rs:4255-4261`; confined apps always get wrappers, `:3364`;
  shebang scripts without a declared interpreter get wrappers,
  `:3391-3396`).
- Promotion is one-directional: only pod-authored, extras==0 artifacts
  become shared; a shared entry never back-fills a pod key. Entries with
  any repair or wrapper, and ELF-lib-wrapped entries (absolute store
  paths baked, `src/snap.rs:3790-3821`), stay pod-locked.
- A cross-context mismatch is a miss, never an error.
- No silent substitution: the reconcile report gains a per-member
  provenance line (cached / held / installed / rebuilt, with flavor), so
  every reuse is visible.

### 5. Rejected alternatives

- **`prebuilt = true` DSL marker with sandbox/leak-scan skip** (option D).
  Rejected 4/4. The recipe's build string is arbitrary declared shell, so
  the marker is a confused-deputy flag; skipping the sandbox violates
  ADR-0039; skipping the leak scan reopens ADR-0018 Decision 3. Its
  honest core — no merged prefix when `requires`/`build_deps` are empty —
  already exists (`pod_build_prefix` early-returns `None`,
  `src/pod.rs:6021-6027`). Its artifact-ingest idea already exists as
  blob pins, with the deliberate refresh refusal. GAMMA's shell-free
  declarative form (`prebuilt = { source, binaries = {…} }`) is logged as
  a far-later option; with Phases 1-4 landed it buys little.
- **Pre-build content short-circuit** (option B). Rejected 4/4. The
  payload's sha3-384 exists only after the build; a would-be-identical
  oracle cannot exist. The space B targets is owned by the #113 holds,
  the #142 churn guard, and `--rebuild`. A third, weaker identity would
  shadow the escape hatches.
- **Pre-squashfs stage caching** (option A2). Rejected 4/4. Duplicates the
  sandbox's output contract (a second full copy per package), makes the
  `run_build → repair → wrappers → leak_scan → pack` ordering a replay
  hazard, and the leak scan re-runs on every restore anyway. Strictly
  worse than eliminating the pack entirely.
- **Static pre-build no-op prediction** (option A1 standalone). Rejected
  4/4. "Pod extras would have done nothing" is a stage-derived fact, not
  a meta-derived one. Survives only as the recorded post-build counts
  inside the Phase 4 sidecar.
- **URL-keyed memoization for unpinned sources**. Rejected. It silently
  pins semantics that the recipe explicitly left floating. Logged as a
  revisit trigger with delta's objection on record.
- **Skip-keep for drifted, deps-declaring loaded members** (delta,
  minority). Rejected 3-1 in favor of the named refusal: holds make the
  case rare, and a silent skip must never ship a stale member into a new
  generation. The guards delta attached (declared_names insertion, report
  line) are mandatory if it is ever revisited.

## Consequences

**Positive**: a version-bumped `-bin` refresh stops re-downloading pinned
sources and stops rebuilding digest-identical loaded members; a repo
build and a pod build of the same closure share work for the first time;
the closure-gate abort class (any deps-declaring loaded member) becomes
structurally unreachable on the hold path; the closure-blind
`name_version_arch` shortcut and the existence-only cache validation
holes close; every cache reuse is visible in reconcile output; no new
crates (sha2 and sha3 are already in the tree).

**Negative**: one-time cold-miss wave when v5 lands (v4 entries are never
served across the bump; alpha's timing note — land E first so the wave
cannot block a bump — is adopted); the sidecar and provenance lines add
store surface to maintain; C does nothing for unpinned always-latest
recipes until their sources are pinned or Phase 5 lands; cross-context
reuse is conservative and will refuse entries a human might call safe
(mismatch is a miss by rule); `pod refresh` gains a flag whose absence
changes what the verb does.

**Neutral**: the #113 selector-vs-bytes aliasing trade-off now spans the
loaded layer and the v5 key; the leak scan still runs on every real build
(only cache hits skip it, and only via the recorded-noop gate); phase
ordering, not code, separates the incident's two complaints.

## Revisit triggers

- Phase 5: resolve loaded deps pins from the declaring pod's lockfile via
  `materialize_deps_entry` by hash (removes the Phase 1 residual
  refusal).
- Phase 5: pod-side recording of observed source pins, so always-latest
  recipes can serve from the source cache without a manual recipe edit
  (delta's unpinned-semantics objection must be answered first).
- Phase 5: URL + revalidate memoization for unpinned sources.
- Phase 5: GAMMA's declarative `prebuilt = { source, binaries }`, if the
  `-bin` class ever needs the shell-free form.
- Measured cold-miss wave size after the v5 bump; `nau cache` verb
  integration for the source cache's disk lifecycle.
- `mksquashfs -processors` and other build-perf-plan items that the v5
  key unblocks (byte-neutrality via the rebuild-compare ritual).

## Evidence

Incident and code facts (verified by all four council seats against the
tree, 2026-09-29/30): pod build path `src/pod.rs:5951` →
`src/snap.rs:4561`, no PackageCache consultation; source fetch into
throwaway tempdir `src/snap.rs:4881-4902`; loaded rebuild unconditional
`src/pod.rs:4887-4927` with `deps_pin: None` at `:4925`; gate bail
`:5963-5968`; own holds `src/pod.rs:3635-3647` (issue #113); refresh
bypass + churn guard (issue #142, `src/pod.rs:5019-5031`); pod extras
`src/snap.rs:4585-4596`; discarded repair count `:4586`; ELF-lib wrapper
bakes absolute store paths `:3790-3821`; wrapper triggers on undeclared
interpreters `:3391-3396` and confined launchers `:3364`; `build_input_digest`
`src/snap.rs:791-823` (compression excluded `:789`, toolchain selectors
`:786-787`); `POD_BUILD_EPOCH` `src/pod.rs:5914-5929`; `name_version_arch`
shortcut `src/pod.rs:6076-6084`; `remove_undeclared` `src/pod.rs:5135-5150`;
cache validation holes `src/cache.rs:365-382`, `:412`; PackageCache pool
wiring `src/main.rs:987-991`, `:1041-1046`; top-level outputs never store
`src/main.rs:1396-1481`; `init_pkg_cache` gating `src/main.rs:798-806`;
`build_one_arch` `src/main.rs:1740-1829`; unpinned verify pass-through
`src/snap.rs:4738-4746`; floating restamp `:4751-4756`;
`verify_held_deps_blob` `src/pod.rs:3678-3703`; `hold_style_skip_claims`
`src/pod.rs:3589-3603`; containment precedent `src/pod.rs:3496-3499`
(issue #177); merged-prefix early return `src/pod.rs:6021-6027`; v4 key
and move-together rule `src/cache.rs:54-67`, `:107-134`. Ratified plan
alignment: `.planning/build-perf-plan.md` items 1a, 2 (v3, 2026-09-27).

## References

ADR-0039 (offline sandbox), ADR-0040 Decision 6 and Revisit triggers
(v4 aliasing, v5 trigger), ADR-0043 (remote build cache; names the pod
downloads dir as a cache consumer), ADR-0018 Decision 3 (leak-scan
guarantee), ADR-0024 (explicit trust), ADR-0047 (the node migration whose
subpod side triggered tonight's gate). Issues: #113 (content holds),
#142 (refresh + churn guard + recipe-closure stamps), #175 (floating
sources), #177 (refresh containment), #116 (blob pins), #309 (the
coordinator dispatch work in flight adjacent to this ADR).
`.planning/build-perf-plan.md` v3 is the planning companion; this ADR is
the ratified-record twin of its items 1a and 2.
