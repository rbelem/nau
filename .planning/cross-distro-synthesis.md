# Cross-Distro Synthesis — Best of Each World for shoot

> **Purpose:** Single design synthesis combining the three research streams — Ubuntu Core, Fedora
> Silverblue, NixOS — into concrete adoption verdicts for shoot as (a) a package manager and (b) an
> emerging distro/image format. Every borrowed idea cites its source brief; conflicts between the
> three philosophies are arbitrated explicitly rather than silently.
> **Companion docs:**
> - `.planning/ubuntu-core-synthesis.md` → moved to `docs/research/ubuntu-core-synthesis.md` (existing UC synthesis — built upon, not duplicated)
> - `docs/research/ubuntu-core-runtime-brief.md`, `docs/research/ubuntu-core-build-brief.md`
> - `docs/research/fedora-silverblue-runtime-brief.md`, `docs/research/fedora-silverblue-build-brief.md`
> - `docs/research/nixos-architecture-brief.md`
> - `docs/nix-language-design-lessons.md`, `docs/gap-analysis-snapcraft-nix.md`
> - `.planning/archive/ROADMAP.md` (phase numbers referenced throughout)
> **Date:** August 2026
> **Revision 2 (August 2026):** incorporates council-review verdicts — Phase 22 split (22a/22b),
> staged T6 position, reordered §5 sequence, §4 additions, and the missed-patterns items
> (validation-sets, boot health checks, bootc positioning, VM-test harness, manifest provenance/SBOM).
> **Revision 3 (2026-08-31):** §7 records the grill-session resolutions (runtime ownership, native
> target, security stack, file-level store, generations, runtime installs) and the project rename
> (shoot → shuttle; distro ShuttleOS). Normative decisions now live in `docs/adr/0010-0012`.

---

## 1. Three models at a glance

| Dimension | Ubuntu Core | Fedora Silverblue | NixOS | shoot today |
|---|---|---|---|---|
| **Runtime model** | OS = squashfs snaps assembled at boot; base snap is `/` via `snap-bootstrap`; snapd drives everything | Immutable `/usr` checked out from an ostree commit; `/etc` per-deployment merged, `/var` shared; systemd is PID 1 | System = symlink farm into one `/nix/store` closure; nothing mutates `/usr`; activation flips one symlink | Build-time CLI only; emits `.snap` squashfs + rootfs-style `.img` (squashfs root, systemd-boot/GRUB, GPT ESP+root) |
| **Storage / update model** | Per-snap squashfs revisions in `/var/lib/snapd/snaps`; essential snaps update via A/B try-boot; apps refresh live, ~2 revisions retained | Content-addressed object store; deployment = hardlink checkout; updates staged, finalized at shutdown, flipped at boot | Content-addressed `/nix/store`; GC roots = profiles; most of a rebuild is store reuse | Binary cache `~/.cache/shoot/pkgs`, SHA-256 keyed by source tarball, LRU-pruned; no update model |
| **Declaration format** | Signed **model assertion** (YAML/JSON) + `gadget.yaml` partition contract | **Treefile** YAML (era 1) → Containerfile + declarative wrappers like BlueBuild recipes (era 2) | **Nix language**; `flake.lock` pins every input | **Lua** data-description DSL (ADR-0002): `snap()`, `image()`, `merge()`, `pin()`; Nickel proposed (ADR-0009) |
| **Composability** | None at runtime — model is a flat snap list; validation-sets pin coherent sets | Treefile include-chain per desktop variant; client-side layering via rpm-ostree (slow) | **Module system**: typed options, `mkMerge`/`mkIf`/`mkOverride` — independent modules merge | `require()` + `merge()` only; no option declarations, no priorities (Phase 21 pending) |
| **Security model** | Strict confinement for all app snaps (AppArmor+seccomp+namespaces+cgroups); interfaces as the only resource path; FDE/SecureBoot/TPM on UC20+ | No per-package confinement; trust = image-level digest (composefs + fs-verity chain from kernel cmdline to every file) | Sandboxed builds (kernel namespaces, no network); no runtime per-package confinement | bubblewrap build sandbox (ADR-0004); confinement fields pass through into `snap.yaml`; images unsigned |
| **Reproducibility** | Store-resolved revisions pinned by the model; image = deterministic data assembly from assertions | Commits content-addressed; compose via Koji/Pungi (era 1) or plain podman builds (era 2) | Inputs-hash addressing; builds may still be non-reproducible; FODs are the supply-chain hole | Partial: hermetic build sandbox + `shoot.lock` (sources/snaps); **input revisions unpinned** (Phase 16 gap) |
| **Rollback** | Bootloader auto-revert if try-boot fails; `snap revert` for apps, no reboot | Previous deployment retained until cleanup; rollback = boot-entry reorder, not re-download | Boot previous generation — instant and total, because nothing was mutated | None — prior outputs persist in cache by accident of hashing, not by policy |

The pattern across all three columns: **separation of immutable system state from mutable user
state, an immutable-by-default artifact, and rollback implemented as pointer selection rather than
undo logic.** shoot has the artifact (`.snap`/`.img`) but none of the state separation or pointer
machinery yet.

---

## 2. What each system does best

### 2.1 From Ubuntu Core

1. **The signed declarative system definition (model assertion).** The image is a consequence of
   the model, not vice versa; the same document drives image creation *and* runtime identity.
   *Why it matters:* one artifact answers "what should this system contain" for builders, devices,
   and auditors. *shoot adoption:* `image()` already declares base/kernel/gadget/snaps in Lua —
   the missing piece is a serializable, signable image manifest emitted from eval (layer: snap IR →
   image assembly). Verdict: **Adopt** — unsigned manifest first, signing later.
   (ubuntu-core-runtime-brief.md §5, ubuntu-core-build-brief.md §3)

2. **`gadget.yaml` as a partition contract with roles and update semantics.** Roles
   (`system-seed/boot/save/data`), filesystem-label conventions, per-structure `update.edition`
   semantics, boot-asset `preserve` lists. *Why:* the partition layout becomes a machine-checkable
   contract shared between build time and runtime, not ad-hoc parted invocations. *shoot adoption:*
   the `disk` DSL in `image()` (examples/full-system: ESP+root) gains a role vocabulary and explicit
   update intent. Verdict: **Adapt** — roles now, `update:` semantics only when images get runtime
   refreshes. (ubuntu-core-build-brief.md §2)

3. **Seed tree + recovery systems.** An immutable golden copy of the system (snaps + assertion
   chain + model) on a dedicated partition, serving install, recover, and factory-reset modes.
   *Why:* recovery and reinstall become data operations on a read-only copy. *shoot adoption:*
   image assembly output format — only relevant if shoot targets snapd-compatible images; the UC
   synthesis already scopes a minimal shoot image target as "seed dir + labels + boot assets, not a
   rootfs build." Verdict: **Adapt** (deferred until the snapd-compatible image target is chosen —
   see open question 5). (ubuntu-core-runtime-brief.md §6, ubuntu-core-synthesis.md §3)

4. **Strict confinement with typed interfaces.** Every app snap confined; plugs/slots are the only
   path to resources; typed interface declarations with attributes and content tags.
   *shoot adoption:* Lua DSL + `SnapMeta` (Phase 15 typed plugs/slots, Phase 19 content/layout
   interfaces). shoot already has string-array plugs; typing them is the adoption. Verdict:
   **Adopt.** (ubuntu-core-runtime-brief.md §4, gap-analysis §3.3/§3.7)

5. **A/B try-boot transactional updates.** New essential-snaps set installed to a candidate slot;
   bootloader env set to `try`; automatic revert on failed boot within the boot budget.
   *Why it matters:* atomicity for the *system*, not just the package, without a running update
   daemon in the critical path. *shoot adoption:* a future deployment phase on top of `image()`
   output (see new Phase 24). Verdict: **Adapt** — mechanism worth owning only if shoot ships
   runtime updates. (ubuntu-core-runtime-brief.md §3)

6. **Retention + grade gating discipline.** Old revisions retained by policy (not GC accident);
   `grade: dangerous` as the explicit local/dev escape hatch; `snap revert` as the cheap app-level
   undo. *shoot adoption:* cache/store policy — never prune the current and previous artifact of a
   deployed image; a `--dev`/`grade` style flag marking locally-built snaps injected into images.
   Verdict: **Adopt** (policy, not code). (ubuntu-core-runtime-brief.md §3, §5)

7. **Coherent-set pinning (validation-sets).** Validation-sets pin a tested, coherent set of snap
   revisions so a device never runs an untested combination. *Why it matters:* shoot's `pkgs/`
   tree (100+ interdependent source packages + `package-index.json`) is precisely the coherence
   problem — nothing today guarantees the whole set builds together. *shoot adoption:* an index
   snapshot in the lockfile (a pinned set), not the assertion machinery. Verdict: **Adopt** (as
   lockfile + index snapshot). (ubuntu-core-runtime-brief.md §5; council review)

8. **Boot health checks.** UC's try-boot needs a definition of "good boot" (health checks,
   greenboot-style) or auto-revert either fires on slow boots or never fires. *shoot adoption:*
   systemd unit-based health checks wired into Phase 24's try-boot. Verdict: **Adopt** (with
   Phase 24). (council review)

### 2.2 From Fedora Silverblue

1. **Content-addressed object store with cheap derived views.** Four SHA-256-addressed object
   types; checkouts are hardlink farms — a second version costs disk only for changed files.
   *Why:* makes keeping N artifacts around nearly free, which is what makes atomic replace and
   rollback economically rational. *shoot adoption:* the store layer (Phase 22b content-addressed
   store; extend hashing from source-tarball-only to full build inputs). Verdict: **Adopt.**
   (fedora-silverblue-runtime-brief.md §1, §9)

2. **The state-split contract: immutable system payload, separate state, merged config.**
   Silverblue keeps `/usr` immutable, 3-way-merges `/etc` per deployment (old default, new
   default, local changes; conflicts flagged), and never touches `/var`. *Why:* the cleanest
   published contract for what an update may and may not touch. *shoot adoption (staged, per
   council review):* (1) now — stop merging user-state into the rootfs squashfs; declare system
   (packed) vs state (persistent partition/dir) paths; (2) config defaults to NixOS-style
   generated `/etc` at image-build time — free for a builder with no runtime daemon; (3) runtime
   overrides via systemd-native drop-ins/`tmpfiles.d`/`EnvironmentFile=` (no merge engine);
   (4) promote the SB 3-way merge only after runtime updates exist and hand-edited `/etc` proves
   a real workflow. Verdict: **Adopt staged** — the state split now, the merge engine only on
   demand. (fedora-silverblue-runtime-brief.md §3, §9; council review)

3. **Rollback = keep the old artifact + flip a pointer.** Previous deployments stay bootable until
   explicitly cleaned; rollback reorders boot entries, it does not re-download or undo.
   *Why:* the cheapest correct rollback design — no inverse operations ever. *shoot adoption:*
   design law for the store GC (Phase 22b reference-counted GC must treat booted/previous
   generations as roots) and for any future update path. Verdict: **Adopt.**
   (fedora-silverblue-runtime-brief.md §2, §9)

4. **BLS boot entries + atomic loader symlink flip.** One BootLoader Spec entry per deployment;
   `/boot/loader` symlink flips atomically between `loader.0`/`loader.1`; GRUB/systemd-boot list
   all entries natively. *shoot adoption:* image assembly's bootloader configuration — shoot
   already supports systemd-boot; emitting BLS entries per generation is a small delta that makes
   multi-boot free. Verdict: **Adapt** (when updates exist). (fedora-silverblue-runtime-brief.md §4)

5. **Distribution over commodity infrastructure.** Era 2 moved distribution from a bespoke ostree
   remote to plain OCI registries; build infra collapsed to "anyone with a container builder +
   CI" (Universal Blue on GitHub Actions; BlueBuild is a Rust CLI). *shoot adoption:* Phase 20 —
   `shoot upload`/release should target ordinary artifact registries, not a shoot-specific server;
   images are already pushable artifacts. Verdict: **Adopt** (positioning for Phase 20).
   (fedora-silverblue-build-brief.md §3, §4)

6. **Declarative wrapper wins over imperative engine.** The ecosystem rejected imperative-only
   Dockerfiles as UX and re-added declarative YAML on top (BlueBuild recipes ≈ treefiles ≈ shoot's
   Lua). *shoot adoption:* none needed — this is independent validation of the Lua-DSL-first
   stance; never regress to "scripts only" UX. Verdict: **Adopt** (as validation).
   (fedora-silverblue-build-brief.md §3.2, §5)

7. **composefs/fs-verity image digests.** `/usr` becomes a single verifiable digest with a
   kernel-level trust chain to every file. Verdict: **Skip** for now — revisit when images ship
   and a trust story is demanded. (fedora-silverblue-runtime-brief.md §7)

8. **bootc: the OCI image is the system.** The bootc model ships the whole bootable OS as a
   container image; "update" = pull a new image; distribution rides ordinary registries. It is
   the industry's consolidation point and the closest existing model to shoot's `.img` +
   registry distribution (Phases 20/25). *shoot adoption:* adopt explicitly as the distribution
   positioning — image = system artifact in a registry — no new machinery. Verdict: **Adopt**
   (as positioning). (fedora-silverblue-build-brief.md §5; council review)

### 2.3 From NixOS

1. **Explicit, serializable IR between language and build (the `.drv`).** The intermediate
   representation is a dumpable, diffable file; remote builds, caching, and GC all fall out of it.
   *shoot adoption:* eval layer — `shoot eval -o manifest.json` (snap-level today, image-level
   "toplevel" manifest next; see new Phase 23). The image() eval should culminate in one complete
   image description, exactly as NixOS eval culminates in `system.build.toplevel`. Verdict:
   **Adopt.** (nixos-architecture-brief.md §3, §5, §11)

2. **Content-addressed, immutable store with GC roots.** Path = hash of inputs; nothing writes
   into built paths; GC computes exact reachability from roots while the system runs.
   *shoot adoption:* Phase 22b — address outputs by (source + dep + script hashes), reference-counted
   GC rooted at lockfiles/deployed images, replacing LRU pruning. Verdict: **Adopt.**
   (nixos-architecture-brief.md §3, §7)

3. **The module system: declared options + typed merge + priorities.** Independent modules
   contribute to shared options; `mkMerge`/`mkIf`/`mkOverride` resolve composition declaratively —
   "nobody edits a central config file," which is why NixOS features compose.
   *shoot adoption:* Phase 21 (`option()`, `mkIf`, `mkMerge`, `mkForce`, recursive eval). Design
   the merge semantics at the IR level so they survive the ADR-0009 language transition. Verdict:
   **Adopt.** (nixos-architecture-brief.md §5)

4. **Purity enforced at runtime, not in the language.** Sandboxing, content hashing, and input
   locking do the work; the language merely bridges intent to the store. *shoot adoption:* none
   needed — confirms ADR-0002 (data-description DSL) and ADR-0004 (bubblewrap) and the lesson that
   the remaining gaps (lockfile, full input hashing) are runtime gaps. Verdict: **Adopt**
   (validation; directs effort to runtime, not DSL purity).
   (nixos-architecture-brief.md §2, §11; nix-language-design-lessons.md §5)

5. **Generations are cheap because nothing mutates.** Every build writes new paths; "rollback" is
   booting an old symlink target. *shoot adoption:* cache policy — keep prior `.snap`/`.img`
   outputs keyed by manifest hash (fallout of #2). Verdict: **Adopt.**
   (nixos-architecture-brief.md §7, §11)

6. **Fixed-output derivations for network steps.** The only network-permitting builds are
   addressed by *declared content hash* — the classic purity hole, but also the exact right model
   for source downloads. *shoot adoption:* Phase 16 lockfile entries are precisely FOD records
   (`url`, `rev`, `narHash`); build-script network use should be discouraged/flagged the same way.
   Verdict: **Adopt.** (nixos-architecture-brief.md §3, §9)

7. **Declarative VM tests (`nixosTests`).** NixOS tests boot a full system in QEMU from a
   declarative definition and assert on its behavior. *Why it matters:* the highest-leverage
   testing pattern for a one-dev image builder — shoot emits bootable images with no test story
   for them today. *shoot adoption:* a minimal `shoot test` harness (boot the built image in
   QEMU, assert boot + basic services) as a prerequisite for Phase 24's try-boot work.
   Verdict: **Adopt.** (council review)

---

## 3. Where the three philosophies conflict

| # | Tension | Ubuntu Core | Silverblue | NixOS | shoot position |
|---|---|---|---|---|---|
| T1 | **Unit of composition** | Package artifact (squashfs snap); system = set of snaps | System commit (ostree); packages dissolved into `/usr` | Store closure; packages are store paths, system = toplevel closure | Keep the snap as the package artifact (identity + snapd compat); keep the image as a second artifact; introduce the content-addressed store *underneath* both, not instead of them |
| T2 | **Distribution topology** | Central Store + assertion chain; brand accounts | Any OCI registry; no special server | Local-first + substituters; flake registry is a default, not a gate | Decentralized by default: package index + git inputs (already), plain registries for images (SB era-2 lesson); Store client stays read-only; never require a shoot-operated server |
| T3 | **Config merging** | Flat snap list; coherence via validation-sets | Flat list + include chain; layering is client-side | Typed option merge with priorities — the composition engine | Merge is a pure function over manifest fragments at the DSL layer (Phase 21 options/merge); the resolved IR (T1's manifest) is always a flat, fully-evaluated artifact carrying per-field provenance — mirroring how NixOS merges ~2,000 modules into one toplevel |
| T4 | **Update transport** | Per-snap refresh with deltas; channels/tracks | Static deltas pre-computed between commits | Closure substitution, no deltas — dedup does the work | Dedup first — but the benefit arrives only with full-input addressing (22a); until then `.snap`/`.img` are monolithic blobs. Pin image distribution to OCI registries (they dedup layers); escalation = casync-style chunk-level wire dedup, never static deltas; revisit trigger: measure update payload once images ship |
| T5 | **Confinement** | Universal strict confinement; interfaces are the only resource path | None per-package; image-level trust (composefs digest) | None per-package; sandbox applies to builds | Keep snapd confinement semantics via typed plugs/slots (Phase 15/19); do not invent a shoot confinement system, and do not confine the image itself |
| T6 | **State & config at update time** | Writable areas on a data partition; gadget `defaults:` one-shot; hooks | 3-way `/etc` merge; shared `/var`; `/usr` never touched | Generated `/etc` per generation; activation scripts for impure fix-ups | Staged: (1) immutable system payload + separate state partition/dir now; (2) generated `/etc` at image-build time as the config default; (3) systemd-native drop-ins/`tmpfiles.d` for runtime overrides; (4) promote SB 3-way `/etc` merge only after runtime updates ship and hand-edited `/etc` proves a real workflow |
| T7 | **Rollback mechanism** | Bootloader try-boot env + auto-revert; `snap revert` for apps | Retain deployment + reorder boot entries | Boot old generation symlink | Pointer flip (SB) for images — no undo logic, no inverse ops; try-boot auto-revert (UC) as the safety net layered on top; app-level `revert` is free once the store retains revisions |

Rationale for the contentious calls:

- **T1** — snaps are shoot's identity and its snapd compatibility story; Nix's store model is
  *internal* machinery (nixos-architecture-brief.md §3), and ostree commits would discard the
  package boundary that `requires`/`deps`/`index` are built on. Layer, don't replace.
- **T3** — NixOS's composition power comes from option merging, but its *output* is a flat
  toplevel (nixos-architecture-brief.md §5–6). shoot should copy both halves: rich merge in, flat
  manifest out. A flat-only model (UC/SB) cannot express Phase 21 modules; a merge-all-the-way-down
  model makes the IR unnavigable and un-diffable. Spec the merge as a pure function *over manifest
  fragments*, not as a property of the IR format — otherwise Phase 21 blocks on Phase 23's schema.
  Record per-field provenance (which module/option contributed each value) at eval: `mkForce`-style
  priority resolution is undebuggable without it. (council review)
- **T4** — NixOS deliberately gets update transport for free from content addressing; but dedup
  pays nothing until full-input addressing lands (22a) — until then every artifact is a monolithic
  blob and any input change re-hashes the whole thing. "shoot never needs a full-tree pull" is
  therefore only true post-22. The bite scenario is image transport to constrained devices over
  metered links; the mitigation is pinning distribution to OCI registries (T2), with casync-style
  chunk-level wire dedup as the Phase 25 escalation and a standing trigger to measure real update
  payloads once images ship. (council review)
- **T6** — Staged position (2–1 council; beta dissents in favor of keeping the SB contract
  outright). The SB 3-way merge presumes ostree's per-deployment `/etc` checkout machinery, which
  shoot lacks — `src/image.rs` bakes `/etc` into the read-only squashfs today. "The only one
  specified as a contract" is a documentation-quality argument, not an engineering-fit one.
  Decisive: pointer-flip rollback (T7) plus merged `/etc` yields "system rolls back, config
  doesn't" — the canonical Silverblue pain — while generated `/etc` rolls back *with* the image
  and is free at build time for a builder with no daemon. Beta's counter (3-way merge is simpler
  than activation scripts) does not apply at build time with no daemon; the staged path preserves
  3-way merge as the on-demand promotion.

---

## 4. What NOT to borrow

- **Owning a language that needs rewriting.** Three independent Nix evaluator rewrites
  (CppNix evolution, Lix, Tvix) wrestling the same eval/evolution problems — the canonical warning
  against custom-language ownership. Consistent with ADR-0009's choice of an upstream-maintained
  language (Nickel) over a bespoke DSL. Do not add language features (macros, laziness, type
  systems) that create a second interpreter burden.
  (nix-language-design-lessons.md §2, §3)
- **Lazy evaluation.** Nix's laziness is a documented footgun (untraceable errors, thunk leaks);
  Tvix dropped lazy trees; even Nickel's constrained laziness makes eval bounding mandatory
  (ADR-0009 negative consequences). shoot's eager evaluation stays.
  (nix-language-design-lessons.md §2.2; ADR-0009)
- **Client-side layering (rpm-ostree).** Every layered change recomposes the tree locally and must
  be re-applied on upgrade; upstream focus has moved to baked images (bootc). All shoot mutation
  happens at build time; there is no `shoot install-into-image`.
  (fedora-silverblue-runtime-brief.md §6; fedora-silverblue-build-brief.md §5)
- **Imperative-only authoring (raw Containerfile UX).** The ecosystem's own correction —
  BlueBuild rebuilding a declarative layer over podman — is evidence against shipping scripts-only
  UX. (fedora-silverblue-build-brief.md §3.2)
- **Store centralization and assertion bureaucracy.** `grade: dangerous` is mandatory for local
  snaps; "fully offline" ubuntu-image builds require hand-feeding every snap plus pre-cached
  assertions and there is no `--offline` flag. shoot remains offline-first: locked inputs + cache
  must suffice, and Phase 16's `--offline` mode is the commitment. Conditional: if Q5 resolves
  *snapd-compatible*, a minimal assertion subset becomes mandatory for image seeding — the skip
  applies to the bureaucracy, not the format.
  (ubuntu-core-build-brief.md §4.4, §8; ubuntu-core-runtime-brief.md gotcha 2; council review)
- **Partition-layout freeze as an undocumented default.** UC gadget refresh can never repartition
  (reinstall required); seed sizing must anticipate remodeling. If shoot adopts the role vocabulary
  (§2.1-2), resizing/growth policy must be an explicit, documented decision, not an inherited
  constraint. Similarly: avoid snapd-internal magic (empty `grub.conf` marker files, one-shot
  `defaults:`) leaking into the shoot DSL unless the snapd-compat target requires them.
  (ubuntu-core-runtime-brief.md gotchas 2, 9, 14; ubuntu-core-build-brief.md §8)
- **FDE/TPM/recovery-key machinery.** TPM-sealed keys are fragile (firmware update = recovery-key
  exercise), hardware-dependent, and a large surface. Out of scope until images ship.
  (ubuntu-core-runtime-brief.md §4, gotcha 7)
- **Store-path semantics inside packages.** Nix's RPATH-rewritten symlink farms buy GC precision
  at the cost of FHS incompatibility — the perennial Nix packaging tax. Snaps are FHS-clean; shoot
  content addressing lives at the cache/store layer (artifact keys), never inside the squashfs
  payload. (nixos-architecture-brief.md §3; gap-analysis §4.6)
- **"Experimental" format limbo.** Flakes carried the experimental label for years while becoming
   de-facto infrastructure. When shoot introduces its lockfile and image manifest formats, version
   and commit them from day one. (nixos-architecture-brief.md §10)
- **Privileged long-lived daemons.** snapd, rpm-ostreed, and nix-daemon are all privileged,
   always-running daemons — the hidden cost center of all three systems. shoot stays a oneshot
   CLI; if systemd units are ever needed they are emitted data, not a daemon shoot ships.
   (council review)
- **Mutable channels/tracks.** UC channels/tracks are server-side mutable pointers — the
   anti-lockfile. All shoot inputs pin by hash (Phase 16); never add a mutable indirection that
   changes what a rebuild means. (council review)
- **Option-tree sprawl.** When Phase 21 lands, cap module scope: "everything is an option" is why
   nobody can read a NixOS config. A scope limit is cheap now, expensive to retrofit.
   (council review)
- **Serial-assertion identity, static-delta precomputation, activation scripts.** Respectively:
   UC's serial/vault assertion identity machinery, ostree's server-side delta build-out, and
   NixOS's runtime activation-script plumbing. All are post-22/24 machinery — none before images
   ship and Q1 resolves. (council review)

---

## 5. Roadmap mapping

### Absorbed by existing phases

| Ideas | Phase | How it lands |
|---|---|---|
| UC typed interfaces, confinement declarations | **Phase 15** (snap.yaml coverage) | Typed plugs/slots with interface + attributes are the UC interface model |
| Nix `flake.lock`, SB registry digest pinning, UC offline lesson | **Phase 16** (inputs lockfile) | `inputs` section with `rev` + `narHash` (the FOD record); `--offline` mode is the explicit anti-UC-store commitment |
| SB "declarative wrapper over imperative engine" | **Phase 17/18** (plugins, parts) | Plugin trait = structured pull/build/stage/prime, DSL stays declarative on top |
| UC interfaces (content sharing), layouts | **Phase 19** | Typed content interfaces + `default-provider` |
| SB commodity distribution, BlueBuild CI-first model | **Phase 20** | Registry/CI targets rather than a shoot-operated server |
| NixOS module system, SB treefile include-chain | **Phase 21** | `option()`/`mkIf`/`mkMerge`/`mkForce` + recursive eval; merge specced as a pure function over manifest fragments (T3) so it survives the ADR-0009 language transition |
| Full-input cache keying (live correctness bug: `src/cache.rs` keys source snaps on name+version+URL only — editing `build` or `requires` silently serves stale snaps) | **Phase 22a** | Extend the cache key to source + build script + `requires` hashes; keep LRU pruning. Small, independent of the language question, sequence early |
| Nix store, ostree object store, SB retention, UC revision retention | **Phase 22b** (gated on Q1) | Reachability-rooted GC store + `shoot why-depends`; interim policy: never prune the current + previous deployed artifact |

### New phases proposed

- **Phase 23 — Image manifest IR (toplevel).** `shoot eval -o image.json`: the flat, serializable,
  diffable result of evaluating `image()` — Nix `.drv`/`toplevel` + UC model-assertion analog,
  unsigned at first. Carries per-field provenance (module/option path recorded at eval) and, nearly
  free, an SBOM/provenance artifact — the concrete thing §6.4's signing would protect. Small;
  prerequisite for Phase 21's eval, Phase 22b's addressing, and any signing.
  *(Source ideas: nixos-architecture-brief.md §3, §5; ubuntu-core-build-brief.md §3; council
  review.)*
- **Phase 24 — Transactional image updates + rollback (gated on Q1; speculative until then).**
  A/B artifact slots, BLS entries + atomic loader flip (systemd-boot and GRUB both read BLS),
  try-boot with auto-revert plus boot health checks defining "good boot" (systemd unit-based,
  greenboot-style), the staged T6 state layout (state partition + generated `/etc` + systemd-native
  overrides), store GC respecting generation roots. Prerequisite: the `shoot test` QEMU
  boot-and-assert harness (§2.3-7). Only if open question 1 resolves "shoot owns updates."
  *(ubuntu-core-runtime-brief.md §3; fedora-silverblue-runtime-brief.md §2–§4; council review.)*
- **Phase 25 (optional, late) — Distribution polish (bootc-style: the image is the system
  artifact).** Push/pull images and store objects to/from plain registries; dedup-based update
  transport; escalation for metered-device updates is casync-style chunk-level *wire* dedup —
  not static deltas; revisit composefs/fs-verity only if measurement demands them.
  *(fedora-silverblue-build-brief.md §4; fedora-silverblue-runtime-brief.md §1, §7; council
  review.)*

### Suggested sequence (post-council)

1. **Input lockfile + `--offline`** (Phase 16) — Nix flake.lock model; fixes the only CRITICAL
   reproducibility gap and is a prerequisite for everything content-addressed later.
   Language-independent (per ADR-0009), so it need not wait for the spike.
2. **Serializable IR / image manifest** (new Phase 23) — cheapest high-leverage move; unblocks
   module-system eval, store addressing, diffing, provenance, and future signing.
3. **Full-input cache keying** (Phase 22a) — fixes a live correctness bug in `src/cache.rs`;
   days of work; independent of the language question.
4. **ADR-0009 spike** — resolve the language question *before* building the module system:
   Nickel ships native merging with priorities/defaults, so Lua-side `option()`/`mkIf` work risks
   partial obsolescence. (Council: Phase 21 at slot 3 was the doc's riskiest call.)
5. **Builder usability** (Phases 15, 17) — typed interfaces + plugins; the gap analysis rates
   these CRITICAL and the original top-5 contained no usability work. The distro tail must not
   wag the builder dog.
6. **Module system** (Phase 21) — specced as a pure function over manifest fragments (T3),
   implemented once, in the chosen language.
7. **GC-roots store** (Phase 22b) — gated on Q1; retention-by-policy is the interim.
8. **Transactional updates + rollback** (new Phase 24) — gated on Q1, speculative until then.

Rationale: correctness (16, 22a) and cheap leverage (23) first; the foundational language
decision (ADR-0009 spike) before anything it could obsolete (21); builder usability ahead of
purity machinery; anything gated on an unresolved question stays gated and labeled.

---

## 6. Open questions

1. **Does shoot own the runtime?** Phase 24 (updates, rollback, recovery) only makes sense if
   shoot targets deployed systems; if images are handed to snapd or an admin, UC A/B and SB
   pointer-flip machinery is dead weight. Builder-only vs system-owner decides ~1/3 of this doc.
2. **Module system timing vs the language transition.** ADR-0009 (Proposed) moves definitions to
   Nickel; Phase 21's `option()`/`mkIf` semantics are language-portable but its DSL examples are
   Lua. Does Phase 21 land in Lua first, wait for Nickel, or get specced at the IR level with two
   front-ends?
3. **When to promote the 3-way `/etc` merge?** T6 is now staged: generated `/etc` + state
   partition is the default. The remaining question is the promotion trigger: once runtime
   updates exist, does hand-edited `/etc` prove a real workflow that demands SB-style 3-way
   merge with conflict reporting?
4. **Signing posture.** Unsigned manifests (dev) → what? Minimal detached signatures over the
   image manifest (self-managed keys), or a UC-style assertion chain with account/key registries?
   The UC chain is powerful but is the single largest bureaucratic surface in the briefs. Whatever
   the answer, the artifact to sign is now concrete: the Phase 23 manifest + its SBOM/provenance
   block.
5. **snapd-compatible or snapd-free?** Current `examples/full-system` images boot systemd-boot +
   squashfs root without snapd. A snapd-compatible seed-layout target (UC synthesis §3) would buy
   the snapd ecosystem at the cost of its labels, roles, and assertion expectations; a native boot
   chain stays simpler but forgoes `snap` runtime management. The T5/T6 positions above assume
   snapd-free; flip them if not.

---

## 7. Session resolutions (2026-08-31)

Answered in a grill session (decision set ratified by the owner; full rationale in
`docs/adr/0011` and `docs/adr/0012`). Supersedes the corresponding open items above.

| # | Question | Resolution |
|---|---|---|
| Q1 | Does shoot own the runtime? | **Yes — shuttle owns day-2** (updates, rollback, installs, health). Phases 22b/24 de-gated. |
| Q2 | ADR-0009 spike | **Ran; owner invoked the Luau fallback** — ADR-0010 supersedes ADR-0009 (Nickel retained as evaluation record). Phase 21 lands in Luau. |
| Q3/Q4 | State contract; snapd-compatible vs snapd-free | **Native snapd-free.** UC-compat is a gated future profile (manifest IR target-agnostic, `target = native \| uc-seed` at assembly). Hybrid rejected: two runtime owners. T6 staged position stands. |
| Q5 | Daemon law | Amended: no privileged *long-lived* daemon; emitted systemd units/timers + short-lived commands. sysupdate complies. |
| Q6 | Sequence | Confirmed, extended (below). |
| Q7 | Values call | Interpretation **(A)**: parity on boot trust / image integrity / update trust. Per-app confinement = build-time systemd directives + confinement lint; snap-strict dynamic confinement formally not delivered. |
| Q14 | Dedup depth | **File-level content-addressed store directly** (no package-level interim; "no users, build the destination"). |
| Q15 | Runtime installs | **In scope** — Phase 24b: `shuttle install/remove/upgrade/rollback`, store on state partition, generations, signed installs. |

Security stack (ordered, from council review — see ADR-0011 for the ledger and verified file:line
findings): boot-chain fix → snap-revision assertion verification (TOFU fix; the Store sha3-384 pin
comes from the same API response as the URL) → dm-verity + roothash-in-UKI → systemd-sysupdate A/B
+ signed image manifest → key ceremony (Phase-24 deliverable) → Phase 24a app execution →
confinement lint. FDE deferred, LUKS slot reserved. Deferred: SELinux, remote attestation, RAUC,
bootc, composefs-for-base, Flatpak (docs-only).

**Sequence (final):** `16 → 23 → 22a → boot-chain + TOFU fixes → 15 → 17 → 21 → 22b (file store +
GC) → 24a → 24 → 24b → 25`. (ADR-0009 spike completed 2026-08-30, ahead of its old slot.)

**Rename (2026-08-31):** shoot → **shuttle** (CLI/package manager); the distro is **ShuttleOS**.
GitHub repo renamed with redirects; historical artifacts untouched; naming invariant recorded in
ADR-0013 (paths carry the name, concepts never, digests never). Council had unanimously recommended
against "shuttle" (shuttle.dev PATH collision, crates.io awslabs holder, SEO); owner accepted the
tax knowingly in favor of the two-name split.

**Remaining open:** pc-kernel `CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG` audit; kernel sourcing
(vanilla vs Ubuntu-patched swappability); BlastOff-class namesake monitoring for ShuttleOS
(GitHub org `shuttleos` stale-claimed; shuttleos.com unrelated; `.dev/.org/.io` available);
UC-profile demand; 3-way `/etc` merge promotion trigger.

**Superseded 2026-09-04:** the pc-kernel `CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG` audit is
closed (ADR-0011 "Kernel-config audit"): nix kernel 6.18.45 has the option **not set** — no
roothash signature enforcement on this kernel; the declared UKI/PCR fallback (roothash bound
via signed UKI cmdline) is the operative path. Same boot proof supersedes the *"Phase 24 —
Transactional image updates + rollback (gated on Q1; speculative until then)"* framing
(§ "Post-Q1 ordering" above and elsewhere): Q1 was resolved by ADR-0011 (shuttle owns the
runtime, Phase 24 de-gated) and the QEMU missions (2026-09-04, `/tmp/opencode/shuttle-verity/`,
`/tmp/opencode/shuttle-userspace/`) proved a shuttle-assembled disk boots to a dm-verity
verified root with userspace running from the verified device — image bootability and
dm-verity activation are no longer speculative.
