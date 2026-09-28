# ADR-0047: Version coexistence — one name per pod, version lines by constraint

## Status

Proposed. Design-ratified 2026-09-27: the four-seat council ruling
(`.planning/research/version-conflicts-council.md`, ticket #254) as amended
the same day by the operator's single-node-package decision (#278), which
superseded the suffixed-sibling design before any of it landed. Status
follows the ADR-0043 precedent — ratified design, unbuilt machinery: no
code exists yet (`EvalRequest` carries no `constraint` field;
`pkgs/n/node.lua` declares no line table), so this ADR records rulings
about future behavior, and the compiling lanes that build it join the
queue after the current one (#278).

## Context

The same package at different versions must coexist on one machine, and
the motivating cases were live: `pkgs/n/node22.lua` (authored WIP,
stashed — coexisted with `node` by renaming the package, every app, and
every colliding internal tree), `pkgs/t/toolchain-gcc-gnu-x86_64.lua`
(dropped binutils over a prefix conflict), `pkgs/v/valkey-search.lua`
(hand-built C++ include order). The council settled the policy; the
operator then reduced the sanctioned mechanism to one sentence: **there
is exactly one `node` package — the version line is selected, not
named.** External survey: `docs/research/package-version-conflicts.md`.

Two facts constrain every answer. `@` is the constraint sigil
(`parse_pod_package`, `src/pod.rs`), so Homebrew-style `node@22` is
impossible as a package name — the superseded design was forced into
`node22` and every collision that follows. And the pod manifest is keyed
by package name (a duplicate name in `packages` is a hard error,
`src/pod.rs`), while the farm warns on binary collisions but the loader
first-matches sonames silently: any feature putting two same-soname
payloads in one pod makes incidental PATH/load order load-bearing,
against ADR-0015 D6's never-silent rule.

## Decision

1. **The build prefix stays fail-closed, zero merge semantics.**
   Byte-identical dedup; anything else is a hard error. No priority, no
   sub-prefixes. **One compiler toolchain per build prefix** (the
   ADR-0018 ownership rules, below, are its local form).

2. **One version of a name per pod, permanently — reaffirmed, now as the
   rule that makes single-package-multi-line work.** The rationale is
   unchanged: the farm warns for binary collisions, but the loader
   first-matches sonames silently, so two same-soname payloads in one pod
   make incidental ordering load-bearing (ADR-0015 D6). Rekeying the
   manifest to carry multiplicity would touch the farm classifier,
   `extensions/<pkg>` naming, loader-libs records, services and desktop
   emit, GC rooting, peer manifests, and `@constraint` semantics — the
   blast radius buys nothing once lines are selected, not named. Under
   the amended design this rule is no longer a restriction to work
   around: it is exactly why one recipe can own every version line of
   its name (`SnapMeta`, manifests, farm, and lockfile all stay
   single-version-per-name) and why coexistence needs no new machinery.

3. **Two lines coexist ACROSS pods, never within one; the coexistence
   unit is `name@constraint` in another pod.** Within a pod,
   `pod add node@22` into a pod holding node 26 is a replace: the pin
   moves, a new generation is emitted, nothing is silently shadowed.
   Across pods, each pod pins its own line and the farm of each resolves
   independently — the existing per-pod manifest and generation machinery,
   unchanged. This leaves the T2–T6 epic machinery (#255/#256/#258/#259)
   untouched: it is payload-level and name-agnostic.

4. **`@constraint` graduates from pod-package filter to recipe-selection
   input.** Today the declared constraint only filters resolution
   (`version_matches_constraint`, the dotted-prefix matcher — no range
   operators). Amended: the declared `@constraint` threads into recipe
   evaluation — `EvalRequest` (`src/isolate.rs`) gains a `constraint`
   field, exposed to the recipe as a DSL global, the same injection
   pattern as `fetch()`/`inputs`. A recipe declares its version lines
   (e.g. `pkgs/n/node.lua` gains a `lines` table mapping line →
   `{version, url, sha256}`) and selects by constraint, defaulting to the
   current line. Two hard edges: **no `fetch()` at selection** — line
   selection must be reproducible from the lockfile pin, never re-resolved
   against a live network index at eval time; and the grammar does not
   grow — `parse_pod_package`/`version_matches_constraint` stay as they
   are, so `node@22` and `node@22.2` work and `node@>=22` never will.
   The per-pod lockfile already records `{version, constraint}`
   (`src/lock.rs`): no schema change.

5. **The suffixed-name pattern is the documented anti-pattern.** A
   `<base><digits>` package (`node22`) renaming every app
   (`node22`/`npm22`/`npx22`) to dodge its own sibling is the escape
   hatch for genuinely different products only — two distributions of
   one upstream are one package name with two lines, selected per pod
   (Decisions 3–4). The lint and doctor surface inverts accordingly
   (#260): warn on the suffix shape, point at `name@constraint`. The
   suffixed WIP (suffixed apps, relocated `node_modules/npm22` tree,
   unstaged `include/`) is superseded; the one discovery that carries
   over is Decision 7's.

6. **Command/path ownership.** Each PATH-visible command name — like each
   shared subtree (ADR-0018's 2026-09-23 addendum, #174) — has exactly
   one owning payload in a merge; overlaps are fixed in the payload by
   dropping the duplicate, never by merge priority. This generalizes the
   existing negotiation in `pkgs/b/binutils.lua` (it drops the triplet
   names because the gcc deb set owns them). With Decision 2, a merged
   build prefix can never meet two lines of one name, so the
   unstaged-`include/` discipline `node22.lua` documented dies with the
   suffixed design — the shared-path conflict it guarded against is
   prevented upstream.

7. **The interpreter-wrapper invariant, and the canonical npm/npx story.**
   An interpreter app's wrapper execs the bare interpreter name (the #9
   build-time wrapper: `exec "$interpreter" "$script" "$@"`), resolved
   from the pod's farm PATH at runtime. That is correct **because of
   Decision 2**: name-uniqueness-per-pod guarantees the interpreter on
   PATH is the same line as the staged script tree — no version skew is
   expressible. Canonical npm/npx handling (landed from the stash
   verbatim): the interpreter-wrapper pass rewrites command files in
   place *following* relative symlinks, so wrapping `bin/npm` — a symlink
   into `lib/node_modules/npm/bin/npm-cli.js` — would clobber the real
   script; the recipe stages real copies first (`rm` the symlinks, then
   `cp -L` — rm precedes cp because cp follows an existing destination
   link and would write through it) and declares the apps with
   `interpreter = "node"`. Unsuffixed apps bind to the pod's selected
   line.

8. **Loader authority, recorded here for the coexistence policy.**
   Per-app closure-scoped lib lists (the T-series tickets, amending
   ADR-0028/0034) supersede the generation-wide export scope; "RUNPATH is
   advisory; the wrapper's closure list is authoritative"; the
   prepend-don't-replace behavior is kept (#89); the deferred-revisit
   trigger inverts into a review criterion — reopen only if the closure
   walk proves pathological in practice. The addenda to ADR-0028/0034
   themselves land with the implementing tickets.

9. **The reject list** — each with its reason, so none returns as a
   "feature":
   - **Nix-style priority in the merged prefix**: converts loud failure
     into silently wrong toolchains; Nix itself aborts unprioritized
     merges.
   - **Gentoo SLOTs/sub-slots**: same-name multiplicity with an
     ABI-cascade surface shuttle's name-keyed manifests cannot represent
     honestly.
   - **Manifest rekey / same-name multiplicity in one pod**: the
     loader-soname argument of Decision 2.
   - **Snapd-style instance keys in a pod**: instance names are the
     suffixed anti-pattern with runtime plumbing added.
   - **Shims, update-alternatives, env-per-selection, per-cwd
     dispatch**: rejected by name in ADR-0015 D7 (fork per call, lies to
     `which`/`/proc/self/exe`).
   - **Grafts**: post-hoc tree surgery the content-addressed store has
     no place for.
   - **Virtual-provides/versioned-provides solving beyond
     `@constraint`**: a resolver shuttle does not have and the lockfile
     does not need.
   - **Automatic payload relocation and generation-time patchelf of
     store blobs**: violates content addressing.
   - **Per-package or per-version sub-prefixes**: breaks the
     `PKG_CONFIG_SYSROOT_DIR` one-root and the toolchain `cp -a` sysroot
     contract.
   - **Soname/ABI registries or sub-slot cascades**: silent
     first-match ordering made formal.
   - **`ld.so.conf.d` host registration**: escapes the per-app closure
     boundary.
   - **Runtime farm dispatch wrappers**: the farm is direct symlinks
     (ADR-0015 D7); dispatch happens at selection, not at exec.
   - **Include-precedence machinery in the build sandbox**: the merged
     prefix stays one `/usr`-like root (ADR-0018 D2).
   The word **"priority" stays reserved** — `ClaimLayer` means
   composition precedence, nothing else. Scoped exception kept open:
   ADR-0003 multi-output snaps remain usable case-by-case (contingency
   in T4), rejected only as a general coexistence mechanism.

10. **Pre-authorized contingency.** If the toolchain pre-gate shows the
    Debian binutils 2.44-3 pairing is load-bearing, command ownership
    flips to the Debian set — documented, not mechanized (no priority
    lands) — and this flip is **pre-authorized** with a mandatory ADR
    amendment note (council open item 1, default adopted).

## Alternatives considered

- **The suffixed-sibling design** (`node22.lua` as a sibling package;
  the stashed WIP). Rejected by the operator (#278): it makes every
  consumer of a version line rename its world — package, apps, module
  trees, interpreter declarations — and the rename leaks into every
  dependent recipe. One name, selected lines, needs none of that.
- **Manifest rekey to name+version.** Rejected (Decision 2's blast
  radius; the loader's silent soname first-match makes it unsound).
- **A range grammar for constraints** (`node@>=22`). Rejected for now:
  the dotted-prefix matcher already covers pin-and-hold semantics
  (`update_pod` holds a pin whose candidate violates the constraint),
  and operators grow the grammar only when a real case needs it
  (Revisit triggers).

## Consequences

**Positive**: one recipe owns every version line of its name — no
suffixed sprawl, no per-line fork of build logic; coexistence rides
machinery that exists (per-pod manifests, generations, the lockfile's
`{version, constraint}` record); the lint surface shrinks to one warning
shape (#260); the wrapper invariant becomes a provable consequence of
the name rule instead of a discipline recipe authors must maintain.

**Negative — named, not hidden**: two lines of one package can never
share a shell's PATH; a consumer that genuinely needs both simultaneously
in one process environment has no sanctioned story (run the second in
another pod — or name a genuinely different product and own the
anti-pattern's costs knowingly). Line selection is constraint-pinned, so
a declared line that disappears upstream is a sync-time refusal, never a
silent re-pin (the implementing lanes must confirm the refuse path).

## Revisit triggers

- A proven case needing two lines of one name in one process environment
  — reopen the reject list from Decision 9, not the manifest.
- Range operators demanded by real pin workloads — grow the constraint
  grammar deliberately, keeping `fetch()` out of selection.
- The binutils pairing flip (Decision 10) firing — file the ADR
  amendment note it is pre-authorized with.

## References

- ADR-0012 (store/generations), ADR-0015 D6/D7/D8 (conflict policy, no
  shims, the #9 wrapper), ADR-0017 (the lockfile is the pin record),
  ADR-0018 (merged prefix, leak scan, 2026-09-23 ownership addendum),
  ADR-0028/0034 (pod loader path — addenda land with the T-series),
  ADR-0003 (multi-output exception).
- `.planning/research/version-conflicts-council.md` (the four-seat
  ruling), `docs/research/package-version-conflicts.md` (the external
  survey).
- Issues: #254 (this ADR, T1), #278 (the amending design decision),
  #260 (T7 — lint/doctor/doc rescopes onto this ADR), #9 (interpreter
  wrappers), #89 (prepend-don't-replace), #174 (subtree ownership).
