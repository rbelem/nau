# Privileged install path for Phase 24b: a setuid activate helper, never a daemon

## Status

Proposed. Gates Phase 24b (ADR-0012 Decision 5: `shuttle install/remove/
upgrade/rollback`). Grounded in issue #49 (council review of the gap
analysis, 2026-09-09, ranked #3 — gates Phase 24b, immediately after boot)
and a full read of the runtime it must serve. Extends ADR-0011 (Decision 5,
the daemon law), ADR-0012 (generations, the runtime verbs), ADR-0023 (state
partition — `/var/lib` is the state mount), ADR-0024 (key ceremony, the
trusted-key set), and ADR-0032 (Decision 5's user-level scope precedent).
Supersedes nothing; the current code's zero-privilege-check posture is a
documented absence, not a decision.

## Context

ADR-0012 Decision 5 named the Phase 24b runtime verbs; the code landed
without landing the privilege model. `shuttle install` run as an
unprivileged user journals `started` and then dies partway with an opaque
`fs::write` EACCES, because the defaults are root-owned system paths —
`DEFAULT_STATE_DIR = "/var/lib/shuttle"` (`src/runtime.rs:106`) and
`DEFAULT_EXTENSIONS_LINK_DIR = "/var/lib/extensions"` (`src/runtime.rs:109`)
— and there is no privilege check anywhere on the path (issue #49). The
failure mode is worst-shaped: late, partial, and unexplained.

The hard constraint is ADR-0011 Decision 5: **no privileged long-lived
daemon ships.** Runtime features are emitted systemd units/timers plus
short-lived shuttle commands. Any privilege mechanism must therefore be
per-invocation, and it must survive on hosts with no systemd at all —
ADR-0032's context lists WSL2 (systemd off by default), Devuan, antiX, and
Slackware as hosts pods serve today.

What the runtime already gives us, verified in source:

- The staging discipline is already atomic-rename-based: stage at
  `generations/.staging-<N>`, commit with rename(2), flip `active` by temp
  symlink + rename (`src/runtime.rs:7-16`, `:49-60`,
  `flip_active` at `:1626-1641`). The privileged surface is therefore
  narrow by construction: **rename into the root-owned state root, write
  the crash-recovery journal, relink `/var/lib/extensions/<pkg>`, run
  `systemd-sysext refresh`, run `systemctl daemon-reload`** (`activate` at
  `:1643-1687`). Everything upstream of the rename — fetch, snap-revision
  assertion verification, manifest signature verification, staging, hashing
  — is pure user work on user-writable paths.
- The crash-recovery journal is a three-state machine (`started` /
  `staging` / `committed`, `:55-60`, `:624-683`) where `committed` means
  "finish the idempotent flip and drop the journal" — i.e. the design
  already tolerates a crash after commit and before activation completes,
  and every runtime command re-converges from disk truth. A privilege
  boundary inserted between staging and rename inherits this machinery; it
  does not need a new one.
- Trust verification already fails closed where it matters: signed
  manifests verify against `/etc/shuttle/trusted-keys/` (device anchor
  `/etc/shuttle/update-key.pub` as single-anchor fallback,
  `src/runtime.rs:112`) or the operator keychain
  `~/.config/shuttle/keys/`, revoked-first per ADR-0024 §4
  (`src/runtime.rs:73-88`). This machinery runs unprivileged — reading the
  trust set needs no root — and the privileged side can re-run it.
- A privileged boot-time activation path **already ships**: the #60 emitted
  oneshot converges a half-written journal and calls the same `activate`
  seam as the CLI (`src/runtime.rs:1689-1730`, `src/main.rs:4040`,
  `src/image/state.rs:237`, `src/image/boot.rs:287`). Root-mediated
  activation is not new behavior; only the *interactive* post-boot path is
  undefined.
- polkit is pre-positioned as a pool package (`pkgs/p/polkit.lua`,
  "framework for centralizing the decision making process for user
  privilege escalation", `:11-15`). It is available as a *dependency*; it
  is not owed a *daemon*.

Owner requirements from issue #49: unprivileged fetch/verify/stage into a
user-writable spool + **one privileged `shuttle activate` step — never a
daemon**; the mechanism is a grill-session ADR, implementation follows in
Phase 24b.

## Decision

1. **The privilege boundary sits at the rename, and only at the rename.**
   Everything through staging runs as the invoking user; the root-owned
   operations are exactly: (a) write `journal.json` transitions in the
   state root, (b) rename the caller's staged tree into
   `generations/.staging-<N>` and thence `generations/<N>`, (c) create and
   replace the symlinks under `/var/lib/extensions/`, (d) run
   `systemd-sysext refresh` and `systemctl daemon-reload`, (e) flip the
   `active` symlink. Fetch, Snap Store resolve with snap-revision
   assertion verification (`src/store.rs`), manifest signature
   verification against the ADR-0024 trust set, content staging, and all
   hashing stay unprivileged — none of them needs a root-owned path. This
   is a sharpening of issue #49's candidate, not an alternative to it.

2. **Unprivileged work stages into a per-user spool inside the state
   root: `/var/lib/shuttle/spool/<uid>/`.** The spool must live on the same
   filesystem as the state root because commit is rename(2) — a symlink or
   a foreign mount would fail at the boundary with EXDEV, which is fail
   closed but useless; same-fs by placement is the design. The helper
   (Decision 3) creates `<uid>` on first use, mode 0700, owned by the
   caller. Staged trees are named `spool/<uid>/.staging-<N>` with the same
   layout they will have after commit (`manifest.json`, `extensions/`,
   `store/` blobs as hardlinks — same-fs with the blob store is already a
   documented requirement, `src/runtime.rs:24-30`). The spool is the
   caller's disk usage: an abandoned install costs the user's space, not
   root's, and the spool is swept on the next successful run of any
   runtime verb for that uid.

3. **Mechanism: one setuid-root micro-helper, `shuttle-activate`, mode
   4755 root:<group>.** Not a systemd unit, not D-Bus, not sudo. The
   helper is a separate small binary in the same package, invoked
   `shuttle-activate <request-file-descriptor|request-path>` — it does
   exactly one thing and exits. The daemon law is satisfied structurally:
   a setuid binary that lives for the duration of one rename sequence is
   the same class as the short-lived shuttle commands ADR-0011 §5 already
   sanctions (and as fusermount/mount-style helpers every *nix ships); it
   holds no state, listens on nothing, and survives a `kill -9` without
   leaving anything the journal machine cannot converge (Decision 5). It
   is also the only candidate that works on the non-systemd hosts ADR-0032
   documents: on a SysV box the sysext/reload steps resolve to `None` (the
   existing `RuntimeTools` machinery, `src/runtime.rs:372-426`) and the
   helper degrades to rename+relink alone — no systemd required anywhere
   on the privilege path.

4. **The helper re-verifies everything; it trusts no unprivileged claim.**
   This is the security core of the ADR. Given a request naming a staging
   tree and an operation (install-commit / flip / remove / gc-sweep), the
   helper:
   - resolves the caller's **real** uid (it is setuid; never trust
     invocation-time identity strings) and requires membership in the
     `<group>` of Decision 6 — root always passes;
   - opens the spool path with `openat2(RESOLVE_NO_SYMLINKS |
     RESOLVE_BENEATH)` semantics (falling back to component-wise
     `lstat` + dir-fd `openat` where openat2 is unavailable), refusing any
     symlink or path escape — a staging dir reachable through a symlink
     would let a caller redirect the rename outside the state root;
   - checks the staging dir is owned by the calling uid, mode 0700;
   - **re-reads the manifest from the staged tree itself** (never from
     caller-supplied bytes), re-verifies its signature against the
     `/etc/shuttle/trusted-keys/` set with the ADR-0024 revoked-first rule
     (`src/runtime.rs:80-88`), and **re-hashes every staged file against
     the manifest** immediately before the rename. This is what kills the
     TOCTOU argument: the unprivileged side's verification is advisory;
     the content that is renamed is the content that was just hashed, and
     the hashing happens through directory file descriptors the caller's
     other processes cannot swap underneath. A caller racing their own
     staging dir gains nothing — content that fails signature or hash is
     refused, and content that passes is content the caller was already
     authorized to install. The privilege escalation question ("may this
     uid change the system store?") is answered by group membership alone;
     the integrity question ("is this content trustworthy?") is answered
     by the keys, not by the caller's word;
   - takes an `flock` on a `.activate.lock` in the state root for the
     whole request, serializing concurrent activations from multiple
     users. Generation numbering is max+1 (`src/runtime.rs:713`); the lock
     keeps two users' commits from colliding on the number and keeps
     commit/flip atomic as a pair;
   - performs journal transitions exactly as the existing machine
     dictates: `started` before touching the tree, `staging` after the
     first rename, `committed` before the flip (`src/runtime.rs:55-60`) —
     then flips `active`, relinks the extension trees, and runs
     `systemd-sysext refresh` + `systemctl daemon-reload`.
   - rejects request arguments that are not the constrained vocabularies:
     package and generation identifiers `[a-z0-9-]` (the ADR-0032
     classifier charset), absolute paths only inside the spool and state
     roots.

   The helper sanitizes its environment (fixed absolute paths for the
   systemd tools via the existing `RuntimeTools::from_host` resolution,
   `src/runtime.rs:392`; no PATH/LD_* inheritance) and runs the systemd
   steps with the current best-effort contract — warn-never-fail when the
   tool is absent, a counted, named `skipped` otherwise
   (`src/runtime.rs:1648-1685`).

5. **Failure semantics are fail-closed and journal-shaped; degradation is
   a named error, never a silent skip.** Three cases, distinguished:
   - **Denial** (caller not in group, signature/hash re-verification
     failure, path validation failure): nothing is renamed; the request
     exits non-zero with a named error (`activation denied: uid 1000 not
     in group shuttle` / `boundary verification failed for <pkg>: hash
     mismatch`). The staged tree stays in the caller's spool for
     inspection and is swept on the next verb. The CLI never degrades to
     "installed but not activated" — an unactivated commit is reported as
     what it is, and `shuttle rollback`/re-run converges it.
   - **Crash mid-request** (helper killed after `started` / `staging` /
     `committed`): the existing journal recovery answers. `started` →
     remove journal; `staging` → remove staging dir + journal;
     `committed` → finish the idempotent flip + drop journal
     (`src/runtime.rs:58-60`, `:644-683`). The helper introduced no new
     durable state, so the existing converge-on-next-command contract
     holds unchanged; `activate()`'s idempotency (`src/runtime.rs:1645`)
     means re-running activation heals a partially activated system.
   - **systemd step failure after the flip** (sysext refresh or
     daemon-reload runs and fails): the generation is committed and
     `active` is flipped — truth is on disk and rollback is available.
     This stays best-effort-with-a-note per the current contract, and the
     note is the user-visible signal that a re-run of any runtime verb (or
     the boot oneshot, #60) will heal it.

6. **Multi-user: a dedicated `shuttle` group, checked against the calling
   uid; ShuttleOS pre-activation needs neither.** On generic hosts the
   operator admits users to `shuttle` (or, where local convention prefers,
   aliases the group to `wheel` at packaging time — the helper checks
   group membership, not the group name). Root always passes. The
   ShuttleOS image-builder case never touches the helper: image assembly
   runs as root and writes the store directly, and the emitted boot
   oneshot (#60) activates as root at first boot
   (`src/image/state.rs:237`, `src/image/boot.rs:287`) — the helper exists
   for post-boot interactive administration on a running system, which is
   exactly issue #49's gap.

7. **`remove`, `rollback`, and `gc --prune` ride the same helper; the
   trust-set check is scoped to the request.** Flip-only requests (rollback)
   name a target generation number and validate it exists inside the state
   root before flipping. Removal and prune name generation numbers and
   package names in the constrained charset only — never caller paths —
   and operate purely inside the state root. Only install-commit re-runs
   signature and hash verification, because only install-commit introduces
   new content; flip/remove/gc move or delete content the helper can
   re-derive from the manifests already on disk.

## Alternatives considered

- **Short-lived privileged systemd unit (`systemd-run --pipe` or an
  oneshot) gated by polkit.** Rejected for three reasons. (1) *Non-systemd
  hosts*: ADR-0032 documents WSL2-systemd-off and SysV as supported pod
  hosts; a privilege mechanism that exists only where systemd does makes
  the runtime verbs second-class exactly there. (2) *Policy blindness*:
  authorizing a transient unit means authorizing its argv, and polkit's
  systemd actions cannot inspect what a transient unit will do — the
  authorized action is "run this command as root," which is a root shell
  wearing a queue number. The setuid helper inverts this: the policy is
  the binary's code. (3) *Complexity*: the request descriptor, the
  re-verification, and the journal discipline still all have to be
  written; the unit only relocates them behind a broker. Recorded
  honestly: on an all-systemd future this alternative deserves a re-look
  (Revisit triggers).
- **polkit-gated D-Bus service.** Rejected outright: it is a privileged
  long-lived process holding the system bus — the daemon ADR-0011
  Decision 5 forbids, full stop. polkit being pre-positioned
  (`pkgs/p/polkit.lua`) is a package fact, not an architectural
  instruction; using it would mean shipping the thing the daemon law was
  written to prevent.
- **sudoers fragment (`sudo shuttle install …`).** Rejected: sudoers
  argv matching is advisory and non-portable (it can be bypassed via
  environment, subcommands, or a differently-spelled invocation unless
  every entry point is wrapped), and `sudo shuttle` runs the *entire
  CLI* as root — the boundary-validation story of Decision 4 would have
  to be rebuilt inside a root process that also builds images. It also
  assumes sudo exists, which a minimal ShuttleOS rootfs does not
  guarantee. The setuid helper is sudo reduced to exactly one operation,
  with the validation in the operation itself.
- **`pkexec` around the helper.** Tempting — it is setuid + polkit for
  free — but rejected for v1: it imports a session-agent dependency
  (polkit's agent must be running in the caller's session), it breaks on
  headless/SSH admin, and its polkit policy would again be "may run this
  binary," duplicating the group check with more machinery. The group
  check is coarser than per-action polkit policy and that is accepted
  (Consequences); a polkit policy file layering finer rules over the same
  helper is a revisit trigger, not a dependency.
- **Whole-verb-as-root (`shuttle install` re-execs itself under sudo/
  doas when EACCES).** Rejected: it keeps the privilege surface at "the
  entire runtime" instead of the rename, forfeits the unprivileged
  fetch/verify/stage split the staging design already invites, and
  reproduces the opaque half-root failure mode (some files written as the
  user, some as root) that issue #49 exists to kill.
- **World-writable state root with sticky-bit discipline (dpkg-style
  `/var/lib` openness).** Rejected: it removes the boundary instead of
  crossing it cleanly; gc, prune, and blob deletion become writable by
  any group member without any choke point for the lock or the journal,
  and the "root-owned store" invariant of ADR-0023's state-partition
  story is weakened for no operational gain.

## Consequences

**Positive**: the privileged surface is one small, auditable binary with a
constrained vocabulary instead of a daemon or a CLI-as-root; the
unprivileged phase keeps all existing verification (assertions, ADR-0024
trust set, hashing) exactly where it is, and the boundary re-runs the
trust checks on content it is about to bless, so a compromised spool
cannot launder unverified bytes into the system store; the journal
crash-recovery machine and the idempotent `activate()` seam absorb crash
and denial semantics with no new durable state; non-systemd hosts get the
full verb set (minus the sysext steps that never applied there) with one
mechanism; concurrent multi-user installs serialize at one flock instead
of racing max+1 generation numbers; the boot oneshot (#60) and the
interactive path converge on the same `activate` seam they already share;
the spool makes partial-failure costs visible and attributable (user
disk, user cleanup); the decision is implementable entirely within the
existing runtime structure — no new storage model, no new journal, no new
trust machinery.

**Negative**: a setuid binary is a real attack surface however small —
Rust's std makes env/argv hygiene easy to get subtly wrong, the openat2
fallback path is a classic audit trap, and the double hash+signature
verification at the boundary costs CPU on every install (accepted:
installs are incremental, and verification at the boundary is the price
of not trusting the caller); group administration is a manual host step
(documented, never performed silently — the ADR-0032 linger precedent);
the group check is all-or-nothing (any member can install any key-signed
content system-wide — finer-grained polkit policy is deferred); the
journal now crosses a process boundary, so the unprivileged CLI must
tolerate "helper refused after stage" as a first-class outcome in its UX;
tests need a fake-root harness (the bubblewrap sandbox precedent,
ADR-0004) since CI cannot setuid; and the helper adds a second shipped
binary whose setuid bit packaging (perms, group, RPM/deb scriptlet) is a
new release surface that must never silently install non-setuid and call
itself done.

## Revisit triggers

- All supported hosts gain systemd (the WSL2-default and SysV cases
  disappear) → re-compare against the polkit-gated oneshot alternative;
  the request descriptor and boundary verification carry over unchanged,
  only the launcher changes.
- Per-user or per-package authorization is required (multi-tenant admin
  box, fleet operator roles) → a polkit policy layer over the same
  helper, or key→namespace scoping in the ADR-0024 trust set; both are
  additive to Decision 4's validation, not replacements.
- `systemd-sysext` presentation is replaced (ADR-0012 Decision 4's
  composefs-pending audit resolves, or sysext is dropped for a different
  merge) → the helper's post-flip steps change; the spool/journal/rename
  core is presentation-agnostic and stands.
- The ShuttleOS interactive-admin story matures (e.g. a management
  endpoint appears) → the helper's group policy and the D-Bus-service
  question re-open together; the daemon law still applies to whatever
  answers.
- Staged-spool disk exhaustion becomes a reported incident class →
  spool quotas or an idle-sweep timer policy, decided then.

## Evidence

- Privileged defaults with zero checks: `src/runtime.rs:106`
  (`DEFAULT_STATE_DIR = "/var/lib/shuttle"`), `:109`
  (`DEFAULT_EXTENSIONS_LINK_DIR = "/var/lib/extensions"`); issue #49
  (EACCES mid-journal, "zero privilege checks anywhere").
- Atomic staging / flip / journal contract: layout comment
  `src/runtime.rs:7-16`; journal states and recovery `:49-60`, `:624-683`;
  `flip_active` (temp symlink + rename) `:1626-1641`; `activate`
  (relink + `systemd-sysext refresh` + `daemon-reload`, best-effort with
  named `skipped`, idempotent) `:1643-1687`; generation max+1 `:713`.
- Narrow privileged surface (rename + refresh + reload): the `activate`
  body, `src/runtime.rs:1660-1673`; issue #49's reduction ("the
  privileged surface reduces to rename + `systemd-sysext refresh` +
  `daemon-reload`").
- Trust machinery reused at the boundary: device anchor
  `src/runtime.rs:112`; trusted-key set + operator keychain + revoked-first
  rule `:73-88`; ADR-0024 §4 (revocation distinguishable from
  never-trusted).
- Systemd-optionality already handled: `RuntimeTools::from_host` /
  `for_pod_runtime` / `SHUTTLE_SYSTEMD` opt-out, `src/runtime.rs:372-426`.
- Privileged boot activation already shipped: `src/runtime.rs:1689-1730`
  (boot entry, journal convergence rule), `src/main.rs:4040` (`shuttle
  runtime activate`), `src/image/state.rs:237`, `src/image/boot.rs:287`
  (the #60 oneshot and its client).
- State partition and `/var/lib` residency: ADR-0023 Decisions 2, 4
  (`/var/lib/shuttle` and `/var/lib/extensions` live on the state mount) —
  the spool placement of Decision 2 rides this mount.
- Daemon law: ADR-0011 Decision 5 ("no privileged long-lived daemon
  ships. Runtime features are emitted systemd units/timers plus
  short-lived shuttle commands"); ADR-0024 Decision 2 applies the same
  law to updates.
- Runtime verbs in scope: ADR-0012 Decision 5 (Phase 24b verb set).
- User-level scope precedent and the "documented, never performed
  silently" host-step norm: ADR-0032 Decisions 5, 8.
- polkit pre-positioned as a pool package only: `pkgs/p/polkit.lua:1-27`.
- Setuid/escalation-hygiene precedent in-repo: ADR-0004 (bubblewrap
  sandbox — the project's existing bounded-escalation tooling).
