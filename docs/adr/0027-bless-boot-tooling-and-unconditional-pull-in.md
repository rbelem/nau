# Ship the bless-boot tooling the base lacks, and pull boot-complete.target into every boot

## Status

Accepted (2026-09-13). Amends ADR-0024 §3 (try-boot assessment). Grounded in
issue #85, found by the #81 default-path KVM proof on the core26 chain.

## Context

ADR-0024 §3 emits `systemd-bless-boot.service`, `boot-complete.target`, and the
health unit that gates the target — but emits them into a transaction nothing
guarantees. Stock systemd pulls `systemd-bless-boot.service` into
`basic.target` via `systemd-bless-boot-generator`, and only when boot counting
is already in effect (`LoaderBootCountPath` set, i.e. from the first sysupdate
install on). Two measured facts break the emitted machinery:

1. **The core26 base ships neither binary.** `core26_462` (systemd 259) ships
   `boot-complete.target` and the counted-boot protocol but no
   `systemd-bless-boot` and no `systemd-bless-boot-generator` (the UC22-era
   bases — measured core22 2437/2955 — ship both). On UC26 a counted boot
   could never be marked good: nothing pulls the bless service, and even a
   hand-pulled one would exec a missing `/usr/lib/systemd/systemd-bless-boot`.
   The countdown would exhaust into a spurious revert after three healthy
   boots.
2. **Factory boots are never assessed on ANY chain.** The generator is silent
   without `LoaderBootCountPath`, so the counterless factory UKI gets no
   `boot-complete.target` in its transaction and the #84 completion gate
   ("completion must be observable") cannot hold for the first boot — the
   exact boot a fleet operator must trust.

## Decision

1. **The completion target is pulled into every boot transaction.**
   `emit_boot_assessment` writes `etc/systemd/system/basic.target.wants/
   boot-complete.target`. `Wants=`, not `Requires=`: a failed health check
   fails the target (so the boot is never blessed) without failing the boot
   itself. On counted boots the generator's pull-in coexists with this link —
   systemd deduplicates the job. `systemd-bless-boot.service` itself stays
   un-enabled: on factory boots there is no boot counter, so running the
   helper against a missing counter must not become a red failed unit on
   every first boot; "the bless legitimately does not apply" is the #84-honest
   reading of an assessed factory boot.
2. **The build ships the two binaries when the base lacks them.** The step-5c
   gate calls `stage_bless_boot_binaries` (`src/image/staging.rs`): bases that
   ship their own tooling pass through untouched; otherwise the tooling comes
   from the build host's systemd installation, located via
   `SHUTTLE_BLESS_BOOT_DIR`, `which`, and the FHS paths
   (`/usr/lib/systemd`, `/lib/systemd`, their `system-generators/` subdirs),
   staged at `usr/lib/systemd/systemd-bless-boot` and
   `usr/lib/systemd/system-generators/systemd-bless-boot-generator`.
3. **The emitted units carry `DefaultDependencies=no` — the ordering-loop
   lesson.** The first factory-boot proof of the naive pull-in was rejected
   by systemd itself: `Ordering cycle found, skipping boot-complete.target`.
   The loop was basic.target →(wants)→ boot-complete.target →(requires)→
   shuttle-boot-health.service →(implicit service default `After=basic.target`)
   → basic.target; systemd deleted the target from the transaction and the
   completion marker never appeared (a second, cascaded cycle skipped an
   unrelated lxd unit riding the same loop through multi-user). Fix, matching
   the stock completion units: `boot-complete.target` and the health unit are
   emitted with `DefaultDependencies=no`, and the health unit's pre-#85
   `After=default.target multi-user.target graphical.target` narrows to
   `After=local-fs.target` — the one edge the default gate (`shuttle runtime
   activate`, which activates the store on the state partition) actually
   needs, and one that completes before basic.target, so no loop. Verified
   statically with `systemd-analyze verify --root` before rebuilding, then by
   the KVM proof.
4. **Every sourcing step fails closed.**
   - *Arch-aware*: the ELF `e_machine` of both host binaries must match the
     image arch — cross builds need explicitly provided tooling.
   - *Version-gated*: the host binary's own `--version` must parse and clear
     the #79 floor (240); below 255 the existing cosmetic-EBUSY warning
     applies.
   - *Runnable on-device*: the `libsystemd-shared-<major>.so` the binaries
     link resolves against the guest's own lib when the major matches
     (RUNPATH → that directory), otherwise the host's copy is staged into
     `/usr/lib/systemd` (a self-consistent pair — `libsystemd-shared` is not
     a stable ABI across majors) with its host RUNPATH stripped. The guest
     libc must byte-define every `GLIBC_*` version the staged host ELFs
     request — the #80 `GLIBC_ABI_GNU2_TLS` lesson (nix tooling needs
     glibc ≥ 2.36; the core22 guest's 2.35 lacks it) enforced at build time.
     All static: no foreign binary is ever executed.
   - *Post-condition*: `assert_bless_boot_tooling_staged` re-reads the staged
     tree after emission — assessment emitted without both binaries present
     is a build error, never a first-boot discovery.
5. **Version skew loader↔tooling is tolerated, deliberately.** Strict
   tooling-major == base-major equality would fail every UC26 build today (no
   systemd 259 tooling exists on this host) and is unnecessary: the shipped
   pair is self-consistent, and `bless-boot` talks to the world through the
   stable boot-count protocol (240+) plus EFI variables and ESP renames — the
   same skew UC images already carry between the gadget's systemd-boot and
   the base's systemd.

## Consequences

**Positive**: counted boots on UC26 can actually be blessed (the generator now
exists on-device); factory boots reach `boot-complete.target` with the health
unit executed, so #84's marker means something on the first boot; a tooling
gap fails at build time with a named fix instead of a device that reverts
after three healthy boots.

**Negative**: the image carries the build host's tooling bytes (≈ 47 KiB of
binaries plus, when majors skew, a ≈ 6.5 MiB `libsystemd-shared`) — accepted
for correctness over byte-minimality, mirroring #81's ship-the-binary stance.
Cross-arch builds now require matching host tooling (fail-closed, named).
The guest-libc byte gate is a static approximation of dynamic-linking
suitability, deliberately conservative.

**Revisit triggers**: a future core base that ships the tooling again shrinks
this to the fast path. If `systemd-bless-boot` ever grows a hard
`libblkid`/dlopen dependency on its bless path, the staged closure must grow
the util-linux libs with it.

## Evidence

- Measured `core26_462`: no `systemd-bless-boot`, no generator, systemd 259
  (`usr/lib/x86_64-linux-gnu/systemd/libsystemd-shared-259.so`), glibc 2.43.
- Measured `core22_2437`/`core22_2955`: both binaries present (fast path).
- KVM proofs (2026-09-13, this branch): factory UC26 boot reaches
  `Reached target boot-complete.target` with the health unit executed before
  it; the counted path (`+3-0`) shows the shipped tooling blessing via the
  generator. Console-side detail: while a job spinner is active (the known
  90 s root-`dev-disk-by` wait of this proof chain), systemd suppresses
  per-job console lines, so the health unit's own `Starting/Finished` lines
  can be eaten from the serial log even when the job ran — the boot journal
  (dumped to the ESP by a proof oneshot) is the authoritative evidence.
- The fail-closed gates fired in production during development: a build
  without `SHUTTLE_BLESS_BOOT_DIR` on this host was refused with the named
  error, and a staging attempt whose host tooling needed a GLIBC version the
  wrong-arch libc could not define was refused naming both.
