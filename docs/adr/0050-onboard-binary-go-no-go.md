# ADR-0050: Onboard binary split — measurement dossier and go/no-go

## Status

Proposed. Carries the go/no-go ruling for the binary-split plan (#312–#320),
decided by the threshold the council ratified when it commissioned the
measurement: **PROCEED only if the device-reachable closure is ≥ ~15–20% of
the release binary; otherwise NO-GO** (close #314–#320 as wontfix, keep the
single binary). Measured 2026-09-30 against HEAD `b1bdc7a` (isolated export,
pinned toolchain); the numbers below are the dossier. The measurement lands
**below the bar** — verdict: **NO-GO** (see [Decision](#decision)).
Operator ratification pending; until it lands, the split tickets stay open.

## Context

The split plan (#312–#320) proposed carving the onboard/device surface out of
the single `nau` binary into its own guest artifact so that images stop
embedding host machinery (the Luau VM, the analyzer, the build/pod/farm
stack) at `/usr/bin/nau`. Before any machinery lands, this ADR answers the
only question that decides whether the machinery should exist at all: **how
much of the release binary is actually reachable from the device verb set?**
If the device-reachable share is substantial (≥ 15–20%), the guest is a real
subsystem worth a dedicated artifact; if it is thin, the split's tracer,
allowlist contracts, and dual-artifact CI cost more than the bytes they save.

Everything here measures the COMMITTED state: HEAD exported with
`git archive` into a scratch dir, built release with the pinned toolchain
(`nix shell nixpkgs#gcc -c env -u LD_LIBRARY_PATH -u COMPILER_PATH -u
LIBRARY_PATH CC=gcc CXX=g++ devbox run -- cargo build --release`), zero
warnings. `cargo bloat` is not installed in the pinned environment — skipped;
per-family attribution below comes from `nm --size-sort -S -C` on an
unstripped rebuild (`CARGO_PROFILE_RELEASE_STRIP=none`, env-only override —
no source or manifest change).

## Measurement results

### Sizes

| Artifact | Bytes | Note |
|---|---:|---|
| `target/release/nau` (as shipped) | 24,816,624 | `strip = true` in `[profile.release]` |
| Same build, unstripped | 32,820,400 | symtab/strtab visible for `nm` |
| Reclaim already banked by `strip` | 8,003,776 | 24.4% of the unstripped file |

Section breakdown of the shipped binary: `.text` 19,424,992 B; `.rodata`
1,622,480 B; `.eh_frame` 1,687,744 B; `.gcc_except_table` 704,740 B;
`.rela.dyn` 649,632 B; `.data.rel.ro` 343,280 B; `.data` 41,592 B. Rust's
linker defaults already apply `--gc-sections` on this target, so the numbers
below are post-GC as far as the toolchain's reachability analysis goes; the
residual question (what a guest-only crate graph would shed beyond that) is
exactly what the #314 prototype would have confirmed empirically.

### Attribution (nm symbol bytes, demangled; 20,678,466 B total)

| Family | Bytes | % of symbols | Notes |
|---|---:|---:|---|
| Luau VM + type analyzer + shim | 5,450,298 | 26.4% | `Luau::*`, `lua*` C/C++ of the vendored analyzer, `nau_checker_*`/`nau_check_*` shim bridge (mlua `luau` feature + `build.rs` cc) |
| `nau` own Rust | 4,351,318 | 21.0% | all 26 verbs + workers (pre-reshape tree at HEAD) |
| Host-only long tail | ~3,243,110 | 15.7% | pgp/rustls crypto dep tree (k256, p384/p521, cx448, num_bigint), BZ2/lzma/zlib/HUF decompressors, miette/toml_edit/unicode infra |
| rustls + ring + ureq | 2,611,796 | 12.6% | TLS for the floor-tool provisioner (issue #101) |
| stdlib (core/std/alloc) | 1,073,404 | 5.2% | shared by every artifact |
| pgp (rpgp) | 1,055,699 | 5.1% | snap-store assertion verify (host) |
| clap + clap_builder | 878,551 | 4.2% | any CLI binary needs this much |
| — of which clap_complete | 92,258 | 0.4% | completion generation, host-only |
| full_moon | 664,584 | 3.2% | Rust-side Lua parser (host) |
| mdns-sd | 508,601 | 2.5% | LAN peer discovery (`peer browse`/`serve`) |
| dbus / libdbus (vendored) | 462,245 | 2.2% | Secret Service lookups (workstation) |
| ed25519/curve25519-dalek | 177,476 | 0.9% | **device-reachable** (update-manifest verify) |
| rsa | 113,391 | 0.5% | UC seed keygen only (host) |

`%` columns are of nm symbol bytes, not file size — the file carries
`.eh_frame`, relocations, and padding on top. Ratios transfer approximately.

### Device verb set (measured from unit emission — the allowlist)

Exactly two verbs are exec'd on a device, both pinned absolutely to
`/usr/bin/nau` (issue #81; `NAU_BIN_PATH`, `src/image/staging.rs:499`):

| Verb | Unit | Source |
|---|---|---|
| `runtime activate` | `nau-runtime-activate.service` (boot-time generation activation) and the default `ExecStart` of the boot-health gate | `ACTIVATE_EXEC` `src/image/state.rs:300`; `BOOT_HEALTH_EXEC` `src/image/boot.rs:303`; unit bodies `state.rs:308–328`, `boot.rs:395–421` |
| `runtime recover-slots --esp-mount <esp>` | `nau-slot-recovery.service` (stranded-slot reclaim, issue #86) | `RECOVER_SLOTS_EXEC` `src/image/boot.rs:47`, rendered at `boot.rs:93–116` |

No other `/usr/bin/nau` exec line exists in any emitted unit. Every other
`ExecStart=` in the image is a snap service, systemd's own
`systemd-sysupdate`/`systemd-bless-boot`, a `/bin/sh` repart one-liner, or
`/bin/true`.

### Evidence behind the closure

**(a) The device path never invokes `nau run`.** The only route into
`confine::run` is the pod-domain `nau run` verb (`src/main.rs:4058–4082`),
which requires a reconciled pod directory on the invoking machine. The two
device verbs go elsewhere entirely: `runtime activate` →
`RuntimeStore::activate_current` (`src/main.rs:4972`, `src/runtime.rs:1773`)
→ journal recovery + symlink flip + `systemd-sysext refresh` +
`systemctl daemon-reload` (external tools via `RuntimeTools`, 
`src/runtime.rs:1718–1749`); `runtime recover-slots` →
`slot_recovery::recover_slots` (`src/main.rs:4995`,
`src/slot_recovery.rs:664`) → lsblk/sfdisk partition assessment + PE
completeness checks. Neither touches `confine.rs` or the snap value types —
the guest closure does **not** grow by them.

**(b) Device-side crypto is ed25519-dalek only.** The one verification the
device performs is the update-manifest envelope check
(`src/runtime.rs:826`, inside `install_batch`) → `verify_signatures`
(`src/runtime.rs:2207`) → `sign::verify` / `Keychain::load_dir` /
`reject_revoked` against the embedded anchors (`/etc/nau/update-key.pub`,
`/etc/nau/trusted-keys/`) — all `src/sign.rs`, which is ed25519-dalek
(`src/sign.rs:87`). The pgp stack (`src/assert.rs:56–57`) is reached from
the snap-store pull path (`src/store.rs:233`) and UC seeding (`src/uc.rs`) —
host-side; rsa (`Cargo.toml:28`, `src/uc.rs:83`) exists for UC seed keygen
only. Neither is device-reachable.

**(c) On-device `pull` never reaches mDNS.** `src/pull_peer.rs` contains zero
references to discovery or mDNS — the peer-transfer lane resolves through
registry/static peers. mdns-sd is consumed only by `discovery.rs`
(`Cargo.toml:70`), whose callers are the `peer browse` listing verb
(`src/main.rs:4655`) and the `serve` announce (`src/serve.rs:231`) — neither
is in the device verb set. Device-side updates ride systemd-sysupdate
(`src/image/boot.rs:118–151`): systemd's own machinery downloads and applies
the payload; nau is not in that loop.

### Device-reachable closure (the gated number)

The verb set's transitive needs: the runtime store machinery, sign.rs's
ed25519 path, the argv parser, serde/sha2/sha3 hashing, and std. Sized from
the attribution table (symbol bytes):

| Closure member | Bytes | Basis |
|---|---:|---|
| ed25519/curve25519-dalek | 177,476 | measured bucket |
| clap + clap_builder | 878,551 | measured bucket (clap_complete excluded — host tooling) |
| nau-own device slice (runtime.rs, sign.rs, slot_recovery.rs, command.rs, output.rs, cli.rs tree, dispatch) | ~435,000–650,000 | 10–15% of the measured `nau` bucket (estimate) |
| stdlib slice | ~215,000–320,000 | 20–30% of the measured stdlib bucket (estimate) |
| sha2/sha3/serde edges | ~5,000 | inside shared buckets; negligible |
| **Device-reachable closure** | **~1.7–2.0 MB** | **≈ 8–10% of symbol bytes; ≈ 7–8% of the 24.8 MB release binary** |

This is a symbol-family estimate: the honest exact number requires the #314
prototype build (linking a guest-only crate graph and reading its
`--gc-sections` output). The estimate's order of magnitude is not in doubt —
every plausibly mis-bucketed byte moves it by fractions of a percent.

## Decision

**NO-GO.** The device-reachable closure measures ≈ 8–10% of the release
binary — **below the ratified 15–20% bar**. On the threshold the council set
when commissioning this measurement, the split tickets **#314–#320 are
recommended to close as wontfix**, and the single-binary posture stands: one
`nau`, staged into every image at `/usr/bin/nau` exactly as today.

Why the thin closure kills the split rather than motivating it: the split
plan does not shrink the workstation artifact at all (the host still builds
every family in the table); its entire payload-side payoff is bounded by what
a guest-only link could shed, and that payoff is small in absolute terms —
the 24.8 MB binary rides inside a GB-scale dm-verity rootfs (~1–2% of the
image, less after payload compression), so the theoretical ~20 MB-per-slot
saving is noise against the cost side: a permanent second artifact, the #314
tracer and its contract tests, the allowlist enforcement surface, and a
dual-build CI matrix. A two-verb boot responder is not a subsystem that
amortizes that machinery.

**Transparency note (recorded for the operator, does not change the
verdict):** the inverse metric — the host-only mass a split *could* shed from
the guest — measures ≈ 76–85% of symbol bytes (Luau 26.4%, TLS 12.6%, pgp
5.1%, full_moon 3.2%, mdns 2.5%, dbus 2.2%, rsa 0.5%, clap_complete 0.4%,
crypto long tail, plus most of nau's own code). If the threshold were
re-gated on *removable* mass rather than *device-reachable* mass, the verdict
would flip. This ADR applies the threshold as ratified (closure-based); a
conscious re-gate is the operator's call and out of scope here.

### Binary naming (recorded for whichever posture wins)

The council ratified the cargo `[[bin]]` target name **`nau-mothership`**
(the glossary's own term: *a pod is the small nau served by the system
mothership*). The INSTALLED filename on any device remains immutable
**`/usr/bin/nau`** — `NAU_BIN_PATH` (`src/image/staging.rs:499`), the
absolute `ExecStart` constants (`src/image/state.rs:300`,
`src/image/boot.rs:47`), and the staged-path drift-pin test keep the
installed name and the unit exec targets from drifting. An optional
`nau-mothership` debug hardlink in the build tree is permitted; nothing on a
device may reference it. This naming stands regardless of the NO-GO (build
and docs may adopt the target name; the device path never changes).

## Invariants pinned (survive the verdict)

1. **`nau <domain>` UX** follows ADR-0049's post-reshape spellings; any
   future device-surface work speaks the namespaced grammar, never new
   top-level verbs.
2. **Hidden workers stay `current_exe` self-re-exec'd** — no env override,
   no PATH discovery (`src/isolate.rs:318–325`; ADR-0049 Security section).
   The isolation ruling is about discovery, not visibility.
3. **The device artifact is staged as `/usr/bin/nau`** — absolute
   `ExecStart=` in every emitted unit, the staged path and the unit constants
   pinned together by test (`src/image/staging.rs:496–499`).
4. **Device surface = explicit allowlist.** Today that is exactly the two
   verbs in the table above. A verb joins the allowlist only by appearing in
   a unit emission first, or by a named ruling recorded in an ADR — never by
   accident of linkage.
5. **Embed resolution order** for any staged-artifact resolution: env
   override → sibling of `current_exe` → fail-closed at default-flip; never
   PATH. (The production form today is simpler — `embed_source()` is
   `current_exe` itself, `src/image/staging.rs:737–744`; the full order is
   the contract any future indirection must implement.)
6. **`strip = true` stays** in `[profile.release]` (`Cargo.toml`): the guest
   never needs symbols — the boot units exec it headlessly, and every A/B
   slot and update payload carries the stripped bytes.

## Consequences

**Positive:** the split machinery is never built — no tracer, no second
artifact, no dual CI matrix; the measurement dossier (this ADR) is the
artifact instead. The single-binary invariants (§ Invariants) are now
explicit and testable rather than incidental. `strip = true`'s already-banked
8.0 MB is on record so nobody re-litigates "is the binary mostly symbols".

**Negative:** images keep embedding the full binary at `/usr/bin/nau`
(~24.8 MB per slot; ~1–2% of the rootfs). The ~76–85% host-only mass stays
reachable from the device artifact — the attack-surface argument for the
split is answered by the allowlist invariant (§4) and dm-verity instead of by
linkage. If device payloads ever become a measured constraint, the remedy is
a fresh ruling re-gating on removable mass, not a silent restart of #314.

## References

- Binary-split council plan and tickets #312–#320 (the plan this ADR measures)
- ADR-0049 (CLI domain namespacing — the `nau <domain>` UX and the
  pod+runtime onboard seam it pinned), ADR-0011 (update signing, the
  ed25519 device verify path), ADR-0033 (peer sharing — why mdns-sd is
  host-side), ADR-0023 (state partition / boot activation), ADR-0024
  (A/B sysupdate — the device update loop that never invokes nau)
- Measurement raw data: nm dump and build logs under `/tmp/opencode/`
  (scratch; reproducible from the protocol in [Context](#context))
