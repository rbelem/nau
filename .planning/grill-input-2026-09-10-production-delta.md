# Grill session — production delta (2026-09-10)

Decisions ratified by the owner in a `/grill-with-docs` session. Design records:
**ADR-0023** (state partition + `/var` split) and **ADR-0024** (on-device
sysupdate execution, try-boot, key ceremony). Glossary updated (`State
partition`, `Boot assessment`, `Key ceremony`).

## Frontier, all settled

| # | Question | Resolution |
|---|---|---|
| Q1 | State partition in the image DSL | Declared `Partition` role — `"state"` (native), `"system-data"` (UC), extending the existing role field (ADR-0023 §1) |
| Q2 | What persists across an A/B update | T6 staged position: persist `/var/lib` (store, extensions, identity), generate `/etc` defaults in the image, runtime overrides via state (ADR-0023 §2–3) |
| Q3 | Sysupdate execution scope | Full step (d): trigger + try-boot + health check + revert, ticketed separately (ADR-0024 §2–3) |
| Q4 | "Ceremony enforcement" | Code (trust policy: revoked keys refused) + a `/wizard` runbook, not code only (ADR-0024 §4) |
| Q5 | Proof of done | Mixed: state partition + activation unit-tested; A/B flip + revert proven in QEMU; #50 is a hard prerequisite |
| Q6 | What makes `/var` writable | State partition mounted at `/var/lib`; `/var` skeleton tmpfs + `tmpfiles.d` (ADR-0023 §2) |
| Q7 | QEMU harness sequencing | #50 (QEMU boot-and-assert) is ticket 0; everything downstream of "does it boot" waits on it |
| Q8 | Key-ceremony scope | Operator CLI + device-side revocation distribution; SLSA-lite provenance (#56) stays out (ADR-0024 §4) |
| Q9 | Initrd-module audit site | Build-time hard gate in `build_disk_image`; `doctor` may warn (ADR-0024 §1) |
| Q10 | Generated vs hashed `/etc` | `/etc` stays in the hashed root; runtime overrides via state + tmpfiles, no merge engine (ADR-0023 §3) |
| Q11 | First-boot population | `tmpfiles.d` for directories + generated `shuttle-runtime-activate.service` oneshot for generation activation (ADR-0023 §4) |
| Q12 | Sysupdate trigger | systemd-native `sysupdate.timer` + `.service`, emitted only when `update_source` is set (ADR-0024 §2) |
| Q13 | Try-boot owner | Stock systemd: `systemd-bless-boot.service` + `boot-complete.target` + a gating health-check unit (ADR-0024 §3) |

## Gap-map evidence (2026-09-10, read-only recon)

- State partition: **PARTIAL** (UC-only; non-UC images have no state partition; no fstab/tmpfiles/mount units).
- On-device sysupdate execution: **ABSENT** — transfer files emitted, nothing triggers them, no revert path.
- `/etc` + `/var`: **PARTIAL** — `/etc` baked into the hashed root; no `/var` writes, no tmpfiles, no state split.
- `RuntimeStore` boot activation: **PARTIAL** — `activate()` exists (`src/runtime.rs:1518-1535`) but is called only from CLI paths; no boot unit.
- Key ceremony: **PARTIAL** — primitives in `src/sign.rs:164-330`, no CLI surface, no promotion step, no device-side revocation.
- Doctor/boot validation: **ABSENT** except the host-side verity config audit; no initrd module inventory, no sysupdate/state readiness check.

## Next

`/to-spec` on this session, then `/to-tickets` (blocking edge: #50 before the
try-boot/revert tickets), then `/implement` per ticket.
