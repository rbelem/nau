# Handoff: shuttle — full security stack built, boot-proven to userspace (2026-09-04)

## Session scope

One long session: resumed at Phase 23 (manifest IR + parity gate, 432 tests, 42 commits
unpushed), then implemented ADR-0011 steps (a)–(g), Phase 24b, Phase 25 + follow-ups,
three QEMU boot proofs, and close-out. Ended at **598 tests green, remote in sync**.

## Commits (all on main, all pushed to origin/main = 1fc5f45)

| Commit | What |
|---|---|
| `2338867` | feat(image): UKI boot chain via ukify (ADR-0011 step a) |
| `3213699` | feat(store): snap-revision assertion verification (step b; new src/assert.rs, rpgp) |
| `1ad11c5` | feat(image): dm-verity + roothash-in-UKI (step c) |
| `9e1f47d` | feat(image): sysupdate A/B + signed manifest (step d; minisign-shaped Ed25519, src/sign.rs) |
| `7a391fc` | feat(runtime): app units + confinement lint + key ceremony (steps e/f/g; src/units.rs, src/lint.rs) |
| `0a24ddb` | feat(runtime): install/remove/upgrade/rollback/gc with generations (Phase 24b; src/runtime.rs) |
| `86f2b4c` | feat(registry): OCI push/pull, curl transport, zero new deps (Phase 25; src/oci.rs) |
| `3ed92dd` | fix(image): pin 4K fs blocks under dm-verity (found by QEMU proof) |
| `0e96388` | docs(adr): close kernel-config audit; correct superseded planning notes |
| `1fc5f45` | feat(registry): pull-to-install, blob mounts, Artifact binding (Phase 25 follow-ups) |

Plus earlier in session: pushed the inherited 42-commit backlog first (`3e4c7c0..86f2b4c`).

## Boot proofs (all rootless, all under /tmp/opencode/, repo left clean)

| Proof | Result | Dir |
|---|---|---|
| KVM harness (qemu 11.1 + OVMF, Alpine login) | PASS | shuttle-vm/ (`boot-test.sh`, `SHUTTLE_IMG=` slot) |
| Shuttle-built UKI direct-boot (nix 6.18.45, ukify 261.1) | PASS, cmdline byte-identical | shuttle-uki/ |
| Full disk from disk (GPT+ESP+UKI+cmdline+roothash) | PASS to /init | shuttle-disk/ |
| Verity activation (`status: verified`, sentinel MATCH, switch_root) | PASS + stretch | shuttle-verity/ |
| Userspace (busybox getty AND systemd 261.1 PID1, multi-user.target) | PASS both | shuttle-userspace/ |

Key evidence-backed fixes: 4K/4K verity pairing (`3ed92dd`); virtio/dm-verity as
modules ⇒ initrd inclusion mandatory; `nixpkgs#systemdUkify` is the ukify attr;
`--threshold=5` integer form (systemd 261 rejects 5.0).

## Architecture (new since gap-analysis handoff)

- `src/assert.rs` — snap-revision chain verify (rpgp, hardcoded Canonical root)
- `src/sign.rs` — local Ed25519 sign/verify, Keychain, rotate/revoke
- `src/units.rs` + `src/lint.rs` — hardened unit emission, warning-only strict lint
- `src/runtime.rs` — generations, file-level CA store (hardlinks), journal, mark-sweep GC
- `src/oci.rs` — curl OCI client (Bearer, HEAD-dedup, mounts), push/pull/install
- Manifest `Artifact::Built` variant (eval still emits `unbuilt`, byte-stable)

## Known flakes / environment notes (do NOT chase)

- `attack_isolation` 15/16 under parallel load, 16/16 in isolation (5+ confirmations,
  untouched files). Bare shell (no devbox) fails 4 snap tests + eval_parity
  (missing mksquashfs/lua5.4) — pre-existing, verified via stash.
- No sudo on this box; losetup/mount/DM-host blocked. userns+mountns OK.
- dcg guard blocks `rm -rf`/compound shell — split commands, use write-tool.
- Subagent spawns failed 3× mid-session (ConnectionRefused); recovered. If a lane
  dies, its partial work is usually additive — inspect before replacing.
- Lane test-count arithmetic is unreliable — always rerun the full gate yourself
  (`cargo test --no-fail-fast`, `clippy --all-targets -- -D warnings`, `fmt --check`).
- Lane was right that lane-sandbox failures ≠ tree failures twice (snap tests).

## Open (ordered)

1. Privileged `build_disk_image` single-command run — needs a rooted host.
2. `analyzer-spike/` untracked — keep as evaluation record or delete.
3. Production delta (new phase): persistent /var, state partition, on-device
   sysupdate execution, ceremony enforcement.
4. `/tmp/opencode` proof dirs (~500M) — reclaim or archive recipes into docs.

## Suggested skills for next session

- `diagnosing-bugs` — if the privileged disk run surfaces real issues.
- `to-tickets` — to break the production delta (item 3) into grabbable issues.
- `research` — if scoping on-device sysupdate execution details.
- `caveman` — token saver for any further structural navigation.
