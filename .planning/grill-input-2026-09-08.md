# Grill input — 2026-09-08

Feed to `/grill-with-docs`. Three decision areas; each has its evidence banked. After grilling: `/to-tickets` on the parity backlog + cutover, `/implement` per ticket, `/wizard` for cutover.

## 1. Native build-deps (`build_deps`)

**Why now:** 3 pool packages blocked on it — `htop`, `tig` (need ncurses), `git-credential-manager` (needs libicu). Everything else in the parity backlog is unblocked-by-design.

**Evidence bank:** `.planning/research/native-build-deps-survey.md` — eight distro systems surveyed (Debian Build-Depends, RPM BuildRequires, Arch/Alpine makedepends, Void hostmakedepends, Gentoo BDEPEND, Nix nativeBuildInputs/strictDeps, conda build/host/run), with a synthesis: one `build_deps` field (host/target collapse under native builds), sandbox scoping as the primary enforcement (bwrap already there), post-build ELF+string leak scan as the truth (RPM find-requires + conda overlinking precedent), hard-error policy with a greppable `leaks_ok` escape hatch, build-deps recorded in the recipe hash for reproducibility.

**Grill targets:** declaration shape (Lua field vs separate store type), leak-scan failure policy (hard error vs warn — survey recommends hard), `check_deps` future axis, whether build_deps participate in lockfile pins.

## 2. devbox.d flake-tools port/keep (~48 flake dirs)

**Why now:** blocks cutover planning; the pod (gen 44, 34 packages) replaces devbox-global only if the flake-hosted tools either port to `pkgs/` or stay deliberately nix-hosted.

**Evidence bank:** `~/.local/share/shuttle/pods/default/pod.lua` (live pod), `~/Workspace/github.com/rbelem/devbox-global/devbox.d/` (the ~48 flake dirs), parity enumeration in `shoot-handoff-2026-09-04-full-stack.md`.

**Grill targets:** per-tool criteria (usage frequency, build complexity, nix-only value); whether "keep nix-hosted" is a cutover exception or a shuttle gap to ticket; ordering (port first vs cutover first).

## 3. Kernel-payload ↔ base contract (new, empirical 2026-09-08)

**Finding:** the store-snap E2E image (`core22` base + unpinned `pc-kernel`) resolved **pc-kernel rev 3720 = 4.4.0-287-generic (Xenial ESM line)** — a base-incompatible legacy kernel. Empirically its initrd has **no virtio drivers, no dm-verity module, no veritysetup**, and its snapd boot logic demands the UC18 contract (`LABEL=writable` partition + `snap_core=`/`snap_kernel=` cmdline), which a verity/systemd-boot image does not satisfy.

**Impact:** any `pin("pc-kernel")`-style image silently pairs the wrong kernel with core22; full first-boot userspace through a shuttle-built image is blocked on payload selection, not on image assembly (assembly + verity + UKI + PARTUUIDs all verified correct — see `08d07bf` and `/tmp/opencode/shuttle-e2e/serial2.log`).

**Grill targets:** base-aware kernel resolution (pin kernel revs per base? warn on kernel-version floor? per-base channel?), whether the image DSL should require an explicit kernel↔base contract field, and whether full-boot proof should use the gadget-proper chain (GRUB + writable + snap_core args) vs a modern kernel/initrd pair.

---

## Grilled outcomes (2026-09-08 session)

All three areas settled. Design records: **ADR-0018** (build_deps), **ADR-0019** (kernel↔base contract); glossary updated (`Requires` = runtime, new `Build dependency`).

- Q1 split, Q2 merged prefix, Q3 mechanism-first/toolchain-migration-follows, Q4 hard error + `leaks_ok`, Q5 recipe hash + lockfile pins → ADR-0018.
- Q6 hard kernel↔base contract (kernel snap's declared `base:` must match image base; explicit override escape) → ADR-0019.
- Q7 **(b)**: full first-boot userspace proof = its own ticket, using the gadget-proper chain (GRUB + `writable` + snap boot variables).
- Q8 group policy: libs → pool `requires` targets (not pod entries); build-blocked tools (tmux, tig, gcm, gitFull) → tickets after ADR-0018 ships; small tools (wl-clipboard, wtype, statix, luarocks, PerlTidy, nerd-fonts ×3) → port now; toolchains (go, cargo, gcc) → pod entries AND build_deps customers; nix-specific (attic-client, nix-search-cli, nix-prefetch-git) → drop at cutover. **Open per-tool at ticket time:** apps/services (chromium, valkey, podman, zenity, jdk21).
- Q9 flake tools: port-by-default for cheap (prebuilt release → meta/fetch packages) + medium tiers; expensive tier (nix-overlay builds: opencode source overlay, blesh, playwright-chromium-deps) decided per tool at cutover.
- Q10 cutover last: build_deps + parity ports first, `/wizard` retires devbox-global once the daily set is covered.

Next: `/to-tickets` from this file (blocking edges: ADR-0018 implementation blocks the build-blocked tools + toolchain migration; ADR-0019 blocks the boot-proof ticket).
