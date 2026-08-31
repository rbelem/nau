# System and package format: file-level content-addressed store, generations, two-axis updates

## Status

Accepted (2026-08-31). Extends ADR-0011 (runtime ownership, native target). Naming invariant per ADR-0013 applies throughout.

## Context

The owner set two destination requirements: Nix-style **per-file dedup inside packages**, and **native runtime package installs** on deployed systems — with no users to migrate, the destination architecture should be built directly rather than staged through a package-level interim. Silverblue and Ubuntu Core both validate the resulting two-axis shape (immutable A/B system + separate app-installation axis); Nix validates the content-addressed substrate. rpm-ostree-style client-side layering remains the rejected anti-pattern (synthesis §4).

## Decision

1. **The store is file-level content-addressed from the start.** Files are addressed by hash; packages are signed manifests of file hashes plus metadata (apps, units, directives). No monolithic package artifact exists on the native path — this upgrades Phase 22b's scope from package-level artifacts to the file store, replacing the LRU binary cache.
2. **Two-axis system.** Axis 1: the immutable, dm-verity-protected base (kernel + essential system) updates atomically via systemd-sysupdate A/B (ADR-0011). Installs never mutate the base. Axis 2: the package store lives on the state partition; runtime installs add content + manifests there.
3. **Generations** pin base-version + package set + configuration as one bootable selection. `shoot rollback` boots the previous generation. GC is reachability-rooted at generations and lockfiles. Generations make retention ~free (file-level sharing).
4. **Presentation of installed trees**: composefs-class merge (metadata EROFS naming fs-verity-backed content) merged read-only at boot via systemd-sysext — pending a kernel-config audit of shipped kernels; fallback: materialize per-generation EROFS/squashfs extension images from the store (same UX, weaker sharing). composefs for the *base* image stays deferred (ADR-0011).
5. **Runtime commands (Phase 24b)**: `shuttle install/remove/upgrade/rollback` on-device — fetch, verify against signed manifests, write store, emit hardened units (same deploy path as build-time assembly, Phase 24a), activate, bump generation, GC.
6. **`.snap` is an export format only** (Snap Store compatibility, a standing project constraint); the native format is the store + manifest pair. Lockfiles and manifests are name-agnostic; digests never embed the project name (format-version numbers instead, per ADR-0013).
7. Distribution of images/store content rides ordinary OCI registries (Phase 25); chunk-level wire dedup is the escalation for metered devices, never static deltas.

## Alternatives considered

- **Package-level dedup first, file-level later** — rejected: no users means no migration debt; the interim would be throwaway.
- **Single-axis systems**: image-only with no runtime installs (Silverblue-purist) — rejected, the owner requires native installs; everything-through-the-store with no A/B base (NixOS-purist) — rejected, ADR-0011's verity + sysupdate base is already decided and simpler to secure.
- **rpm-ostree-style layering of the base** — rejected without discussion (synthesis §4).

## Consequences

**Positive**: shuttle becomes a runtime package manager — the ShuttleOS claim is literal; rollback and retention are near-free; installs transfer only new files; build-time and install-time app deployment share one code path.

**Negative**: two update axes must stay coherent (generations are the contract — both axes must be recorded in one generation manifest); the composefs/sysext presentation depends on kernel features that must be audited per shipped kernel (fallback defined); signed manifests are now security-critical on the install path too, widening the key-ceremony surface from ADR-0011.
