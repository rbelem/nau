# Git submodule fetching + pinning on inputs

A github input may declare `submodules` — materializing the declared submodule trees at the parent's pinned revision, with every submodule's own commit recorded in the lockfile so a submodule-consuming build is reproducible without trusting `.gitmodules` drift.

## Status

Accepted (2026-09-14). Issue #43. Extends ADR-0008 (package inputs) and the Phase 16 input lockfile; it deliberately does NOT extend the ADR-0020 `sources` model (tarball build inputs), which stays hash-of-artifact only.

## Context

Some targets need submodule trees fetched as part of the parent source clone — trees that a declared `sources` entry cannot express, because the submodule revs live in the parent's gitlinks, not in any downloadable artifact. `git clone` alone leaves gitlinks as empty directories; a build that expects them materialized fails. Without pinning, the materialized content depends on whatever the submodule HEAD is at clone time.

## Decision

Extend the `inputs` machinery (where git fetching and revision pinning already live) with a per-input `submodules` declaration:

```lua
inputs = {
  myinput = {
    url = "github:owner/repo/branch",
    submodules = true,                          -- every .gitmodules entry
    -- or: submodules = { "libfoo", "vendor/bar" },
  },
}
```

1. **Fetch = clone parent at pin + init declared submodules.** On the pinned path, after the parent clone lands at its revision, each declared submodule is fetched (`git submodule update --init`, shallow with a full-fetch fallback) at the gitlink commit that revision records. Submodule content is therefore a pure function of the parent pin — a submodule "rev change" is impossible without a new parent rev, so parent pinning already carries the invalidation; the per-submodule pins make it legible and verifiable.
2. **Declaration names `.gitmodules` entries** by section name or path. An unmatched name is a hard error naming the submodule and listing what exists; a declaring input with no `.gitmodules` at the pinned rev is a hard error. `path:` inputs reject the declaration outright.
3. **Lockfile shape**: the input's `InputLockEntry` gains an optional `submodules` map, `.gitmodules` name → `{ path, revision, sha256 }` — the materialization path, the resolved submodule commit, and the content hash of the submodule tree at lock time. The entry is omitted for inputs without submodules, so pre-#43 lockfiles load unchanged.
4. **Verification at every resolution** (cache hit or offline rebuild), before the parent tree hash so failures name the submodule: a declaration with no recorded pin is drift (`run 'shuttle lock'`); a pinned submodule missing from the tree or with a moved content hash is a named changed-since-lock error. The parent's whole-tree hash still covers everything as a backstop. Offline rebuilds work entirely from the pin + cache — no re-resolution.
5. **Out of scope**: tarball/registry sources (ADR-0020 model, unchanged), per-submodule `ref` overrides (a submodule is pinned by its parent's gitlink; a `ref` override would break that invariant), and the unpinned branch-head cache path (no lock record exists there to verify against).

## Consequences

**Positive**: submodule-dependent sources materialize reproducibly; per-submodule identity is visible in `shuttle.lock` (parent rev + submodule name → submodule rev); tamper and drift fail closed with named errors; old lockfiles keep loading.

**Negative**: an input declaring submodules pulls more content than the parent tree alone; the parent tree hash now depends on submodule content, so changing the `submodules` declaration requires a re-lock (record-once, like every other pin).

**Neutral**: `protocol.file.allow=always` is set for the submodule fetch step — git blocks `file://` submodule URLs by default (CVE-2022-39253), but this fetch boundary already trusts the cloned repo (its build script runs next), and the file transport is what makes mirrored/vendored fixture layouts possible.
