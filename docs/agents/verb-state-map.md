# Verb → state map

What each nau verb touches, and where live state actually lives. Built from
the 2026-10-05 review (council + jev); refresh the pool rows when #350/#351
(front + funnel lifecycle) and #356 (one-window command) land.

## The one rule first: live service state is systemd, not nau

`systemctl --user is-active/is-failed nau-pod-<pod>-<service>.service` on the
pod host is the only authority on whether a pod service is running. `nau
doctor --pod` is advisory (it checks tool readiness; it never fails on a
failed unit), and `nau pod list` prints package versions, not runtime state.

## Verb → state

| Verb family | Touches | Notes |
|---|---|---|
| `chart` (check/eval/lock/lint/audit/deps) | Read-only over chart + lockfile + store metadata | No store writes; safe mid-sync |
| `chart versions`, `chart index` | Network (git remotes, index) + no local state | ADR-0052 versions mode |
| `build snap` | `target/`, downloads cache, store (new blobs) | The gate builds the same tree — sequence against live runs (gate lock, #349) |
| `build cache` | The binary package cache | Cache entries are content-keyed (#344); a `.sha3-384` sidecar proves a payload matches itself only |
| `pod add/sync` | Pod declaration + lockfile pins, pod store, generation chain, bin farm | Sync baselines stale after recipe edits — refresh first (#311-family lesson) |
| `pod refresh` | Store resolution + generation chain | Re-resolves every pin against the Snap Store per run (`nau index resolve` underneath) |
| `pod pull` | Store + downloads cache + sidecars | Reuse gate `existing.exists() && !force_build` — a re-released same version does not propagate without deleting the stale pair (#344 residue) |
| `pod gc` | Store blobs, downloads staging (`--downloads`), generation history | Mark = union of all generation manifests; 1-hour keep rule guards concurrent installs |
| `pod list` | Nothing — prints the declaration's resolved versions | Not runtime state |
| `pod doctor --pod` | Nothing — advisory tool-readiness probe | Never fails on a failed unit |
| `pod run` | Executes inside the pod env | Hidden top-level `run` retained (#321) |
| `runtime` verbs | System state root (`/var/lib/nau`): generations, store, `active` symlink | Pod-scoped GC never touches system generations |
| `build-request submit/run` | Queue front (POST), farm queue dir, worker builds, static tree release | Identity POST only, token-gated (ADR-0052 D4+D6) |
| `pool provision/destroy` | Hetzner API, worker VMs, funnel plumbing | No front verb yet (#351); no foreign-worker guard yet (#352); funnel lifecycle ticketed (#350) |
| `pool burst/down/issue/publish/pickup` | Worker fleet + queue front | Farm-side; see nau-farm-ops skill for the ops contract |
| `image build/test/verify` | Pinned snaps → image file; QEMU boot; flashed-target check | Factory twin slots verify by demanded position |
| `trust` verbs | Keychain (`~/.config/nau`), CA material | The loader demands 64-hex keys — ssh-format keys need the #352-adjacent fix |
| `ship push/pull` | OCI artifact bundles, store blobs | Carries the manifest executable bit (fixed 4a29f84) |
| `peer serve/browse/export` | Pod store (read-only serve), LAN announcements | The front verb (#351) reuses `nau-peer` serve POST routes |
| `index resolve` | Store metadata + Snap Store network probes | Runs under every sync — the per-sync re-verification contract |
| `doctor` (default) | Nothing — full tool-readiness gate | `--pod` scopes to what pod verbs need (#97) |

## Known dark spots

- No verb reports live service state — systemd is the surface (see the rule
  above). A `nau pod status` that shells to systemctl is conceivable but
  deliberately unbuilt; revisit if the runbook's systemctl dance grows.
- `pool` has no front verb and no funnel lifecycle yet — the operator seam
  (front.py + manual funnel) is the interim contract (ADR-0055, #350, #351).
- No verb forces a rebuild of a reused payload — delete the stale
  payload+sidecar pair and re-pull until the #344 residue lands.
