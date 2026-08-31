# Fedora Silverblue Runtime Model — Technical Brief

> **Purpose:** Dense reference on how a Silverblue system works at runtime: ostree storage, deployments, atomic upgrade/rollback, boot integration, composefs, rpm-ostree layering, bootc.
> **Companion:** `fedora-silverblue-build-brief.md` (build pipeline).
> **Sources:** ostreedev.github.io/ostree (introduction + man pages), github.com/coreos/rpm-ostree, github.com/bootc-dev/bootc, github.com/composefs/composefs.
> **Date:** August 2026. Covers ostree 2024.x/2025.x, bootc 1.x, composefs on F41+.

---

## 1. ostree: git for OS binaries

Content-addressed object store under `/ostree/repo` (physically `/sysroot/ostree/repo`). Four object types, all SHA-256 addressed at `objects/<first-2-hex>/<rest>.*`:

| Type | Content |
|------|---------|
| `file` | File content (compressed) + xattrs/mode/uid/gid |
| `dirtree` | Ordered child list: checksum + name per entry |
| `dirmeta` | Directory metadata only |
| `commit` | Root dirtree pointer + parent + subject/timestamp/GPG sig |

Checkouts are **hardlink farms** into the object store — deploying a second OS version costs disk only for changed files. Refs map names to commits: `fedora/42/x86_64/silverblue` → SHA. Static deltas: server pre-computes binary diffs between commit pairs; client applies automatically during pull.

## 2. Deployments

```
/ostree/deploy/<stateroot>/
  deploy/
    <commit>.0/        # serial 0; usr/ = hardlink checkout, etc/ = own copy
    <commit>.1/        # serial 1 (e.g. after rpm-ostree layering)
    ...
  var/                 # real shared /var, symlinked from every deployment
  origin               # refspec the system tracks
```

- **Booted** deployment: running `/usr` (marked `*` in `ostree admin status`).
- **Staged** deployment: written to disk, finalized at shutdown by `ostree-finalize-staged.service`; becomes default on next boot.

Commands: `ostree admin status|upgrade|deploy|rollback|cleanup`.

Boot-failure safety: previous deployment stays intact and bootable until explicitly cleaned; rollback = reorder boot entries, not re-download.

## 3. Filesystem contract

| Path | Behavior |
|------|----------|
| `/usr` | Read-only. Bind-mount remounted ro; composefs overlay on F41+ (see §7). Fully replaced per deployment. |
| `/etc` | Per-deployment copy. On upgrade: **3-way merge** (old `/usr/etc` default, new `/usr/etc` default, user's `/etc`). Local changes preserved; upstream changes applied; conflicts flagged (`ostree admin config-diff`). |
| `/var` | Shared real directory across all deployments of a stateroot. ostree never touches it; apps/OS own migration. |
| `/home` | Persistent, separate from deployments. |
| RPM db | `/usr/share/rpm` — inside immutable `/usr`, per-deployment. |

`/sysroot` = real underlying root FS. Boot flow: bootloader → initrd mounts real root at `/sysroot` → `ostree-prepare-root` builds `/` from the deployment dir → pivot-root.

## 4. Bootloader integration

One BLS entry per deployment under `/boot/loader.{0,1}/entries/` (`title`, `version`, `linux`, `initrd`, kernel `options` containing `ostree=/ostree/deploy/<os>/deploy/<hash>`). `/boot/loader` symlink flips atomically between `loader.0`/`loader.1`. `ostree-system-generator` translates the active entry into early-boot mount units. GRUB/systemd-boot list all entries — selecting an older one boots the older deployment; `ostree admin rollback` just reorders defaults.

## 5. Update flow (end to end)

```
1. CHECK   bootc upgrade | rpm-ostree upgrade | ostree admin upgrade
2. PULL    new commit objects, static delta if available
3. STAGE   hardlink checkout of new /usr + /etc 3-way merge + new BLS entry
           + atomic /boot/loader symlink flip
4. REBOOT  initrd reads BLS entry → ostree-prepare-root → pivot into new deployment
5. DEFAULT new deployment booted; old one retained
6. GC      ostree admin cleanup / prune removes old deployments + unreachable objects
```

Pure-image updates are pre-computed server-side → fast. Client-side layering (§6) repeats dependency resolution locally → slow.

## 6. rpm-ostree: hybrid image/package

`rpm-ostree install <pkg>`: libdnf SAT-resolves deps → downloads RPMs → layers onto current commit → **new local ostree commit** → new deployment → reboot. Also: `override replace/reset` (base package replacement), `status` (shows layers + overrides).

Consequences: each layered change recomposes the tree client-side; upgrades must re-apply layers. RPM db moved into `/usr/share/rpm` per deployment. Upstream status: supported, but development focus shifted to bootc + dnf5.

## 7. bootc + composefs

**bootc**: OCI container image = bootable system. `bootc upgrade` pulls image via containers/image stack into host ostree store (layers imported as ostree objects); nothing runs in a container — systemd is PID 1, `/usr` comes from the image. Registry-auth from standard podman config. `bootc status` shows current + staged.

**composefs** (default on Silverblue F41+, CoreOS earlier): metadata-only EROFS image (dirs, modes, `trusted.overlay.redirect` xattrs) + content-addressed backing store, mounted via overlayfs → `/usr` is a single verifiable digest. With fs-verity per backing file: full kernel-level trust chain from cmdline → image digest → every file. Perf: ~720 MB/s random read without fs-verity (faster than ext4's ~670), ~300 MB/s with fs-verity enabled.

## 8. Key paths

| Path | Purpose |
|------|---------|
| `/ostree/repo` | object store |
| `/ostree/repo/refs/` | ref → commit mappings |
| `/ostree/deploy/<stateroot>/deploy/<hash>.<serial>` | deployment roots |
| `/ostree/deploy/<stateroot>/var` | shared persistent /var |
| `/boot/loader.0`, `/boot/loader.1` + `/boot/loader` symlink | BLS entries, atomic switch |
| `/sysroot` | real underlying root FS |
| `/usr/share/rpm` | per-deployment RPM database |

## 9. Relevance to shoot

- **Content-addressed store + hardlink checkouts**: cheap A/B; the model that makes atomic replace safe. Directly comparable to shoot needing local store + transactional switch for packed snaps.
- **Deployment = immutable artifact, state split** (`/usr` vs `/etc` merge vs `/var` persistent): clean contract worth copying in how shoot separates package payload from user state.
- **Rollback = keep old artifact + flip pointer**: no undo logic, just don't delete. Cheapest correctness mechanism in the design.
- **Layering slowness**: all client-side mutation paths (rpm-ostree install) are slower than baked images — validates shoot's build-time-declaration model.

## Sources

- ostree introduction: https://ostreedev.github.io/ostree/introduction/
- ostree admin deploy: https://ostreedev.github.io/ostree/man/ostree-admin-deploy.html
- rpm-ostree docs: https://github.com/coreos/rpm-ostree/blob/main/docs/index.md
- bootc: https://github.com/bootc-dev/bootc / https://bootc.dev/bootc/
- composefs: https://github.com/composefs/composefs/blob/main/README.md
- composefs integration tracking: https://github.com/ostreedev/ostree/issues/2867
- Fedora Atomic Desktops: https://fedoraproject.org/atomic-desktops/silverblue
