# Ubuntu Core Runtime Architecture — Technical Brief

> **Date**: August 2026. Covers UC16 through UC26 (current: UC24 stable, UC26 released May 2026).
> **Sources**: Canonical Ubuntu Core docs (documentation.ubuntu.com/core), snapcraft.io/docs, snapd GitHub (snapcore/snapd).

---

## Terminology Table

| Term | Definition |
|------|-----------|
| **Base snap** | A snap containing the root filesystem for userspace. Mirrors an Ubuntu LTS release (e.g. `core24` = Ubuntu 24.04). Serves as `/` for the initramfs-to-userspace transition. All app snaps run inside the base snap's namespace. |
| **Kernel snap** | A snap containing the Linux kernel image, modules, initramfs, and optionally firmware/device trees. Selected by the model assertion. Can be refreshed in-place but **cannot be swapped** (different name/ID) without remodeling. |
| **Gadget snap** | A snap shipping board-specific boot assets (bootloader binaries, device trees, grub/u-boot configs), the `meta/gadget.yaml` partition layout specification, default snap configurations, and lifecycle hooks (`install-device`, etc.). Signed by the device brand or OEM. |
| **snapd snap** | The snap daemon itself, packaged as a snap since UC18. Manages all snap lifecycle: install, refresh, removal, confinement, assertions, recovery systems. Exposes a REST API over a Unix socket. Separately upgradeable (unlike UC16 where snapd was bundled in the `core` snap). |
| **App snap** | Any application snap — the "workload" snap. Confined (strict/classic/devmode). Runs under the base snap's rootfs, accesses system resources only through declared interfaces. |
| **Assertion** | A signed, JSON-like text document that binds identity or authorization claims to cryptographic keys. Types: `model`, `serial`, `snap-declaration`, `snap-revision`, `account-key`, `validation`, `repair`. Verified against a chain of trusted keys. |
| **Seed** | The data set on `ubuntu-seed` partition containing snap squashfs files, model assertion, and all required snap/assertion files that define a recovery system. Acts as the "golden image" for installation, recovery, and reinstall. |
| **Snap set** | A set of named snaps declared in the model assertion's `snaps:` list. Defines the complete system composition: which snaps, which types, which channels, which components, which boot modes. |
| **Recovery system** | A complete bootable system stored in `ubuntu-seed/systems/<label>/`. Contains model + assertions + snap pool sufficient to boot into install/recover/factory-reset modes. Each system label is typically date-stamped. |
| **Model assertion** | The "birth certificate" of an Ubuntu Core device. Defines brand-id, model name, architecture, base snap, kernel, gadget, required app snaps, grade, storage-safety, store, validation-sets. Drives both image creation (via `ubuntu-image`) and runtime verification. |
| **Serial assertion** | Binds a specific device instance to its model via a unique serial number. Created during registration (factory or field). Index: `<brand-id, model, serial>`. Links the device's key to its identity. |
| **Remodel** | The process of applying a new model assertion to a live device. Can add/remove snaps, change channels, upgrade base (e.g. core22 → core24), change gadget or kernel. Never downgrades the base snap. |
| **Components** | Optional parts of a snap (e.g. NVIDIA driver KO, debug symbols). Declared in model assertion alongside the parent snap. GA in UC26. Can be required or optional. |

---

## 1. Snap-Based OS Composition

### The OS *is* a collection of squashfs snaps

Ubuntu Core has **no traditional package manager** (no apt, no dpkg at runtime). The entire OS is composed of squashfs images mounted read-only:

```
/var/lib/snapd/snaps/<snap>_<rev>.snap   ← actual squashfs on disk (compressed)
/snap/<snapname>/<revision>/              ← mount point (read-only loop mount)
/snap/<snapname>/current → <revision>     ← symlink to active revision
/snap/bin/<snapname>[.<app>]              ← app command wrappers
```

**Key paths**:
- `/snap/` — mount root for all installed snaps
- `/var/lib/snapd/seed/` — seed data: initial snap images + assertions for recovery systems
- `/var/lib/snapd/snaps/` — installed (and refreshed) snap squashfs files
- `/var/lib/snapd/state.json` — snapd's persistent state
- `/usr/lib/snapd/` — snapd daemon binaries (from the `snapd` snap)
- `/snap/bin/` — symlinks to app commands (added to `$PATH`)

### How the root filesystem is assembled

During boot, `snap-bootstrap` (in initramfs) assembles the root filesystem:

1. **ubuntu-seed** mounted → access to recovery system snaps + assertions
2. **ubuntu-data** mounted (or decrypted) → writable system/user data
3. **Base snap** mounted from seed/data → becomes `/` for userspace
4. **Kernel snap** mounted → provides additional modules, firmware, DTBs beyond what's in the initramfs
5. **Gadget snap** boot assets already used by bootloader
6. All **app snaps** mounted under `/snap/` inside the base snap's namespace

The base snap (e.g. `core24`) contains the minimal Ubuntu 24.04 userspace: libc, libstdc++, python (pre-UC26), systemd units, and essential system files. It **is** the rootfs — there is no separate `/usr` tree from a traditional install.

### Snap types in the system stack

| Snap type | UC16 | UC18+ | Role |
|-----------|------|-------|------|
| `core` (base) | Bundled snapd | Does not include snapd | Root filesystem for userspace |
| `snapd` | Part of `core` snap | Separate, independently upgradeable snap | System daemon, REST API, snap lifecycle |
| `kernel` | Separate | Separate | Linux kernel + modules + initramfs |
| `gadget` | Separate | Separate | Boot assets + partition layout + hooks |
| `app` | Separate | Separate | Workload/application snaps |
| `system` (network-manager, bluez, etc.) | Separate | Separate | Essential system services |

> **UC16→UC18 key change**: snapd was extracted from the `core` snap into its own `snapd` snap, enabling independent upgrade of the daemon without changing the base.

> **UC26 change**: Python interpreter removed from core base snap (core26+). Apps needing Python must bundle it. Cloud-init still available on a separate track.

---

## 2. Boot Chain

### UC20/UC22/UC24/UC26 Boot Flow (UEFI x86)

```
┌──────────────────────────────────────────────────────────────┐
│  UEFI firmware                                               │
│  ↓ Secure Boot: verifies shim → grub.efi signature          │
│  ↓ TPM measurements: firmware, bootloader, kernel cmd line   │
├──────────────────────────────────────────────────────────────┤
│  GRUB (from ubuntu-seed or ubuntu-boot)                      │
│  ↓ Reads grubenv from ubuntu-seed (snapd-managed)           │
│  ↓ Loads kernel.efi from ubuntu-boot                        │
│  ↓ Kernel command line includes:                             │
│     snapd_recovery_mode=<mode>                               │
│     snapd_recovery_system=<label>  (for recovery modes)     │
├──────────────────────────────────────────────────────────────┤
│  Kernel + initramfs (from ubuntu-boot, unpacked from kernel  │
│  snap during install/refresh)                                │
│  ↓ TPM unseals FDE keys (if encrypted)                      │
│  ↓ Runs snap-bootstrap (UC20+)                              │
├──────────────────────────────────────────────────────────────┤
│  snap-bootstrap (initramfs executable)                       │
│  ↓ Mounts ubuntu-seed, ubuntu-boot, ubuntu-data, ubuntu-save│
│  ↓ Selects base snap → mounts as / (userspace root)         │
│  ↓ Selects kernel snap → mounts for extra modules            │
│  ↓ Handles A/B try-boot logic (see §3)                      │
│  ↓ Pivot root into base snap                                │
├──────────────────────────────────────────────────────────────┤
│  systemd (inside base snap)                                  │
│  ↓ snapd.service starts                                     │
│  ↓ snapd verifies assertions, seeds snaps, starts app snaps │
└──────────────────────────────────────────────────────────────┘
```

### UC16/UC18 Boot Flow (simpler, pre-snap-bootstrap)

UC16 used a simpler approach:
- `snapd` (bundled in `core` snap on UC16, separate snap on UC18) ran as a systemd service
- No `snap-bootstrap` in initramfs — the initramfs was minimal
- No built-in FDE, no recovery system partitions
- Boot selection was simpler, without the A/B try mechanism
- `ubuntu-seed` didn't exist; system was a single-partition layout
- Recovery was not built-in (no `ubuntu-save`, no recovery modes)

### UC20+ introduces:
- **`snap-bootstrap`** in initramfs — the central boot orchestrator
- **Four-partition layout** (seed/boot/save/data)
- **Recovery systems** on `ubuntu-seed`
- **Full disk encryption** via TPM 2.0
- **A/B try-boot** mechanism for atomic upgrades
- **Recovery modes**: install, run, recover, factory-reset
- **Model measurement** in TPM chain of trust

### Boot modes and `snapd_recovery_mode`

The kernel command line carries a `snapd_recovery_mode` variable set by the bootloader:

| Mode | What happens |
|------|-------------|
| `run` | Normal boot — system runs from ubuntu-data, base snap as rootfs |
| `install` | First-boot or reinstall — wipes ubuntu-data, creates all partitions, installs run system |
| `recover` | Recovery — boots from seed recovery system in tmpfs, data untouched, allows SSH/local login |
| `factory-reset` | Erases ubuntu-data, restores factory state, preserves ubuntu-save |

### Bootloader types

| Bootloader | Marker file | Boot partition | Environment storage |
|------------|------------|----------------|---------------------|
| GRUB | `grub.conf` in gadget snap | `ubuntu-boot` (ext4/vfat) | `ubuntu-seed` grubenv + `ubuntu-boot` |
| U-Boot | `uboot.conf` in gadget snap | `ubuntu-boot` | `ubuntu-seed` or `system-boot-state` partition |
| Little Kernel (LK) | — | `system-boot-image` partition | `system-boot-select` partition (label: `snapbootsel`) |

---

## 3. Transactional Updates & Rollback

### How a snap refresh works

1. **snapd** checks for updates 4×/day (configurable)
2. New snap revision downloaded as squashfs to `/var/lib/snapd/snaps/<name>_<newrev>.snap`
3. For **app snaps**: mount new revision at `/snap/<name>/<newrev>/`, update symlinks, restart services. Old revision kept (default: retain 2 old revisions).
4. For **essential snaps** (base, kernel, gadget): requires reboot

### A/B Try-Boot Mechanism (UC20+)

This is the core of atomic upgrades and rollback:

```
┌─────────────────────────────────────────────────────────┐
│  Current system (booted from slot A)                    │
│  snap_mode=active                                       │
│  snap_kernel=<current-kernel-snap>_                    │
├─────────────────────────────────────────────────────────┤
│  snapd downloads new kernel snap + new base snap        │
│  snapd installs them to the "other" slot                │
│  snapd sets:                                            │
│    snap_mode=try                                        │
│    snap_try_kernel=<new-kernel-snap>_                  │
│    snap_try_base=<new-base-snap>                       │
│  snapd triggers reboot                                 │
├─────────────────────────────────────────────────────────┤
│  REBOOT → snap-bootstrap reads snap_mode=try            │
│  snap-bootstrap boots with snap_try_kernel and          │
│  snap_try_base instead of the active ones               │
│  ↓                                                      │
│  If boot succeeds → snapd confirms:                     │
│    snap_mode=active                                     │
│    snap_kernel=<new-kernel-snap>_                      │
│    Old slot becomes available for next update           │
│  ↓                                                      │
│  If boot FAILS (kernel panic, timeout, etc.):           │
│    Bootloader reverts to previous known-good slot       │
│    snap_mode returns to active with old kernel/base     │
│    Device boots normally on previous revision           │
└─────────────────────────────────────────────────────────┘
```

**Bootloader environment variables** (GRUB):
- `snap_mode` — `active` | `try` | `recover`
- `snap_kernel` — currently active kernel snap filename
- `snap_try_kernel` — kernel snap to try on next boot
- `snap_core` / `snap_try_base` — current/try base snap

**For U-Boot**: stored in `boot.sel` file on `ubuntu-boot` (or `system-boot-state` partition).

### What happens on failed boot

1. Bootloader detects failed boot (timeout or explicit flag)
2. Reverts to previous kernel/base snap
3. Sets `snap_mode=active` back to original values
4. System boots on previous known-good revision
5. snapd logs the failure; device remains on old revision
6. Operator can investigate and retry

### Gadget snap updates

Gadget refresh is special:
- Boot assets (bootloader binaries, device trees) can be updated via `update.edition` mechanism
- `update.preserve` list protects specific files from being overwritten
- If boot assets change → reboot required
- Partition layout **cannot be changed** by gadget refresh (repartitioning requires reinstall)
- Gadget updates are constrained: no new partitions between boot/save/data, must maintain partition order

### Rollback for app snaps

Simpler than essential snaps:
- Old revisions are retained (default: 2 revisions)
- `snap revert <snap>` switches to previous revision
- No reboot needed
- Data is preserved across reverts

---

## 4. Security Model

### Confinement

**All app snaps on Ubuntu Core run in `strict` confinement** by default. This is enforced by:

| Kernel feature | What it does |
|---------------|-------------|
| **AppArmor** | Mandatory access control — filesystem, network, capability, dbus policies per snap |
| **seccomp** | System call filtering — blocks dangerous syscalls per snap profile |
| **namespaces** | Mount, PID, network, IPC, user namespaces isolate each snap |
| **cgroups** | Resource limits (CPU, memory, I/O) per snap or quota group |
| **udev tagging** | Device access control — snaps only see devices their interfaces allow |

**Interfaces** are the mechanism snaps use to request resources:
- `plug` (consumer) requests access; `slot` (provider) grants it
- Examples: `network`, `hardware-observe`, `gpio`, `camera`, `audio-playback`
- Auto-connected by default for many interfaces; some require manual connection
- `gadget.yaml` can declare `connections:` for first-boot auto-connection

### What is NOT confined

| Component | Confinement status | Notes |
|-----------|-------------------|-------|
| **snapd daemon** | Runs outside confinement (as root) | Manages all other snaps; must have system-level access |
| **kernel snap** | Not confined (it IS the kernel) | Loaded by bootloader, runs before snapd |
| **gadget snap** | Boot assets used pre-confinement | Bootloader runs gadget content before snapd starts |
| **base snap** | Not confined (it IS the rootfs) | Mounts as `/` — confinement happens inside it |

### Full Disk Encryption (UC20+)

**Requirements**: UEFI Secure Boot + TPM 2.0 + IOMMU

**How it works**:
1. At image creation, `ubuntu-image` sets up LUKS encryption for `ubuntu-data` and `ubuntu-save`
2. Encryption key is sealed to TPM — bound to:
   - Bootloader hash
   - Kernel hash  
   - Kernel command line
   - Base snap hash
3. At boot, Secure Boot verifies the chain → TPM unseals key → initramfs decrypts partitions
4. TPM measurements form a chain of trust from firmware through to snap model

**FDE + Secure Boot interaction** (UC24):

| grade | storage-safety | Hardware FDE capable | Result |
|-------|---------------|---------------------|--------|
| `secured` | (any) | Yes | Encrypted + SecureBoot enforced |
| `secured` | (any) | No | **Error** — cannot boot |
| `signed` | unset | Yes | Encrypted (default on capable hardware) |
| `signed` | `prefer-unencrypted` | Yes | Unencrypted |
| `signed` | `prefer-encrypted` | Yes | Encrypted |
| `signed` | `prefer-encrypted` | No | Unencrypted (falls back) |
| `dangerous` | `prefer-encrypted` | Yes | Encrypted |

**Recovery keys**: `snap recovery --show-keys` displays a numeric recovery key for manual entry when TPM-sealed keys are unavailable (TPM reset, firmware change, etc.).

**Non-UEFI platforms** (Raspberry Pi, ARM): FDE is board-specific. UC20/UC22 provide a hook interface (`uc20-fde-hooks`) for custom integrity verification.

---

## 5. Model Assertions

### Anatomy of a Model Assertion

```yaml
type:                  model                    # Always "model"
series:                "24"                     # Ubuntu series (16, 18, 20, 22, 24, 26)
authority-id:          <brand-account-id>       # Who signed this
brand-id:              <brand-account-id>       # Device brand
model:                 my-device-amd64          # Model name (unique per brand)
architecture:          amd64                    # Debian arch name
base:                  core24                   # Base snap (rootfs)
grade:                 signed                   # dangerous | signed | secured
storage-safety:        prefer-encrypted         # (optional) encrypted|prefer-encrypted|prefer-unencrypted
timestamp:             2024-06-04T00:00:00+00:00
sign-key-sha3-384:     <key-fingerprint>

snaps:
  - name: pc
    type: gadget
    default-channel: 24/stable
    id: <gadget-snap-id>

  - name: pc-kernel
    type: kernel
    default-channel: 24/stable
    id: <kernel-snap-id>

  - name: core24
    type: base
    default-channel: latest/stable
    id: <base-snap-id>

  - name: snapd
    type: snapd
    default-channel: latest/stable
    id: <snapd-snap-id>

  - name: my-app
    type: app
    default-channel: latest/stable
    id: <app-snap-id>
    modes: [run]           # Which boot modes include this snap
    presence: required     # required | optional
    components:            # (UC24+ optional)
      my-driver-ko:
        presence: optional
        modes: [run]
```

### Key Model Assertion Fields

| Field | Purpose |
|-------|---------|
| `type: model` | Identifies this as a model assertion |
| `series` | Ubuntu release series. `"rolling"` bridges dev between stable series. |
| `brand-id` | Account ID of the device brand. Must be registered in the Snap Store. |
| `model` | Device model name. Combined with brand-id and series forms the unique index. |
| `architecture` | Debian arch name. Mandatory for non-classic models. |
| `base` | The base snap that defines the rootfs runtime (e.g. `core24`). |
| `grade` | Security constraints: `dangerous` (dev), `signed` (production default), `secured` (FDE+SecureBoot mandatory). |
| `storage-safety` | Controls encryption: `prefer-encrypted` (default on capable hardware), `prefer-unencrypted`, `encrypted` (mandatory). |
| `snaps` | List of all snaps in the system image. Each entry specifies name, type, channel, ID, modes, presence, components. |
| `store` | (optional) Brand store ID. Device defaults to main Ubuntu store if omitted. |
| `serial-authority` | (optional) Who can issue serial assertions. `["generic"]` = Snap Store. |
| `system-user-authority` | (optional) Accounts allowed to issue system-user assertions. |
| `validation-sets` | (optional, snapd 2.60+) Snap sets that must be installed together at specific revisions. |

### How a device knows its identity

```
Image Build Time:
  model assertion → ubuntu-image → seed partition (model + assertions + snap squashfs files)

First Boot:
  1. snap-bootstrap reads model from seed
  2. Verifies model signature against trusted keys
  3. Snapd registers device → obtains serial assertion from Serial Vault or store
  4. Serial assertion binds: <brand-id, model, serial> + device public key

Runtime:
  snap model → shows current model assertion
  snap known serial → shows serial assertion
  Device key signs all local assertions and API requests
```

### Remodeling

Remodel applies a **new model assertion** (incremented revision, same brand key) to a live device:

```bash
sudo snap remodel new-model.assert
```

What remodel can change:
- Add/remove app snaps
- Change snap channels
- Change kernel snap (same or different name/ID)
- Change gadget snap (must keep same bootloader type)
- **Cannot downgrade** base snap (core24 → core20 is invalid)

What remodel cannot change:
- Partition layout (no repartitioning)
- Brand (must stay same brand-id)
- Bootloader type (must stay GRUB or U-Boot)

### Serial Assertions

The **serial assertion** binds a physical device to its model:
- Created during registration (factory provisioning or field registration)
- Signed by the device's unique key pair
- Contains: brand-id, model, serial (unique UUID), device-key, gadget-id, kernel-id
- Can be issued by: Brand Store, Serial Vault, or `["generic"]` (Snap Store auto-generation)
- Stored on `ubuntu-save` partition (survives data wipes)

---

## 6. Snapd Internals Worth Knowing

### Seed Data (`/var/lib/snapd/seed/`)

The seed directory is the **immutable reference** for what the system should contain:

```
/var/lib/snapd/seed/
├── assertions/
│   ├── model-<brand>-<model>.assert       # Model assertion
│   ├── account-<brand>.assert             # Brand account key
│   ├── snap-declaration-<snap-id>.assert  # Per-snap declaration
│   └── ...
├──snaps/
│   ├── <snap>_<rev>.snap                  # Squashfs images (shared pool)
│   └── ...
├── systems/
│   ├── 20240604/                          # Recovery system (date-labeled)
│   │   ├── model                          # Model assertion for this system
│   │   ├── assertions/                    # All assertions for this system
│   │   ├── kernel                         # Kernel image/boot info
│   │   └── ...
│   └── 20241215/                          # Another recovery system
└── seed.yaml                              # Index of snaps and their metadata
```

**First-boot seeding**:
1. snap-bootstrap mounts seed partition
2. Reads `seed.yaml` and recovery system model/assertions
3. Verifies all snap files against their `snap-revision` assertions (hash check)
4. Copies verified snaps to `ubuntu-data` for run mode
5. Installs and activates all snaps declared in the model for `run` mode
6. Device transitions from install mode → run mode

### Refresh Control

| Mechanism | How it works |
|-----------|-------------|
| **Automatic refresh** | snapd checks 4×/day for updates to all tracked snaps |
| **`refresh.hold`** | System option to hold all snaps from refreshing for a duration |
| **`refresh.retain`** | Number of old snap revisions to keep (default: 3 for system snaps) |
| **Validation sets** | Assertion-based: only specific snap+revision combos are allowed |
| **Gating snaps** | A "gating" snap publishes validation assertions controlling "gated" snap revisions |
| **Channel tracking** | Each snap tracks a channel (e.g. `24/stable`). Changing channel changes what revisions are eligible |
| **`refresh.assume`** | Snapd option to assume certain refresh conditions (advanced) |

### `gadget.yaml` at Runtime

The `gadget.yaml` is **not just for image creation** — it governs runtime behavior:

- **Partition roles** define what each partition is for (system-seed, system-boot, system-data, system-save)
- **Bootloader selection** (`grub` or `u-boot`) determines boot environment storage location
- **Boot asset updates**: `update.edition` + `update.preserve` control which files in the gadget snap can be updated on refresh
- **Default configurations**: `defaults:` section applies snap configurations on first install only (not on gadget refresh or remodel)
- **Interface connections**: `connections:` section auto-connects interfaces on first boot only
- **Kernel cmdline**: `kernel-cmdline.allow` defines the allow-list for dynamic kernel parameters
- **Static cmdline**: `kernel-cmdline.append` / `kernel-cmdline.remove` for permanent kernel parameter modifications
- **Volume assignments**: Maps volume names to physical devices for multi-device gadgets (e.g. Pi 4 vs Pi 5)

### `ubuntu-image` Tool

The `ubuntu-image` tool assembles the initial installation image:

```bash
ubuntu-image snap my-model.model \
  --snap pc=24/stable \
  --snap my-app=latest/stable \
  --output uc-image.img
```

- Reads model assertion → resolves snap IDs and channels → downloads snaps → builds seed partition
- Creates only the seed partition in the image (other partitions created at install time)
- Can add `--factory-image` flag for factory installation hints
- Can add `--validation=ignore` to skip assertion validation (development only)

---

## Gotchas for Implementers

### 1. Seed partition must fit TWO recovery systems
The `ubuntu-seed` partition must be large enough to hold two recovery systems (current + remodeling target). Too-small seed = remodel fails. The `ubuntu-image` docs have a [partition size calculator](https://documentation.ubuntu.com/core/how-to-guides/image-creation/calculate-partition-sizes/).

### 2. Gadget refresh CANNOT change partition layout
Once deployed, the partition layout is frozen. The gadget snap's `volumes:` section defines the *initial* layout. Refreshing the gadget can update boot assets but cannot add, remove, or resize partitions. Repartitioning requires full reinstall.

### 3. `ubuntu-data` must be the LAST partition
The partition order (boot → save → data) is a hard constraint. Extra partitions must go before `ubuntu-boot`, not between boot/save/data.

### 4. Classic snaps break the confinement model
Ubuntu Core is designed for strict confinement. Classic snaps (`confinement: classic`) bypass AppArmor/seccomp and are **not recommended** for production. They require `--classic` flag and manual store review approval.

### 5. Base snap upgrade = mandatory reboot
Unlike app snaps (which can refresh live), base snap and kernel snap upgrades always require a reboot. Plan maintenance windows accordingly.

### 6. The "current" symlink is the source of truth
`snap list` shows the "current" revision. Scripts should use `/snap/<name>/current` to find the active snap, not hardcode revision numbers. The symlink updates atomically on refresh.

### 7. TPM-sealed keys are fragile
If hardware changes (firmware update, TPM reset), encrypted devices need the recovery key. Always document `snap recovery --show-keys` output during provisioning. Store recovery keys securely offline.

### 8. Model assertion revision must increment on remodel
The `revision:` field in the model assertion must be higher than the previous one. Same revision = snapd rejects it. Use `date +%s` or similar monotonic counter.

### 9. Gadget defaults are ONE-SHOT
`defaults:` in gadget.yaml only apply during first install. They are **not** reapplied on gadget refresh or remodel. If you need persistent configuration, use `snap set` or the `system:` defaults key.

### 10. Kernel snap cannot be swapped, only refreshed
You can update the kernel snap revision (new kernel version), but you cannot change the kernel snap **name** (e.g. `pc-kernel` → `custom-kernel`) without remodeling. Remodeling to a different kernel requires a new model assertion.

### 11. `ubuntu-save` is mandatory on encrypted systems
If `storage-safety` is `encrypted` or `prefer-encrypted` with capable hardware, `ubuntu-save` must exist (minimum ~20MB, recommended 32MB). It stores device identity, serial assertion, and small persistent snap data (snapd 2.57+).

### 12. Snap squashfs files are in TWO locations
- `/var/lib/snapd/seed/snaps/` — original seed images (immutable, used for recovery)
- `/var/lib/snapd/snaps/` — installed/refreshed snap images
Don't manually delete from either. The seed copy is needed for recovery/reinstall.

### 13. UC26 drops Python from core base
If migrating to core26 and your snap relied on Python from the base snap, you must bundle Python via the Snapcraft Python plugin. Cloud-init is still available on a dedicated core26 track.

### 14. `snap-bootstrap` IS the boot orchestrator
On UC20+, the initramfs runs `snap-bootstrap` which handles: partition mounting, FDE decryption, base/kernel selection, A/B try logic, and pivot root. Understanding this binary is essential for debugging boot issues — it's the single most critical piece of the UC20+ boot chain.

### 15. Interfaces are the ONLY way for confined snaps to access system resources
A strictly confined snap cannot touch `/dev`, network, other processes, or any system resource without declaring the appropriate interface. No interface = no access. Plan your interface requirements in the model assertion's `connections:` section.

---

## Source URLs

- [Inside Ubuntu Core](https://documentation.ubuntu.com/core/explanation/core-elements/inside-ubuntu-core/)
- [Snaps in Ubuntu Core](https://documentation.ubuntu.com/core/explanation/core-elements/snaps-in-ubuntu-core/)
- [Storage Layout](https://documentation.ubuntu.com/core/explanation/core-elements/storage-layout/)
- [Model Assertion](https://documentation.ubuntu.com/core/reference/assertions/model/)
- [Serial Assertion](https://documentation.ubuntu.com/core/reference/assertions/serial/)
- [Gadget Snap Format](https://documentation.ubuntu.com/core/reference/gadget-snap-format/)
- [Full Disk Encryption](https://documentation.ubuntu.com/core/explanation/full-disk-encryption/)
- [Recovery Modes](https://documentation.ubuntu.com/core/explanation/recovery-modes/)
- [How Installation Works](https://documentation.ubuntu.com/core/explanation/how-installation-works/)
- [Remodeling](https://documentation.ubuntu.com/core/explanation/remodeling/)
- [Refresh Control](https://documentation.ubuntu.com/core/explanation/refresh-control/)
- [Remodel Essential Snaps](https://documentation.ubuntu.com/core/explanation/remodel-essential-snaps/)
- [UC26 Release Notes](https://documentation.ubuntu.com/core/uc26/)
- [Release Notes](https://documentation.ubuntu.com/core/reference/release-notes/)
- [Snap Confinement](https://snapcraft.io/docs/snap-confinement)
- [Snap Layouts](https://snapcraft.io/docs/snap-layouts)
- [System Snap Directory](https://snapcraft.io/docs/system-snap-directory)
- [Snapd REST API](https://snapcraft.io/docs/snapd-api)
- [Snap Structure](https://snapcraft.io/reference/development/yaml-schemas/the-snap-format/)
- [Ubuntu Core Components (UC20 discourse)](https://discourse.ubuntu.com/t/ubuntu-core-components-uc20/20777)
- [Seed snaps vs installed snaps (forum)](https://forum.snapcraft.io/t/var-lib-snapd-seed-snaps-vs-var-lib-snapd-sn/23058)
- [canonical/models (GitHub)](https://github.com/canonical/models/tree/master)
- [canonical/pc-gadget (GitHub)](https://github.com/canonical/pc-gadget)
