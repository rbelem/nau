//! Ubuntu Core seed / role-model support (issue #32).
//!
//! Ubuntu Core (UC20+, via `snap-initramfs-mounts` and `snap-bootstrap`)
//! boots a gadget/seed image model, not the simplified self-contained
//! verity-root layout. On first boot `snap-bootstrap` reads the **model
//! assertion** and the **seed** off `ubuntu-seed`, and detects the boot
//! **mode** from `ubuntu-boot/device/modeenv`. Without those the initrd
//! stops upstream of switch-root at:
//!
//! ```text
//! snap-bootstrap: cannot detect mode nor recovery system to use
//! ```
//!
//! This module emits the three pieces that close that gap:
//!
//! 1. The **model assertion** — a UC `type: model` assertion in the
//!    documented UC shape, describing the base + gadget + kernel + extras,
//!    self-signed with the project's Ed25519 keychain ([`crate::sign`]).
//! 2. The **seed** — `seed.yaml` plus the recovery-system directory
//!    (`systems/<label>/`) carrying the model assertion, staged on
//!    `ubuntu-seed`.
//! 3. The **modeenv** — `ubuntu-boot/device/modeenv` with
//!    `mode=run` and the seed/gadget/kernel references snap-bootstrap's
//!    mode detection consumes.
//!
//! Like [`crate::sign`] (optional post-pass over canonical bytes), this is
//! deliberately a separate module from the painting/staging in
//! [`crate::image`] — the seed emit is pure IR construction over the
//! resolved image, callable independently and unit-testable without running
//! `mkfs`/`parted`.
//!
//! # Model-assertion signing
//!
//! snap assertions are openpgp-signed in the store, but this project has no
//! store keypair; the model assertion here is **self-signed with the
//! project's Ed25519 keychain** (the same keys as the boot manifest,
//! ADR-0011/0012). The body is the canonical UC assertion text and the
//! signature is the `base64` Ed25519 signature over that body, attached in
//! the standard snap-assertion shape (`body` + blank line + a
//! `sign-key-sha3-384:` line + blank line + base64 signature). Verification
//! is the project's own [`crate::sign`] roundtrip — `sign` then
//! `verify_keychain`.

use std::fmt::Write as _;
use std::path::Path;

use miette::{IntoDiagnostic, WrapErr};

use crate::image::{base_track, ImageDeclaration};
use crate::sign::{self, KeyPair};
use crate::store::ResolvedSnap;

// ── UC partition role names ──
//
// These become GPT PARTLABELs (via the `name`→PARTLABEL wiring in
// [`crate::image`]) and are matched by the UC initrd's
// `90-ubuntu-core-partitions.rules` as `ID_PART_ENTRY_NAME`.

/// `ubuntu-seed` — carries the seed (seed.yaml + signed model assertion +
/// recovery system).
pub const UC_SEED_PART: &str = "ubuntu-seed";
/// `ubuntu-boot` — carries `device/modeenv` and the boot assets.
pub const UC_BOOT_PART: &str = "ubuntu-boot";
/// `ubuntu-data` — the system-data writable.
pub const UC_DATA_PART: &str = "ubuntu-data";

// ── Gadget role names (gadget.yaml `structure[].role`) ──
//
// The image DSL partition `role` opt maps to these; they select the UC
// PARTLABEL and the populate routing in the image builder.

pub const ROLE_SEED: &str = "system-seed";
pub const ROLE_BOOT: &str = "system-boot";
pub const ROLE_DATA: &str = "system-data";
pub const ROLE_SAVE: &str = "system-save";

/// The UC PARTLABEL a gadget role maps to (gadget.yaml role → partition
/// name). Returns `None` for a non-UC role (or an unimplemented one).
pub fn role_partlabel(role: &str) -> Option<&'static str> {
    match role {
        ROLE_SEED => Some(UC_SEED_PART),
        ROLE_BOOT => Some(UC_BOOT_PART),
        ROLE_DATA => Some(UC_DATA_PART),
        _ => None,
    }
}

/// True when the image base is an Ubuntu Core base (a `coreN` snap that
/// selects the UC gadget/seed model). Non-numeric bases (`core`, custom
/// bases) are NOT UC and leave the simplified image path untouched.
pub fn is_uc_base(base_name: &str) -> bool {
    base_track(base_name).is_some()
}

/// `series` for a UC base (`core26` → `"26"`). Mirrors
/// [`crate::image::base_track`] but returns an owned `String` for the
/// assertion body.
pub fn uc_series(base_name: &str) -> Option<String> {
    base_track(base_name).map(ToOwned::to_owned)
}

/// One snap entry in the model assertion `snaps:` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelSnap {
    pub name: String,
    pub snap_type: String, // "base" | "gadget" | "kernel" | "snapd" | "app"
    pub default_channel: String,
}

/// A UC `type: model` assertion: the header/body fields in the documented
/// UC model-assertion shape, plus the signing key id (the shuttle key's
/// first 16 hex chars, used as the `sign-key-sha3-384` field).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelAssertion {
    pub series: String,
    pub brand_id: String,
    pub model: String,
    pub architecture: String,
    pub base: String,
    pub grade: String,
    pub storage_safety: String,
    pub snaps: Vec<ModelSnap>,
    pub sign_key_sha3_384: String,
}

impl ModelAssertion {
    /// Build the model assertion for an image, deriving the snaps list from
    /// the image declaration + resolved snaps. `brand_id` defaults to the
    /// image name (a per-image brand); `model` to the image name too —
    /// shuttle has no store brand, so the self-signed model identifies the
    /// brand with the image itself.
    pub fn from_image(image: &ImageDeclaration, arch: &str) -> miette::Result<Self> {
        let series = uc_series(&image.base.name).ok_or_else(|| {
            miette::miette!(
                "cannot build a UC model assertion for base '{}' — not a coreN base",
                image.base.name
            )
        })?;
        let mut snaps = Vec::new();
        snaps.push(ModelSnap {
            name: image.base.name.clone(),
            snap_type: "base".into(),
            default_channel: "latest/stable".into(),
        });
        // snapd is the essential daemon snap on UC20+; the base's rootfs is
        // provided by the `coreN` snap, and snapd ships as its own snap.
        snaps.push(ModelSnap {
            name: "snapd".into(),
            snap_type: "snapd".into(),
            default_channel: "latest/stable".into(),
        });
        if let Some(ref k) = image.kernel {
            snaps.push(ModelSnap {
                name: k.snap.name.clone(),
                snap_type: "kernel".into(),
                default_channel: latest_or_derived(&image.base.name, &k.channel),
            });
        }
        if let Some(ref g) = image.gadget {
            snaps.push(ModelSnap {
                name: g.name.clone(),
                snap_type: "gadget".into(),
                default_channel: latest_or_derived(&image.base.name, &image.gadget_channel),
            });
        }
        for s in &image.extra_snaps {
            snaps.push(ModelSnap {
                name: s.name.clone(),
                snap_type: "app".into(),
                default_channel: derive_track_channel(base_track(&image.base.name)),
            });
        }
        Ok(Self {
            series,
            brand_id: image.name.clone(),
            model: image.name.clone(),
            architecture: arch.to_string(),
            base: image.base.name.clone(),
            grade: "signed".into(),
            storage_safety: "prefer-unencrypted".into(),
            snaps,
            sign_key_sha3_384: String::new(),
        })
    }

    /// The canonical assertion **body** (everything before the signature) in
    /// the UC model-assertion text shape. Deterministic — same header order,
    /// same snap order — so the signature is stable across builds of the
    /// same image.
    pub fn body(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "type: model");
        let _ = writeln!(s, "authority-id: {}", self.brand_id);
        let _ = writeln!(s, "series: \"{}\"", self.series);
        let _ = writeln!(s, "brand-id: {}", self.brand_id);
        let _ = writeln!(s, "model: {}", self.model);
        let _ = writeln!(s, "architecture: {}", self.architecture);
        let _ = writeln!(s, "base: {}", self.base);
        let _ = writeln!(s, "grade: {}", self.grade);
        let _ = writeln!(s, "storage-safety: {}", self.storage_safety);
        let _ = writeln!(s, "sign-key-sha3-384: {}", self.sign_key_sha3_384);
        let _ = writeln!(s);
        let _ = writeln!(s, "snaps:");
        for snap in &self.snaps {
            let _ = writeln!(s, "  - name: {}", snap.name);
            let _ = writeln!(s, "    type: {}", snap.snap_type);
            let _ = writeln!(s, "    default-channel: {}", snap.default_channel);
        }
        s
    }

    /// Sign the model assertion with the shuttle Ed25519 keypair and return
    /// the full assertion text: body + blank separator + snap-assertion
    /// signature block. The key id is stamped into the body's
    /// `sign-key-sha3-384` field before signing (a signature never covers
    /// the key that makes it, but the body must be stable first).
    pub fn to_assert(&self, kp: &KeyPair) -> String {
        let mut body = self.clone();
        body.sign_key_sha3_384 = kp.key_id();
        let body = body.body();
        // The key id is the sign-key-sha3-384 value — no re-derivation here;
        // the body is already canonical with the key id stamped.
        let bytes = body.as_bytes();
        let sig = sign::sign_bytes(bytes, kp);
        let mut out = body;
        let _ = writeln!(out);
        let _ = writeln!(out, "sign-key-sha3-384: {}", kp.key_id());
        let _ = writeln!(out);
        out.push_str(&sig);
        out.push('\n');
        out
    }
}

/// Recover the effective default channel for a model snap entry: an
/// author-pinned channel wins, otherwise the base's track
/// (`core26` → `26/stable`), ADR-0019 semantics.
fn latest_or_derived(base_name: &str, explicit: &Option<String>) -> String {
    if let Some(ref c) = explicit {
        return c.clone();
    }
    derive_track_channel(base_track(base_name))
}

/// Emit a `seed.yaml` for a recovery system.
///
/// `seed.yaml` is the index of the snaps in the seed and their metadata,
/// consumed by snap-bootstrap when it assembles the recovery system. Each
/// entry names a snap and its channel; the revision is the resolved
/// revision when known.
pub fn seed_yaml(image: &ImageDeclaration, resolved: &[ResolvedSnap]) -> String {
    let base_track = base_track(&image.base.name);
    let mut s = String::new();
    let _ = writeln!(s, "snaps:");
    let mut snap = |name: &str, channel: String, rev: Option<u32>| {
        let rev = rev.unwrap_or(0);
        let _ = writeln!(s, "  - name: {name}");
        let _ = writeln!(s, "    channel: {channel}");
        let _ = writeln!(s, "    revision: {rev}");
    };
    let rev_of = |name: &str| resolved.iter().find(|r| r.name == name).map(|r| r.revision);
    snap(
        &image.base.name,
        "latest/stable".into(),
        rev_of(&image.base.name),
    );
    snap("snapd", "latest/stable".into(), rev_of("snapd"));
    if let Some(ref k) = image.kernel {
        let channel = k
            .channel
            .clone()
            .unwrap_or_else(|| derive_track_channel(base_track));
        snap(&k.snap.name, channel, rev_of(&k.snap.name));
    }
    if let Some(ref g) = image.gadget {
        let channel = image
            .gadget_channel
            .clone()
            .unwrap_or_else(|| derive_track_channel(base_track));
        snap(&g.name, channel, rev_of(&g.name));
    }
    for s in &image.extra_snaps {
        snap(&s.name, derive_track_channel(base_track), rev_of(&s.name));
    }
    s
}

fn derive_track_channel(track: Option<&str>) -> String {
    match track {
        Some(t) => format!("{t}/stable"),
        None => "latest/stable".into(),
    }
}

/// The `ubuntu-boot/device/modeenv` content. `mode=run` plus the seed,
/// kernel, gadget and recovery-system references snap-bootstrap's mode
/// detection reads to avoid `cannot detect mode nor recovery system to use`.
///
/// `recovery_label` is the system label under `ubuntu-seed/systems/<label>/`
/// that carries this image's model + seed. `kernel_name`/`gadget_name` are
/// snap names (`pc-kernel`, `pc`) formatted to the `_<rev>` seed filename
/// convention; `base_name` likewise.
pub fn modeenv(
    recovery_label: &str,
    kernel_name: Option<&str>,
    base_name: &str,
    gadget_name: Option<&str>,
) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "mode=run");
    let _ = writeln!(s, "ubuntu_boot=ubuntu-boot");
    let _ = writeln!(s, "ubuntu_seed=ubuntu-seed");
    let _ = writeln!(s, "ubuntu_save=ubuntu-save");
    let _ = writeln!(s, "kernel_status=none");
    if let Some(k) = kernel_name {
        let _ = writeln!(s, "snap_kernel={k}_1.snap");
    }
    let _ = writeln!(s, "snap_core={base_name}_1.snap");
    if let Some(g) = gadget_name {
        let _ = writeln!(s, "snap_gadget={g}_1.snap");
    }
    let _ = writeln!(s, "snap_recovery_system={recovery_label}");
    let _ = writeln!(s, "bootloader=systemd-boot");
    s
}

/// The recovery-system label for an image: a build-date-based label so each
/// build gets a fresh recovery system (remodel/date-stamped convention).
pub fn recovery_label(image: &ImageDeclaration) -> String {
    // Date-stamped label: the UC convention is YYYYMMDD; a second build on
    // the same day must not collide, so the image version disambiguates.
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let date = ts_to_date(ts);
    format!("{date}_{}", image.version.replace('.', "_"))
}

fn ts_to_date(secs: u64) -> String {
    // Minimal civil-date conversion (days since epoch → YYYYMMDD). Avoids a
    // chrono dependency for a derived-serial ID.
    let days = secs / 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    format!("{y:04}{m:02}{d:02}")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    // Howard Hinnant's days-from-civil inverse algorithm.
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    ((if m <= 2 { y + 1 } else { y }), m, d)
}

/// Write the full recovery-system seed tree into a staging directory.
///
/// Layout (consumed by snap-bootstrap):
///
/// ```text
/// <seed_stage>/
///   seed.yaml
///   systems/<label>/
///     model
///     seed.yaml
/// ```
///
/// The top-level `seed.yaml` is snap-bootstrap's recovery-system index; the
/// per-system `model` is the signed model assertion for that recovery
/// system.
pub fn emit_seed(
    seed_stage: &Path,
    image: &ImageDeclaration,
    resolved: &[ResolvedSnap],
    model: &ModelAssertion,
    kp: &KeyPair,
) -> miette::Result<()> {
    let label = recovery_label(image);
    let sys_dir = seed_stage.join("systems").join(&label);
    std::fs::create_dir_all(&sys_dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating seed system dir {}", sys_dir.display()))?;
    std::fs::write(seed_stage.join("seed.yaml"), seed_yaml(image, resolved))
        .into_diagnostic()
        .wrap_err("writing seed.yaml")?;
    std::fs::write(sys_dir.join("seed.yaml"), seed_yaml(image, resolved))
        .into_diagnostic()
        .wrap_err("writing systems/<label>/seed.yaml")?;
    std::fs::write(sys_dir.join("model"), model.to_assert(kp))
        .into_diagnostic()
        .wrap_err("writing systems/<label>/model")?;
    Ok(())
}

/// Write `ubuntu-boot/device/modeenv` into a staging directory.
pub fn emit_modeenv(
    boot_stage: &Path,
    recovery_label: &str,
    kernel_name: Option<&str>,
    base_name: &str,
    gadget_name: Option<&str>,
) -> miette::Result<()> {
    let device_dir = boot_stage.join("device");
    std::fs::create_dir_all(&device_dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", device_dir.display()))?;
    std::fs::write(
        device_dir.join("modeenv"),
        modeenv(recovery_label, kernel_name, base_name, gadget_name),
    )
    .into_diagnostic()
    .wrap_err("writing device/modeenv")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::base_track;

    fn sample_image() -> ImageDeclaration {
        // Reuse the trivial builders available in image.rs tests is not
        // possible (module-private); construct a minimal deployment directly.
        crate::image::test_support::sample_image()
    }

    #[test]
    fn is_uc_base_detects_core_n() {
        assert!(is_uc_base("core22"));
        assert!(is_uc_base("core26"));
        assert!(!is_uc_base("core"));
        assert!(!is_uc_base("my-base"));
    }

    #[test]
    fn role_partlabel_maps_uc_roles() {
        assert_eq!(role_partlabel(ROLE_SEED), Some(UC_SEED_PART));
        assert_eq!(role_partlabel(ROLE_BOOT), Some(UC_BOOT_PART));
        assert_eq!(role_partlabel(ROLE_DATA), Some(UC_DATA_PART));
        assert_eq!(role_partlabel("system-save"), None);
        assert_eq!(role_partlabel("other"), None);
    }

    #[test]
    fn model_assertion_body_has_uc_shape() {
        let image = sample_image();
        let model = ModelAssertion::from_image(&image, "amd64").unwrap();
        assert_eq!(model.series, "24");
        assert_eq!(model.base, "core24");
        assert_eq!(model.architecture, "amd64");
        // Kernel + gadget + base in snaps.
        let names: Vec<&str> = model.snaps.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"core24"));
        assert!(names.contains(&"pc-kernel"));
        assert!(names.contains(&"pc"));
        let body = model.body();
        assert!(body.starts_with("type: model\n"));
        assert!(body.contains("base: core24\n"));
        assert!(body.contains("  - name: pc-kernel\n"));
    }

    #[test]
    fn signed_model_assertion_roundtrips_with_keychain() {
        use std::collections::BTreeMap;
        let home = tempfile::tempdir().unwrap();
        let kp = sign::create_secret_key(home.path()).unwrap();
        let image = sample_image();
        let model = ModelAssertion::from_image(&image, "amd64").unwrap();
        let assert = model.to_assert(&kp);
        // The canonical input is the body with the key id stamped, exactly
        // as `to_assert` signed it.
        let mut stamped = model.clone();
        stamped.sign_key_sha3_384 = kp.key_id();
        let body = stamped.body();
        // The assertion embeds the signature block after the body.
        assert!(assert.starts_with(body.as_str()));
        assert!(assert.contains(&format!("\n\nsign-key-sha3-384: {}\n\n", kp.key_id())));
        // The signature is the trailing base64 line.
        let sig_line = assert.lines().last().unwrap_or("").trim();
        let mut map = BTreeMap::new();
        map.insert(kp.key_id(), serde_json::Value::String(sig_line.to_string()));
        // Verify with the project's public key (sign::verify).
        sign::verify(body.as_bytes(), &map, &kp.public_hex()).unwrap();
    }

    #[test]
    fn modeenv_references_run_mode_and_seed_gadget_core() {
        let text = modeenv("20260909_1_0_0", Some("pc-kernel"), "core26", Some("pc"));
        assert!(text.starts_with("mode=run\n"));
        assert!(text.contains("snap_core=core26_1.snap"));
        assert!(text.contains("snap_kernel=pc-kernel_1.snap"));
        assert!(text.contains("snap_gadget=pc_1.snap"));
        assert!(text.contains("snap_recovery_system=20260909_1_0_0"));
        assert!(text.contains("bootloader=systemd-boot"));
    }

    #[test]
    fn seed_yaml_lists_all_snaps() {
        let image = sample_image();
        let resolved = vec![
            ResolvedSnap {
                name: "core24".into(),
                revision: 42,
                sha3_384: "aabb".into(),
                download_url: "http://example".into(),
            },
            ResolvedSnap {
                name: "pc-kernel".into(),
                revision: 7,
                sha3_384: "ccdd".into(),
                download_url: "http://example".into(),
            },
        ];
        let yaml = seed_yaml(&image, &resolved);
        assert!(yaml.contains("  - name: core24"));
        assert!(yaml.contains("    revision: 42"));
        assert!(yaml.contains("    channel: 24/stable"));
    }

    #[test]
    fn emit_seed_writes_system_model_and_seed_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let kp = sign::create_secret_key(home.path()).unwrap();
        let image = sample_image();
        let model = ModelAssertion::from_image(&image, "amd64").unwrap();
        emit_seed(dir.path(), &image, &[], &model, &kp).unwrap();
        assert!(dir.path().join("seed.yaml").exists());
        let sys = dir.path().join("systems");
        assert!(sys.is_dir());
        // Exactly one recovery-system label.
        let labels: Vec<_> = std::fs::read_dir(&sys)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.is_dir())
            .collect();
        assert_eq!(labels.len(), 1);
        assert!(labels[0].join("model").exists());
        assert!(labels[0].join("seed.yaml").exists());
    }
}
