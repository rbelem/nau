//! Image-manifest IR and image declarations — the pure, serializable
//! vocabulary (#317; the seam ADR-0051's `nau-core`/`nau-image` crate split
//! will follow).
//!
//! This home is deliberately dependency-light: it holds the versioned eval
//! manifest ([`ImageManifest`]) and the declarative image vocabulary
//! ([`ImageDeclaration`] and companions), plus their serialization. The code
//! that evaluates and constructs manifests stays on the build side —
//! [`crate::manifest`] for the IR construction, [`crate::image`] for the
//! declaration's Lua parsing. Re-exports in both keep every pre-existing
//! path compiling.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serializer;
use serde::{Deserialize, Serialize};

use crate::snap_types::SnapRef;

/// Manifest schema version. Bump on any breaking field change; consumers
/// gate on this value.
pub const MANIFEST_VERSION: u32 = 1;

// ── IR types ──

/// The versioned image manifest IR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageManifest {
    pub manifest_version: u32,

    /// Declared package inputs joined with their Phase 16 lockfile pins.
    pub inputs: BTreeMap<String, ManifestInput>,

    /// The definition's `snap()` outputs, keyed by outputs-table name.
    pub outputs: BTreeMap<String, SnapOutputEntry>,

    /// The definition's `image()` declarations, keyed by images-table name.
    pub images: BTreeMap<String, ImageEntry>,

    /// Detached signatures over this manifest (synthesis §6.4 — signing
    /// protects exactly this artifact; ADR-0011 step (d)). Entries are
    /// keyed by key id (first 16 hex chars of the public key) and come in
    /// two shapes: the legacy plain base64 signature over the canonical
    /// bytes, or the issue-#56 attested envelope
    /// `{"signature": …, "provenance": …}` whose signature covers the
    /// canonical bytes PLUS the provenance bytes — the SLSA-lite claims
    /// ride under the signature, never in the canonical body, so
    /// byte-identical eval is preserved. The map is excluded from the
    /// canonical bytes, so entries never cover themselves.
    pub signatures: BTreeMap<String, serde_json::Value>,
}

/// One declared package input with its lockfile pin state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestInput {
    /// Declared URL (e.g. "github:owner/repo/branch", "path:vendor").
    pub url: String,

    /// Pinned git commit SHA (github inputs with a lockfile entry).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,

    /// Pinned content hash of the input tree (github inputs with a
    /// lockfile entry).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,

    /// True for `path:` inputs — resolved from the filesystem, unlocked.
    #[serde(default, skip_serializing_if = "is_false")]
    pub local: bool,
}

/// One `snap()` output of the definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapOutputEntry {
    /// The snap's declared name (may differ from the outputs-table key).
    pub name: String,

    /// Declared version. Absent for adopt-info outputs whose version only
    /// materializes at build time — never the "0" placeholder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// True when the version is adopt-info'd (unknown until build).
    #[serde(default, skip_serializing_if = "is_false")]
    pub version_adopted: bool,

    /// Architectures the output builds for.
    pub archs: Vec<String>,

    /// Phase 22a canonical build closure key (`v4:<sha256>`): the content
    /// address the binary cache stores this output under. The most precise
    /// addressing available before Phase 22b's file-level store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closure_key: Option<String>,

    /// Build artifact state — always unbuilt from eval.
    pub artifact: Artifact,
}

/// One `image()` declaration with resolved contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageEntry {
    pub name: String,
    pub version: String,

    /// Target architecture the contents were resolved for.
    pub arch: String,

    /// Snap channel the resolution context used.
    pub channel: String,

    /// Declared bootloader type, when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootloader: Option<String>,

    /// Declared disk layout label ("gpt"/"mbr"), when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_label: Option<String>,

    /// Resolved image contents in fixed role order: base, kernel, gadget,
    /// then extras sorted by name.
    pub snaps: Vec<ManifestSnap>,

    /// Declared kernel params (ADR-0011 step (a)) — threaded through eval
    /// instead of dropped; image builds compose them into the UKI cmdline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_params: Option<Vec<String>>,

    /// Declared kernel modules to force-load at boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_modules: Option<Vec<String>>,

    /// Declared modprobe.d configuration written into the image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_modprobe_config: Option<String>,

    /// Kernel version of the packed payload (lib/modules/<ver>) — build
    /// fact, populated by `nau image`, never by eval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_version: Option<String>,

    /// Composed UKI cmdline (declared params + root= + verity trailer)
    /// — build fact, populated by `nau image`, never by eval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,

    /// UKI filename on the ESP (EFI/Linux/<uki>) — build fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uki: Option<String>,

    /// ESP GPT PARTUUID — build fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub esp_partuuid: Option<String>,

    /// dm-verity root hash embedded in the UKI cmdline (ADR-0011 step (c))
    /// — build fact, populated by `nau image`, never by eval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roothash: Option<String>,

    /// A/B slot updates enabled (`disk.ab = true`, ADR-0011 step (d)).
    /// Omitted when false so single-slot manifests stay byte-identical.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disk_ab: bool,

    /// Declared update source base URL (ADR-0011 step (d)) — the base the
    /// emitted sysupdate transfer files fetch versioned payloads from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_source: Option<String>,

    /// Image artifact state — always unbuilt from eval.
    pub artifact: Artifact,
}

/// One resolved snap in an image's contents: fully pinned by construction
/// (unresolvable pins fail closed before a manifest exists).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestSnap {
    pub role: SnapRole,
    pub name: String,
    pub revision: u32,

    /// sha3-384 hex content digest — the snap-level content address.
    pub sha3_384: String,

    /// Where the pin was found.
    pub pin_source: PinSource,
}

/// The role a snap plays in an image's contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapRole {
    Base,
    Kernel,
    Gadget,
    Extra,
}

/// Where a resolved pin came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PinSource {
    /// Fully pinned in the definition's `pin()`.
    Definition,
    /// Resolved from the `snaps` section of `nau.lock`.
    Lockfile,
    /// Resolved from a pre-resolved package-index pin for the arch.
    Index,
}

/// Build artifact state. Eval never builds; it only ever reports
/// [`ArtifactState::Unbuilt`]. The `Built` state exists for host-side
/// records only (`nau push --record` / `pull --expect`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactState {
    Unbuilt,
    Built,
}

/// One built blob in a [`Built`][ArtifactState::Built] artifact: the
/// OCI content address plus transport metadata. Never emitted by eval —
/// eval manifests stay byte-identical (`blobs` serializes to nothing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuiltBlob {
    /// `sha256:<64 lowercase hex>` content digest (the OCI blob digest).
    pub digest: String,
    pub size: u64,
    pub media_type: String,
}

/// An artifact reference in the IR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub state: ArtifactState,
    /// Per-blob content addresses — populated only in host-side
    /// built-manifest records; eval emits `unbuilt` with an empty list,
    /// which serializes to nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blobs: Vec<BuiltBlob>,
}

impl Artifact {
    /// The single artifact state eval can truthfully report.
    pub fn unbuilt() -> Self {
        Artifact {
            state: ArtifactState::Unbuilt,
            blobs: Vec::new(),
        }
    }
}

/// `skip_serializing_if` helper: omit `local = false` / `version_adopted = false`.
fn is_false(b: &bool) -> bool {
    !*b
}

// ── Additional types ──

/// Kernel snap reference plus kernel configuration.
#[derive(Debug, Clone)]
pub struct KernelEntry {
    pub snap: SnapRef,
    pub params: Vec<String>,
    pub modules: Vec<String>,
    pub modprobe_config: Option<String>,
    /// ADR-0019 escape hatch: an author-pinned store channel (e.g.
    /// "latest/stable") carried on the kernel pin entry
    /// (`pin("pc-kernel", { channel = "…" })`). When set, resolution uses
    /// the channel verbatim — no base-track derivation — and the
    /// declared-base check is skipped; the override is logged at build
    /// time.
    pub channel: Option<String>,
}

/// Bootloader configuration for disk images.
#[derive(Debug, Clone)]
pub struct BootloaderConfig {
    /// Two implemented backends: `"systemd-boot"` (UEFI targets — UKI on
    /// the ESP, issue #71) and `"piboot"` (Raspberry Pi firmware chain —
    /// boot-assets + Pi-spelled kernel payload, issue #87, ADR-0025
    /// amendment). Any other declared value fails declaration validation
    /// instead of being accepted and silently ignored.
    pub type_: String,
    pub timeout: u32,
}

/// One host file staged verbatim into the image rootfs (`files =` in the
/// image declaration, #80).
///
/// `dest` must be an absolute path inside the guest tree
/// (`/usr/bin/systemd-sysupdate`); `source` is resolved against the
/// directory of the declaring `--file` lua (absolute paths pass through).
/// Staged BEFORE the rootfs is hashed, so dm-verity covers them.
#[derive(Debug, Clone)]
pub struct StagedFile {
    pub source: PathBuf,
    pub dest: String,
}

/// Full disk layout definition.
#[derive(Debug, Clone)]
pub struct DiskLayout {
    pub label: String, // "gpt" or "mbr"
    pub partitions: Vec<Partition>,
    pub swap: Option<SwapConfig>,
    /// A/B slot updates (ADR-0011 step (d)). Opt-in, default off —
    /// kernel-free and single-slot images build byte-identically without
    /// it. When set, the root (and its dm-verity hash partition, for kernel
    /// images) is cloned into a same-size slot B after slot A, sysupdate
    /// transfer files are emitted when `update_source` is declared, and GPT
    /// type GUIDs + PARTLABELs are applied so systemd-sysupdate can match
    /// the slots. Requires a "gpt" label.
    pub ab: bool,
}

/// One partition in the disk layout.
#[derive(Debug, Clone)]
pub struct Partition {
    pub name: String,
    pub size: String,         // e.g. "512M", "0" for remaining
    pub fs: String,           // e.g. "vfat", "btrfs", "ext4"
    pub mount: String,        // mount point
    pub options: Vec<String>, // mount options
    /// UC gadget role (issue #32): `"system-seed"`, `"system-boot"`,
    /// `"system-data"` (or `"system-save"`). Only honored when the image
    /// base is a UC coreN base; the role selects the UC PARTLABEL
    /// (`ubuntu-seed` / `ubuntu-boot` / `ubuntu-data`) and the populate
    /// routing (seed / boot / data). Empty for non-UC partitions — the
    /// simplified path is untouched.
    pub role: String,
}

/// Swap configuration.
#[derive(Debug, Clone)]
pub struct SwapConfig {
    pub size: String, // e.g. "8G"
}

// ── Image declaration ──

/// A declarative image composed from multiple snaps.
///
/// Created by the `image()` DSL function:
/// ```lua
/// image {
///     name = "my-system",
///     version = "1.0.0",
///     base = pin("core22"),
///     kernel = pin("pc-kernel"),
///     gadget = pin("pi-gadget"),
///     snaps = { pin("lxd") },
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ImageDeclaration {
    pub name: String,
    pub version: String,
    pub base: SnapRef,
    pub kernel: Option<KernelEntry>,
    pub gadget: Option<SnapRef>,
    /// ADR-0019 escape hatch for the gadget entry — an author-pinned store
    /// channel (`gadget = pin("pc", { channel = "…" })`). Semantics match
    /// [`KernelEntry::channel`]: verbatim channel, no track derivation, no
    /// declared-base check, logged override.
    pub gadget_channel: Option<String>,
    pub extra_snaps: Vec<SnapRef>,
    pub bootloader: Option<BootloaderConfig>,
    pub disk: Option<DiskLayout>,
    pub sysctl: Vec<String>,
    /// Extra host files staged verbatim into the rootfs (#80). The
    /// update flow needs system tooling the base rootfs does not ship
    /// (systemd-sysupdate), so an image can declare `files =` entries;
    /// they land in the hashed tree before dm-verity formats it.
    pub files: Vec<StagedFile>,
    /// Base URL of the systemd-sysupdate payload source (ADR-0011 step
    /// (d)); transfer files are emitted only when set — a local-source
    /// transfer would carry no verification, and unverifiable update
    /// config is never emitted silently.
    pub update_source: Option<String>,
    /// Override for the generated `nau-boot-health.service`'s
    /// `ExecStart` (issue #78). Unset keeps [`boot::BOOT_HEALTH_EXEC`],
    /// so existing images emit a byte-identical unit. Set it to e.g.
    /// `/bin/true` to satisfy the try-boot health gate on demand, or
    /// `/bin/false` to fail it deliberately (ADR-0024 §3 fixtures).
    /// Rust-level only for now — the per-image DSL surface is a follow-up.
    pub boot_health_exec: Option<String>,
}

/// Serialize as the name string (for `meta/snap.yaml`).
impl Serialize for ImageDeclaration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.name.serialize(serializer)
    }
}

impl ImageDeclaration {
    /// Resolve every [`Self::files`] entry's `source` against the directory
    /// of the declaring lua file (called from [`crate::lua::`
    /// `evaluate_images_file`], the one place that knows the `--file`
    /// path). Absolute sources pass through untouched.
    pub fn resolve_files_against(&mut self, base_dir: &Path) {
        for file in &mut self.files {
            if file.source.is_relative() {
                file.source = base_dir.join(&file.source);
            }
        }
    }

    /// Collect all snap references (base + kernel + gadget + extras).
    pub fn all_snaps(&self) -> Vec<&SnapRef> {
        let mut snaps: Vec<&SnapRef> = vec![&self.base];
        if let Some(ref k) = self.kernel {
            snaps.push(&k.snap);
        }
        if let Some(ref g) = self.gadget {
            snaps.push(g);
        }
        for s in &self.extra_snaps {
            snaps.push(s);
        }
        snaps
    }
}

// ── Serialization ──

impl ImageManifest {
    /// Deterministic JSON: pretty-printed, sorted keys (BTreeMap order),
    /// trailing newline. No timestamps, no absolute host paths — the same
    /// definition + lockfile always produce byte-identical bytes.
    pub fn to_json(&self) -> miette::Result<String> {
        let mut json = serde_json::to_string_pretty(self)
            .map_err(|e| miette::miette!("failed to serialize manifest: {e}"))?;
        json.push('\n');
        Ok(json)
    }

    /// Write the manifest atomically: serialize to a temp file in the
    /// target's directory, then rename over the target (lockfile-style).
    /// A crash or failure mid-write leaves any previous manifest intact —
    /// readers never see a half-written file, and a failed eval never
    /// leaves a manifest behind that looks like success.
    pub fn write_atomic(&self, path: &Path) -> miette::Result<()> {
        let content = self.to_json()?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let tmp = parent.join(format!(
            ".{}.tmp-{}",
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("image.json"),
            std::process::id()
        ));
        let cleanup = |tmp: &Path| {
            let _ = std::fs::remove_file(tmp);
        };
        if let Err(e) = std::fs::write(&tmp, &content) {
            cleanup(&tmp);
            return Err(miette::miette!("failed to write {}: {}", tmp.display(), e));
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            cleanup(&tmp);
            return Err(miette::miette!(
                "failed to finalize {}: {}",
                path.display(),
                e
            ));
        }
        Ok(())
    }
}
