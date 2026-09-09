//! Image manifest IR — the flat, serializable, diffable result of evaluating
//! a definition (`shuttle eval`, Phase 23 of
//! `.planning/cross-distro-synthesis.md`).
//!
//! The manifest is the Nix `.drv`/toplevel + UC model-assertion analog: one
//! versioned JSON document carrying everything downstream phases consume —
//! Phase 21's module-system eval, Phase 22b's store addressing, and future
//! signing (synthesis §6.4: the manifest is the concrete artifact signing
//! would protect).
//!
//! # Schema (manifest_version 1)
//!
//! ```json
//! {
//!   "manifest_version": 1,
//!   "inputs": {
//!     "vendored": { "url": "path:vendor", "local": true },
//!     "pkgs": { "url": "github:owner/repo/main", "revision": "…40 hex…", "sha256": "…64 hex…" }
//!   },
//!   "outputs": {
//!     "app": {
//!       "name": "demo-app",
//!       "version": "1.2.3",
//!       "archs": ["amd64"],
//!       "closure_key": "v3:…64 hex…",
//!       "artifact": { "state": "unbuilt" }
//!     }
//!   },
//!   "images": {
//!     "system": {
//!       "name": "demo-system",
//!       "version": "2.0.0",
//!       "arch": "amd64",
//!       "channel": "latest/stable",
//!       "bootloader": "systemd-boot",
//!       "disk_label": "gpt",
//!       "snaps": [
//!         { "role": "base", "name": "core22", "revision": 1847, "sha3_384": "…96 hex…", "pin_source": "definition" }
//!       ],
//!       "artifact": { "state": "unbuilt" }
//!     }
//!   },
//!   "signatures": {}
//! }
//! ```
//!
//! # Determinism
//!
//! Same definition + same lockfile → byte-identical JSON. All maps are
//! `BTreeMap` (sorted keys), image snaps serialize in fixed role order
//! (base → kernel → gadget → extras sorted by name), and the document
//! carries no timestamps and no host paths.
//!
//! # Resolution is data-only
//!
//! Image snap pins resolve from, in order: the definition's `pin()` (full
//! revision + content hash), the Phase 16 lockfile (`snaps` section), or a
//! pre-resolved package-index pin for the target arch. Eval never queries
//! the Snap Store, so fully pinned projects eval offline. Anything
//! unresolvable fails closed with a named error — a partial manifest is
//! never emitted as success. Outputs and images always record
//! `artifact.state = "unbuilt"`: eval does not build, and inventing content
//! hashes is forbidden (the file-level store is Phase 22b).

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use miette::WrapErr;
use serde::{Deserialize, Serialize};

use crate::image::ImageDeclaration;
use crate::lock::LockFile;
use crate::lua::Outputs;
use crate::snap::{PackageInput, SnapMeta, SnapRef};

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

    /// Reserved for detached signatures over this manifest (synthesis §6.4 —
    /// signing later protects exactly this artifact). Always an empty object
    /// in v1; never populated by eval. Future signers attach entries keyed
    /// by key id without bumping the surrounding schema.
    pub signatures: BTreeMap<String, serde_json::Value>,
}

/// One declared package input with its lockfile pin state.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// Phase 22a canonical build closure key (`v2:<sha256>`): the content
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
    /// fact, populated by `shuttle image`, never by eval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_version: Option<String>,

    /// Composed UKI cmdline (declared params + root= + verity trailer)
    /// — build fact, populated by `shuttle image`, never by eval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,

    /// UKI filename on the ESP (EFI/Linux/<uki>) — build fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uki: Option<String>,

    /// ESP GPT PARTUUID — build fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub esp_partuuid: Option<String>,

    /// dm-verity root hash embedded in the UKI cmdline (ADR-0011 step (c))
    /// — build fact, populated by `shuttle image`, never by eval.
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
    /// Resolved from the `snaps` section of `shuttle.lock`.
    Lockfile,
    /// Resolved from a pre-resolved package-index pin for the arch.
    Index,
}

/// Build artifact state. Eval never builds; it only ever reports
/// [`ArtifactState::Unbuilt`]. The `Built` state exists for host-side
/// records only (`shuttle push --record` / `pull --expect`).
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

// ── Manifest construction ──

/// Build the manifest IR from evaluated definition data. Pure: reads the
/// lockfile and the package index, never the network.
///
/// `declared_inputs` are the definition's global `inputs`; github inputs
/// without a lockfile entry fail closed (they cannot be pinned from data).
/// `select` filters both outputs and images to the named entry when given.
pub fn build_manifest(
    outputs: &Outputs,
    images: &HashMap<String, ImageDeclaration>,
    declared_inputs: &HashMap<String, PackageInput>,
    lockfile: &LockFile,
    arch: &str,
    channel: &str,
    select: Option<&str>,
) -> miette::Result<ImageManifest> {
    let (outputs, images) = match select {
        Some(name) => {
            let out: BTreeMap<_, _> = outputs
                .iter()
                .filter(|(k, _)| k.as_str() == name)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let img: BTreeMap<_, _> = images
                .iter()
                .filter(|(k, _)| k.as_str() == name)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            if out.is_empty() && img.is_empty() {
                return Err(miette::miette!("output '{name}' not found in definition"));
            }
            (out, img)
        }
        None => (
            outputs
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            images.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        ),
    };

    let mut manifest = ImageManifest {
        manifest_version: MANIFEST_VERSION,
        inputs: manifest_inputs(declared_inputs, lockfile)?,
        outputs: BTreeMap::new(),
        images: BTreeMap::new(),
        signatures: BTreeMap::new(),
    };

    for (key, meta) in &outputs {
        // Image declarations also convert to SnapMeta (they carry name and
        // version), so a key that is a declared image is excluded from the
        // outputs section — it belongs to `images` only.
        if images.contains_key(key) {
            continue;
        }
        manifest
            .outputs
            .insert(key.clone(), snap_output_entry(meta, lockfile)?);
    }

    let index = crate::index::PackageIndex::load_or_default(Path::new(crate::index::DEFAULT_INDEX))
        .wrap_err("failed to load package index for image contents")?;
    for (key, image) in &images {
        manifest.images.insert(
            key.clone(),
            image_entry(image, lockfile, &index, arch, channel)?,
        );
    }

    Ok(manifest)
}

/// Declared inputs joined with lockfile pins. `path:` inputs are local by
/// nature; a github input with no lockfile entry has no data-derived pin
/// and fails closed — eval never resolves one over the network.
fn manifest_inputs(
    declared: &HashMap<String, PackageInput>,
    lockfile: &LockFile,
) -> miette::Result<BTreeMap<String, ManifestInput>> {
    let mut inputs = BTreeMap::new();
    for (name, input) in declared {
        let local = input.url.starts_with("path:");
        match lockfile.inputs.get(name) {
            Some(entry) => {
                inputs.insert(
                    name.clone(),
                    ManifestInput {
                        url: input.url.clone(),
                        revision: entry.revision.clone(),
                        sha256: entry.sha256.clone(),
                        local: entry.local,
                    },
                );
            }
            None if local => {
                inputs.insert(
                    name.clone(),
                    ManifestInput {
                        url: input.url.clone(),
                        revision: None,
                        sha256: None,
                        local: true,
                    },
                );
            }
            None => {
                return Err(miette::miette!(
                    "input '{name}' ({}) has no lockfile pin; eval resolves pins from \
                     data only — run 'shuttle lock' (or build once online) to record it",
                    input.url
                ));
            }
        }
    }
    Ok(inputs)
}

/// One snap output entry: identity, archs, and the canonical closure key.
fn snap_output_entry(meta: &SnapMeta, lockfile: &LockFile) -> miette::Result<SnapOutputEntry> {
    let closure_key = closure_key_for(meta, lockfile)?;
    Ok(SnapOutputEntry {
        name: meta.name.clone(),
        version: if meta.version_adopted {
            None
        } else {
            Some(meta.version.clone())
        },
        version_adopted: meta.version_adopted,
        archs: crate::snap::resolve_archs(meta, &[]),
        closure_key: Some(closure_key),
        artifact: Artifact::unbuilt(),
    })
}

/// One image entry: declared config echo plus fully-resolved contents.
fn image_entry(
    image: &ImageDeclaration,
    lockfile: &LockFile,
    index: &crate::index::PackageIndex,
    arch: &str,
    channel: &str,
) -> miette::Result<ImageEntry> {
    let mut snaps = Vec::new();
    snaps.push(resolve_snap_pin(
        &image.base,
        SnapRole::Base,
        lockfile,
        index,
        arch,
    )?);
    if let Some(kernel) = &image.kernel {
        snaps.push(resolve_snap_pin(
            &kernel.snap,
            SnapRole::Kernel,
            lockfile,
            index,
            arch,
        )?);
    }
    if let Some(gadget) = &image.gadget {
        snaps.push(resolve_snap_pin(
            gadget,
            SnapRole::Gadget,
            lockfile,
            index,
            arch,
        )?);
    }
    let mut extras: Vec<&SnapRef> = image.extra_snaps.iter().collect();
    // Lua tables are unordered — sort extras by name for a deterministic IR.
    extras.sort_by(|a, b| a.name.cmp(&b.name));
    for extra in extras {
        snaps.push(resolve_snap_pin(
            extra,
            SnapRole::Extra,
            lockfile,
            index,
            arch,
        )?);
    }

    // ADR-0011 step (a): the declared kernel config is part of the IR —
    // eval echoes what was declared. Build facts (kernel_version, cmdline,
    // uki, esp_partuuid, roothash) are only known once `shuttle image`
    // assembles the UKI, so they stay None (skipped) here.
    let kernel = image.kernel.as_ref();
    let kernel_params = kernel
        .filter(|k| !k.params.is_empty())
        .map(|k| k.params.clone());
    let kernel_modules = kernel
        .filter(|k| !k.modules.is_empty())
        .map(|k| k.modules.clone());
    let kernel_modprobe_config = kernel.and_then(|k| k.modprobe_config.clone());

    Ok(ImageEntry {
        name: image.name.clone(),
        version: image.version.clone(),
        arch: arch.to_string(),
        channel: channel.to_string(),
        bootloader: image.bootloader.as_ref().map(|b| b.type_.clone()),
        disk_label: image.disk.as_ref().map(|d| d.label.clone()),
        snaps,
        kernel_params,
        kernel_modules,
        kernel_modprobe_config,
        kernel_version: None,
        cmdline: None,
        uki: None,
        esp_partuuid: None,
        roothash: None,
        disk_ab: image.disk.as_ref().map(|d| d.ab).unwrap_or(false),
        update_source: image.update_source.clone(),
        artifact: Artifact::unbuilt(),
    })
}

/// Resolve one image snap to a full pin from data only: definition pin →
/// lockfile → package-index pre-resolved pin. Any partial pin (revision
/// without content hash) defers to the lockfile, matching the image build's
/// resolution. No data source → named fail-closed error.
fn resolve_snap_pin(
    snap_ref: &SnapRef,
    role: SnapRole,
    lockfile: &LockFile,
    index: &crate::index::PackageIndex,
    arch: &str,
) -> miette::Result<ManifestSnap> {
    // 1. Fully pinned in the definition — pure data, safe offline.
    if let (Some(revision), Some(sha3_384)) = (snap_ref.revision, &snap_ref.sha3_384) {
        return Ok(ManifestSnap {
            role,
            name: snap_ref.name.clone(),
            revision,
            sha3_384: sha3_384.clone(),
            pin_source: PinSource::Definition,
        });
    }

    // 2. Lockfile pin (any partial definition pin defers to it).
    if let Some(locked) = lockfile.lookup_snap(&snap_ref.name) {
        if let (Some(revision), Some(sha3_384)) = (locked.revision, locked.sha3_384) {
            return Ok(ManifestSnap {
                role,
                name: snap_ref.name.clone(),
                revision,
                sha3_384,
                pin_source: PinSource::Lockfile,
            });
        }
    }

    // 3. Pre-resolved package-index pin for the target arch.
    if let Some(entry) = index.find_by_name_or_alias(&snap_ref.name) {
        if let Some(pin) = entry.pins.as_ref().and_then(|p| p.get(arch)) {
            return Ok(ManifestSnap {
                role,
                name: snap_ref.name.clone(),
                revision: pin.revision,
                sha3_384: pin.sha3_384.clone(),
                pin_source: PinSource::Index,
            });
        }
    }

    // 4. Fail closed — never emit a manifest with unresolved contents.
    Err(miette::miette!(
        "image snap '{}' is unresolved: the definition pin lacks revision + content \
         hash, shuttle.lock has no entry, and the package index has no pre-resolved \
         pin for arch '{arch}'; pin it explicitly or record pins via 'shuttle image'",
        snap_ref.name
    ))
}

/// Canonical Phase 22a closure key for one output, resolved from lockfile
/// data only (mirrors the build path: lockfile pins win; unpinned deps pin
/// by declared version with `hash: None`). A requires closure that cannot
/// resolve at all is an unresolvable input — fail closed.
///
/// `build_deps` join the closure (ADR-0018 Decision 4, issue #22): a
/// changed build dependency invalidates the key, matching the build path.
fn closure_key_for(meta: &SnapMeta, lockfile: &LockFile) -> miette::Result<String> {
    let mut names: Vec<String> = if meta.requires.is_empty() {
        Vec::new()
    } else {
        crate::deps::resolve_dep_names(&meta.requires, true).map_err(|e| {
            miette::miette!(
                "output '{}': cannot resolve requires closure for its closure key: {e}",
                meta.name
            )
        })?
    };
    names.sort();
    names.dedup();
    let requires = names.iter().map(|n| requires_member(n, lockfile)).collect();
    let mut dep_names = meta.build_deps.clone();
    dep_names.sort();
    dep_names.dedup();
    let build_deps = dep_names
        .iter()
        .map(|n| requires_member(n, lockfile))
        .collect();
    Ok(crate::cache::BuildClosure::for_meta(meta, requires, build_deps).cache_key())
}

/// One requires-closure member: lockfile pin when present (pure data),
/// else declared-version pinning with `hash: None` — the exact fallback
/// the binary cache uses.
fn requires_member(name: &str, lockfile: &LockFile) -> crate::cache::RequiresMember {
    if let Some(member) = crate::cache::pinned_member(name, lockfile) {
        return member;
    }
    let pin = crate::deps::load_meta(name).ok().map(|meta| meta.version);
    crate::cache::RequiresMember {
        name: name.to_string(),
        pin,
        hash: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// Bare SnapMeta with every optional field empty (mirrors the test
    /// helpers in cache.rs).
    fn bare_meta(name: &str, version: &str) -> SnapMeta {
        SnapMeta {
            name: name.into(),
            version: version.into(),
            summary: None,
            description: None,
            license: None,
            source: None,
            sources: None,
            build: None,
            parts: None,
            architectures: Some(vec!["amd64".into()]),
            grade: "stable".into(),
            confinement: "strict".into(),
            type_: None,
            adopt_info: None,
            version_adopted: false,
            icon_source: None,
            icon: None,
            compression: None,
            environment: None,
            layout: None,
            hooks: None,
            plugs: None,
            slots: None,
            aliases: vec![],
            requires: vec![],
            build_deps: vec![],
            leaks_ok: vec![],
            target: None,
            toolchain: None,
            inputs: None,
            confined: None,
            apps: HashMap::new(),
            deps: None,
            floating: false,
            definition_dir: None,
        }
    }

    fn pinned(name: &str, revision: u32, hash: &str) -> SnapRef {
        SnapRef {
            name: name.into(),
            revision: Some(revision),
            sha3_384: Some(hash.into()),
        }
    }

    fn empty_lockfile() -> LockFile {
        LockFile {
            version: 1,
            sources: HashMap::new(),
            snaps: HashMap::new(),
            inputs: HashMap::new(),
            packages: HashMap::new(),
            build_deps: HashMap::new(),
        }
    }

    fn image_with_snaps(base: SnapRef, extras: Vec<SnapRef>) -> ImageDeclaration {
        ImageDeclaration {
            name: "test-system".into(),
            version: "1.0.0".into(),
            base,
            kernel: None,
            gadget: None,
            gadget_channel: None,
            extra_snaps: extras,
            bootloader: None,
            disk: None,
            sysctl: vec![],
            update_source: None,
        }
    }

    fn manifest_with_image(base: SnapRef, extras: Vec<SnapRef>) -> miette::Result<ImageManifest> {
        let images = HashMap::from([("system".to_string(), image_with_snaps(base, extras))]);
        let outputs = Outputs::new();
        let lockfile = empty_lockfile();
        let declared = HashMap::new();
        build_manifest(
            &outputs,
            &images,
            &declared,
            &lockfile,
            "amd64",
            "latest/stable",
            None,
        )
    }

    // ── Kernel config threading (ADR-0011 step (a)) ──

    fn kernel_image() -> ImageDeclaration {
        ImageDeclaration {
            name: "kernel-system".into(),
            version: "2.0.0".into(),
            base: pinned("core22", 1847, HASH_A),
            kernel: Some(crate::image::KernelEntry {
                snap: pinned("pc-kernel", 1241, HASH_B),
                params: vec!["quiet".into(), "console=ttyS0".into()],
                modules: vec!["btrfs".into()],
                modprobe_config: Some("options btrfs workspace_mirror=/vols\n".into()),
                channel: None,
            }),
            gadget: None,
            gadget_channel: None,
            extra_snaps: vec![],
            bootloader: None,
            disk: None,
            sysctl: vec![],
            update_source: None,
        }
    }

    fn manifest_for(images: HashMap<String, ImageDeclaration>) -> miette::Result<ImageManifest> {
        build_manifest(
            &Outputs::new(),
            &images,
            &HashMap::new(),
            &empty_lockfile(),
            "amd64",
            "latest/stable",
            None,
        )
    }

    #[test]
    fn kernel_params_modules_modprobe_survive_image_entry() {
        let m = manifest_for(HashMap::from([("system".to_string(), kernel_image())])).unwrap();
        let entry = m.images.get("system").unwrap();
        assert_eq!(
            entry.kernel_params,
            Some(vec!["quiet".to_string(), "console=ttyS0".to_string()])
        );
        assert_eq!(entry.kernel_modules, Some(vec!["btrfs".to_string()]));
        assert_eq!(
            entry.kernel_modprobe_config.as_deref(),
            Some("options btrfs workspace_mirror=/vols\n")
        );
    }

    // ── Update config echo (ADR-0011 step (d)) ──

    #[test]
    fn ab_and_update_source_echo_when_declared_and_stay_absent_otherwise() {
        // Default: both fields omitted — single-slot manifests are
        // byte-identical to pre-(d) output.
        let plain = manifest_with_image(pinned("core22", 1847, HASH_A), vec![]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&plain.to_json().unwrap()).unwrap();
        assert!(v["images"]["system"].get("disk_ab").is_none(), "{v}");
        assert!(v["images"]["system"].get("update_source").is_none(), "{v}");

        // Declared: echoed so downstream consumers see the update config.
        let mut decl = image_with_snaps(pinned("core22", 1847, HASH_A), vec![]);
        decl.update_source = Some("https://updates.example.com/os/".into());
        decl.disk = Some(crate::image::DiskLayout {
            label: "gpt".into(),
            partitions: vec![],
            swap: None,
            ab: true,
        });
        let m = manifest_for(HashMap::from([("system".to_string(), decl)])).unwrap();
        let v: serde_json::Value = serde_json::from_str(&m.to_json().unwrap()).unwrap();
        assert_eq!(v["images"]["system"]["disk_ab"], true, "{v}");
        assert_eq!(
            v["images"]["system"]["update_source"],
            "https://updates.example.com/os/"
        );

        // Roundtrip stays byte-stable with the new fields present.
        let back: ImageManifest = serde_json::from_str(&m.to_json().unwrap()).unwrap();
        assert_eq!(back.to_json().unwrap(), m.to_json().unwrap());
    }

    #[test]
    fn kernel_build_facts_stay_skipped_from_eval() {
        let m = manifest_for(HashMap::from([("system".to_string(), kernel_image())])).unwrap();
        let v: serde_json::Value = serde_json::from_str(&m.to_json().unwrap()).unwrap();
        let img = &v["images"]["system"];
        for field in [
            "kernel_version",
            "cmdline",
            "uki",
            "esp_partuuid",
            "roothash",
        ] {
            assert!(img.get(field).is_none(), "{field} must be skipped: {img}");
        }
    }

    #[test]
    fn kernel_free_image_omits_every_kernel_field() {
        let m = manifest_with_image(pinned("core22", 1847, HASH_A), vec![]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&m.to_json().unwrap()).unwrap();
        let img = &v["images"]["system"];
        for field in [
            "kernel_params",
            "kernel_modules",
            "kernel_modprobe_config",
            "kernel_version",
            "cmdline",
            "uki",
            "esp_partuuid",
            "roothash",
        ] {
            assert!(img.get(field).is_none(), "{field} must be skipped: {img}");
        }
    }

    // ── Schema ──

    #[test]
    fn manifest_version_field_is_present() {
        let m = manifest_with_image(pinned("core22", 1847, HASH_A), vec![]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&m.to_json().unwrap()).unwrap();
        assert_eq!(v["manifest_version"], 1, "schema version must be present");
    }

    #[test]
    fn signatures_is_a_reserved_empty_object() {
        let m = manifest_with_image(pinned("core22", 1847, HASH_A), vec![]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&m.to_json().unwrap()).unwrap();
        assert!(
            v.get("signatures").is_some(),
            "signatures reservation must always serialize: {v}"
        );
        assert_eq!(
            v["signatures"].as_object().map(|o| o.len()),
            Some(0),
            "v1 never populates signatures: {v}"
        );
    }

    #[test]
    fn artifacts_are_explicitly_unbuilt() {
        let m = manifest_with_image(pinned("core22", 1847, HASH_A), vec![]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&m.to_json().unwrap()).unwrap();
        assert_eq!(v["images"]["system"]["artifact"]["state"], "unbuilt");
        assert!(
            v["images"]["system"]["artifact"].get("sha256").is_none()
                && v["images"]["system"]["artifact"].get("path").is_none(),
            "no invented hashes or paths on unbuilt artifacts: {v}"
        );
    }

    #[test]
    fn built_artifact_serializes_blobs_unbuilt_stays_omitted() {
        // Built (host-side records only): state + per-blob facts round-trip.
        let built = Artifact {
            state: ArtifactState::Built,
            blobs: vec![BuiltBlob {
                digest: format!("sha256:{}", "a".repeat(64)),
                size: 7,
                media_type: "application/vnd.shuttle.snap.v1".into(),
            }],
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&built).unwrap()).unwrap();
        assert_eq!(v["state"], "built");
        assert_eq!(
            v["blobs"][0]["digest"],
            format!("sha256:{}", "a".repeat(64))
        );
        assert_eq!(v["blobs"][0]["size"], 7);
        assert_eq!(
            v["blobs"][0]["media_type"],
            "application/vnd.shuttle.snap.v1"
        );

        // Unbuilt (eval): the blobs list must NOT appear — eval manifests
        // stay byte-identical (byte-stability + sign canonical tests).
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&Artifact::unbuilt()).unwrap()).unwrap();
        assert_eq!(v["state"], "unbuilt");
        assert!(
            v.get("blobs").is_none(),
            "unbuilt artifact must not emit blobs: {v}"
        );
    }

    #[test]
    fn image_snap_carries_full_pin_and_source() {
        let m = manifest_with_image(pinned("core22", 1847, HASH_A), vec![]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&m.to_json().unwrap()).unwrap();
        let snap = &v["images"]["system"]["snaps"][0];
        assert_eq!(snap["role"], "base");
        assert_eq!(snap["name"], "core22");
        assert_eq!(snap["revision"], 1847);
        assert_eq!(snap["sha3_384"], HASH_A);
        assert_eq!(snap["pin_source"], "definition");
    }

    // ── Determinism ──

    #[test]
    fn same_inputs_produce_byte_identical_json() {
        let build = || {
            let mut extras = vec![pinned("zz-extra", 3, HASH_B), pinned("aa-extra", 2, HASH_A)];
            extras.reverse();
            let m = manifest_with_image(pinned("core22", 1847, HASH_A), extras).unwrap();
            m.to_json().unwrap()
        };
        assert_eq!(build(), build(), "same data must give byte-identical JSON");
    }

    #[test]
    fn image_snaps_use_fixed_role_order_with_sorted_extras() {
        let m = manifest_with_image(
            pinned("core22", 1847, HASH_A),
            vec![pinned("zz-extra", 3, HASH_B), pinned("aa-extra", 2, HASH_B)],
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&m.to_json().unwrap()).unwrap();
        let snaps = v["images"]["system"]["snaps"].as_array().unwrap();
        let roles: Vec<&str> = snaps.iter().map(|s| s["role"].as_str().unwrap()).collect();
        assert_eq!(
            roles,
            vec!["base", "extra", "extra"],
            "fixed role order: {v}"
        );
        assert_eq!(snaps[1]["name"], "aa-extra", "extras sorted by name: {v}");
        assert_eq!(snaps[2]["name"], "zz-extra");
    }

    #[test]
    fn no_host_paths_or_timestamps_in_output() {
        let m = manifest_with_image(pinned("core22", 1847, HASH_A), vec![]).unwrap();
        let json = m.to_json().unwrap();
        assert!(!json.contains(std::env::temp_dir().to_str().unwrap()));
        for banned in ["/home/", "/tmp/", "timestamp", "generated_at"] {
            assert!(
                !json.contains(banned),
                "manifest must not carry {banned}: {json}"
            );
        }
    }

    // ── Fail-closed resolution ──

    #[test]
    fn unpinned_image_snap_fails_closed_with_named_error() {
        let err = manifest_with_image(
            SnapRef {
                name: "core22".into(),
                revision: None,
                sha3_384: None,
            },
            vec![],
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("core22"), "error must name the snap: {msg}");
        assert!(
            msg.contains("unresolved"),
            "error must state resolution failure: {msg}"
        );
        assert!(msg.contains("amd64"), "error must name the arch: {msg}");
    }

    #[test]
    fn partial_definition_pin_without_lockfile_fails_closed() {
        // revision pinned but no content hash: unresolved without data.
        let err = manifest_with_image(
            SnapRef {
                name: "core22".into(),
                revision: Some(1847),
                sha3_384: None,
            },
            vec![],
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("unresolved"));
    }

    #[test]
    fn partial_definition_pin_defers_to_lockfile() {
        let mut lockfile = empty_lockfile();
        lockfile.snaps.insert(
            "core22".into(),
            crate::lock::SnapLockEntry {
                revision: 1847,
                sha3_384: HASH_B.into(),
            },
        );
        let images = HashMap::from([(
            "system".to_string(),
            image_with_snaps(
                SnapRef {
                    name: "core22".into(),
                    revision: Some(1847),
                    sha3_384: None,
                },
                vec![],
            ),
        )]);
        let outputs = Outputs::new();
        let declared = HashMap::new();
        let m = build_manifest(
            &outputs,
            &images,
            &declared,
            &lockfile,
            "amd64",
            "latest/stable",
            None,
        )
        .unwrap();
        let snap = &m.images["system"].snaps[0];
        assert_eq!(snap.pin_source, PinSource::Lockfile);
        assert_eq!(snap.sha3_384, HASH_B);
    }

    #[test]
    fn github_input_without_lockfile_pin_fails_closed() {
        let declared = HashMap::from([(
            "pkgs".to_string(),
            PackageInput {
                url: "github:owner/repo/main".into(),
            },
        )]);
        let images = HashMap::new();
        let outputs = Outputs::new();
        let lockfile = empty_lockfile();
        let err = build_manifest(
            &outputs,
            &images,
            &declared,
            &lockfile,
            "amd64",
            "latest/stable",
            None,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("pkgs"), "error must name the input: {msg}");
        assert!(
            msg.contains("no lockfile pin"),
            "named failure required: {msg}"
        );
    }

    #[test]
    fn path_input_is_local_without_a_lockfile_entry() {
        let declared = HashMap::from([(
            "vendored".to_string(),
            PackageInput {
                url: "path:vendor".into(),
            },
        )]);
        let lockfile = empty_lockfile();
        let images = HashMap::new();
        let outputs = Outputs::new();
        let m = build_manifest(
            &outputs,
            &images,
            &declared,
            &lockfile,
            "amd64",
            "latest/stable",
            None,
        )
        .unwrap();
        let input = &m.inputs["vendored"];
        assert!(input.local);
        assert!(input.revision.is_none() && input.sha256.is_none());
        assert_eq!(input.url, "path:vendor");
    }

    #[test]
    fn github_input_serializes_revision_and_sha256() {
        let mut lockfile = empty_lockfile();
        lockfile.inputs.insert(
            "pkgs".into(),
            crate::lock::InputLockEntry {
                revision: Some("c0ffee".into()),
                sha256: Some("beef".into()),
                local: false,
            },
        );
        let declared = HashMap::from([(
            "pkgs".to_string(),
            PackageInput {
                url: "github:owner/repo/main".into(),
            },
        )]);
        let m = build_manifest(
            &Outputs::new(),
            &HashMap::new(),
            &declared,
            &lockfile,
            "amd64",
            "latest/stable",
            None,
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&m.to_json().unwrap()).unwrap();
        assert_eq!(v["inputs"]["pkgs"]["revision"], "c0ffee");
        assert_eq!(v["inputs"]["pkgs"]["sha256"], "beef");
        assert!(
            v["inputs"]["pkgs"].get("local").is_none(),
            "local=false omitted"
        );
    }

    // ── Outputs section ──

    #[test]
    fn snap_output_carries_closure_key_and_identity() {
        let mut outputs = Outputs::new();
        outputs.insert("app".to_string(), bare_meta("demo-app", "1.2.3"));
        let lockfile = empty_lockfile();
        let m = build_manifest(
            &outputs,
            &HashMap::new(),
            &HashMap::new(),
            &lockfile,
            "amd64",
            "latest/stable",
            None,
        )
        .unwrap();
        let entry = &m.outputs["app"];
        assert_eq!(entry.name, "demo-app");
        assert_eq!(entry.version.as_deref(), Some("1.2.3"));
        let key = entry.closure_key.as_deref().unwrap();
        assert!(
            key.starts_with("v3:"),
            "Phase 22a closure key required: {key}"
        );
        assert_eq!(entry.artifact.state, ArtifactState::Unbuilt);
    }

    #[test]
    fn adopt_info_output_omits_version_and_marks_adopted() {
        let mut meta = bare_meta("adopted", "0");
        meta.adopt_info = Some("part".into());
        meta.version_adopted = true;
        let mut outputs = Outputs::new();
        outputs.insert("app".to_string(), meta);
        let m = build_manifest(
            &outputs,
            &HashMap::new(),
            &HashMap::new(),
            &empty_lockfile(),
            "amd64",
            "latest/stable",
            None,
        )
        .unwrap();
        let entry = &m.outputs["app"];
        assert!(
            entry.version.is_none(),
            "placeholder must not read as a version"
        );
        assert!(entry.version_adopted);
    }

    #[test]
    fn select_filters_outputs_and_errors_on_unknown_name() {
        let mut outputs = Outputs::new();
        outputs.insert("app".to_string(), bare_meta("demo-app", "1.0"));
        let lockfile = empty_lockfile();
        let m = build_manifest(
            &outputs,
            &HashMap::new(),
            &HashMap::new(),
            &lockfile,
            "amd64",
            "latest/stable",
            Some("app"),
        )
        .unwrap();
        assert_eq!(m.outputs.len(), 1);

        let err = build_manifest(
            &Outputs::new(),
            &HashMap::new(),
            &HashMap::new(),
            &lockfile,
            "amd64",
            "latest/stable",
            Some("nope"),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("'nope' not found"));
    }

    #[test]
    fn image_declarations_do_not_leak_into_outputs_section() {
        // The same table key converts both as SnapMeta (images carry name +
        // version) and as an ImageDeclaration. The key must appear under
        // `images` only.
        let mut outputs = Outputs::new();
        outputs.insert("system".to_string(), bare_meta("demo-system", "2.0.0"));
        let images = HashMap::from([(
            "system".to_string(),
            image_with_snaps(pinned("core22", 1847, HASH_A), vec![]),
        )]);
        let m = build_manifest(
            &outputs,
            &images,
            &HashMap::new(),
            &empty_lockfile(),
            "amd64",
            "latest/stable",
            None,
        )
        .unwrap();
        assert!(
            !m.outputs.contains_key("system"),
            "image key must not appear as a snap output: {m:?}"
        );
        assert!(m.images.contains_key("system"));
    }

    // ── Atomic write ──

    #[test]
    fn write_atomic_replaces_content_without_residue() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image.json");
        let m = manifest_with_image(pinned("core22", 1847, HASH_A), vec![]).unwrap();

        m.write_atomic(&path).unwrap();
        m.write_atomic(&path).unwrap();

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(entries, vec!["image.json".to_string()], "no temp residue");

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk, m.to_json().unwrap(), "bytes on disk == to_json");
    }

    #[test]
    fn failed_atomic_write_leaves_previous_manifest_intact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image.json");
        let m = manifest_with_image(pinned("core22", 1847, HASH_A), vec![]).unwrap();
        m.write_atomic(&path).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();

        // A write whose temp file cannot be created (parent "dir" is a file)
        // must fail without touching the existing manifest or leaving residue.
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let bad_path = blocker.join("nested").join("image.json");
        assert!(m.write_atomic(&bad_path).is_err());

        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(before, after, "failed write must not modify the manifest");
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(entries.len(), 2, "only manifest + blocker, no temp residue");
    }

    #[test]
    fn end_to_end_manifest_roundtrips_through_serde() {
        let mut outputs = Outputs::new();
        outputs.insert("app".to_string(), bare_meta("demo-app", "1.2.3"));
        let images = HashMap::from([(
            "system".to_string(),
            image_with_snaps(pinned("core22", 1847, HASH_A), vec![]),
        )]);
        let m = build_manifest(
            &outputs,
            &images,
            &HashMap::new(),
            &empty_lockfile(),
            "amd64",
            "latest/stable",
            None,
        )
        .unwrap();
        let json = m.to_json().unwrap();
        let back: ImageManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.manifest_version, MANIFEST_VERSION);
        assert_eq!(back.images["system"].snaps, m.images["system"].snaps);
        assert_eq!(back.to_json().unwrap(), json, "roundtrip is byte-stable");
    }
}
