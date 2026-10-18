//! Image manifest IR — the flat, serializable, diffable result of evaluating
//! a definition (`nau eval`, Phase 23 of
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
//!       "closure_key": "v4:…64 hex…",
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

use crate::lock::LockFile;
use crate::lua::Outputs;
use nau_core::manifest_ir::ImageDeclaration;
use nau_core::snap_types::{PackageInput, SnapMeta, SnapRef};

// Re-exported from the IR home ([`crate::manifest_ir`], #317) so every
// pre-existing `crate::manifest::` path keeps compiling.
pub use nau_core::manifest_ir::{
    Artifact, ArtifactState, BuiltBlob, ImageEntry, ImageManifest, ManifestInput, ManifestSnap,
    PinSource, SnapOutputEntry, SnapRole, MANIFEST_VERSION,
};

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
                     data only — run 'nau lock' (or build once online) to record it",
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
        archs: nau_core::snap_types::resolve_archs(meta, &[]),
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
    // uki, esp_partuuid, roothash) are only known once `nau image`
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
         hash, nau.lock has no entry, and the package index has no pre-resolved \
         pin for arch '{arch}'; pin it explicitly or record pins via 'nau image'",
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
    Ok(nau_core::cache_key::BuildClosure::for_meta(meta, requires, build_deps).cache_key())
}

/// One requires-closure member: lockfile pin when present (pure data),
/// else declared-version pinning with `hash: None` — the exact fallback
/// the binary cache uses.
fn requires_member(name: &str, lockfile: &LockFile) -> nau_core::cache_key::RequiresMember {
    if let Some(member) = crate::lock::pinned_member(name, lockfile) {
        return member;
    }
    let pin = crate::deps::load_meta(name).ok().map(|meta| meta.version);
    nau_core::cache_key::RequiresMember {
        name: name.to_string(),
        pin,
        hash: None,
    }
}

#[cfg(test)]
mod tests;
