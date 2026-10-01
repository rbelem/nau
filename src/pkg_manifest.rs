//! The signed per-package shareable manifest (ADR-0033 Decision 2) — the
//! one genuinely new artifact peer sharing introduces.
//!
//! Issue #326 PR 4: the wire half (the schema, canonical bytes, and the
//! sign/verify wrapping) moved DOWN into `nau_core::pkg_manifest` beside
//! the install-record vocabulary; this root module keeps the MINTING and
//! publish-lane glue — who signs, and how the generation record becomes
//! a manifest — which rides the runtime's `InstalledPackage`. Every
//! pre-existing `crate::pkg_manifest::` path keeps resolving through the
//! re-export below.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, WrapErr};

pub use nau_core::pkg_manifest::{
    canonical_bytes, host_target, hostname, manifest_path, sign, validate_payload_path,
    validate_sha256, verify, AppAssembly, DesktopIcon, DesktopLauncher, InstallMeta, ManifestFile,
    PackageManifest,
};

use crate::runtime::{Generation, InstalledPackage};

/// Load the operator's signing key for manifest minting. Unlike
/// [`crate::sign::load_secret_key`] — whose `Ok(None)` means signing is
/// opt-out — minting REQUIRES a key: unsigned store entries are never
/// served (ADR-0033 Decision 2). Absence is a named error pointing at
/// the `nau key` ceremony.
pub fn load_signing_key(home: &Path) -> miette::Result<nau_core::sign::KeyPair> {
    nau_core::sign::load_secret_key(home)?.ok_or_else(|| {
        miette::miette!(
            "no signing key at {} — shareable package manifests are always signed; \
             run `nau key keygen` first (see `nau key list` for the ceremony ledger)",
            nau_core::sign::secret_key_path(home).display()
        )
    })
}

// ── One mint, one truth (ADR-0033 Decision 2) ──
//
// Every minting lane (serve, export — build/ingest when they land)
// calls [`mint_manifest`]; there is exactly one implementation so the
// body a peer fetches over `/manifests/<pkg>` and the file a mirror
// freezes are the same bytes by construction, not by discipline.

/// Mint a [`PackageManifest`] from a generation record (ADR-0033
/// Decision 2). The record keeps per-file CONTENT ADDRESSES only — no
/// payload paths and no executable bits — so `files[].path` carries the
/// store identity (the sha256 itself) and `executable` is true for the
/// recorded command binaries (apps, confined launchers, service
/// binaries — the farm links those for direct execution). `install`
/// mirrors the snap.yaml-derived records verbatim: metadata travels,
/// never re-derived. `signer`/`signature` are stamped by [`sign`].
pub fn mint_manifest(record: &InstalledPackage) -> PackageManifest {
    let binaries: BTreeSet<&str> = record
        .apps
        .values()
        .chain(record.launchers.values())
        .chain(record.service_bins.values())
        .map(String::as_str)
        .collect();
    let files: Vec<ManifestFile> = record
        .files
        .iter()
        .map(|sha256| ManifestFile {
            path: sha256.clone(),
            sha256: sha256.clone(),
            executable: binaries.contains(sha256.as_str()),
        })
        .collect();
    PackageManifest {
        name: record.name.clone(),
        version: record.version.clone(),
        revision: record.revision,
        target: host_target(),
        files,
        install: InstallMeta {
            units: record.units.clone(),
            apps: record.apps.clone(),
            launchers: record.launchers.clone(),
            assembly: record.assembly.clone(),
            confined: record.confined.clone(),
            app_confined: record.app_confined.clone(),
            desktops: record.desktops.clone(),
            fonts: record.fonts.clone(),
            services: record.services.clone(),
            service_bins: record.service_bins.clone(),
            requires: record.requires.clone(),
        },
        signer: String::new(),
        signature: String::new(),
    }
}

// ── The union rule (ADR-0033 Decision 5 invariant) ──

/// The pull-staging inbox: staged peer manifests under
/// `<root>/store/manifests/` (see [`manifest_path`] for the layout
/// invariant), sorted by package name. A missing directory is an empty
/// inbox — an installed-only store is still publishable.
pub fn inbox_manifests(store_root: &Path) -> miette::Result<Vec<(String, PathBuf)>> {
    let dir = store_root.join("store").join("manifests");
    let Ok(read) = std::fs::read_dir(&dir) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for entry in read {
        let entry = entry
            .into_diagnostic()
            .wrap_err_with(|| format!("reading {}", dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        out.push((stem.to_string(), path));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// The union's inbox half: staged manifests whose package is NOT in the
/// current generation — the ones published verbatim instead of minted
/// fresh. Both `serve /info` and `export index.json` walk this, so the
/// dynamic view and the frozen tree never disagree on visibility.
pub fn union_inbox<'a>(
    generation: &Option<Generation>,
    inbox: &'a [(String, PathBuf)],
) -> Vec<&'a (String, PathBuf)> {
    let gen_names: BTreeSet<&str> = generation
        .as_ref()
        .map(|g| g.packages.keys().map(String::as_str).collect())
        .unwrap_or_default();
    inbox
        .iter()
        .filter(|(name, _)| !gen_names.contains(name.as_str()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Deterministic keypair from a single seed byte (test-only; local
    /// copy — the wire-half's helper moved to `nau_core::pkg_manifest`).
    fn test_kp(seed_byte: u8) -> nau_core::sign::KeyPair {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed_byte; 32]);
        nau_core::sign::KeyPair {
            seed: sk.to_bytes(),
            public: sk.verifying_key().to_bytes(),
        }
    }

    /// A generation record with one app, one launcher and one service
    /// binary (the executable bits' sources) plus two plain blobs.
    fn record() -> InstalledPackage {
        let mut apps = BTreeMap::new();
        apps.insert("hello".to_string(), "aa".repeat(32));
        let mut launchers = BTreeMap::new();
        launchers.insert("hello".to_string(), "bb".repeat(32));
        let mut service_bins = BTreeMap::new();
        service_bins.insert("srv".to_string(), "cc".repeat(32));
        InstalledPackage {
            name: "hello".into(),
            version: "2.10".into(),
            revision: 7,
            sha3_384: "a3".repeat(48),
            files: vec![
                "aa".repeat(32),
                "bb".repeat(32),
                "cc".repeat(32),
                "dd".repeat(32),
            ],
            units: vec![],
            layer: crate::farm::ClaimLayer::Own,
            apps,
            requires: vec!["libc6".into()],
            launchers,
            assembly: BTreeMap::new(),
            confined: None,
            app_confined: BTreeMap::new(),
            desktops: BTreeMap::new(),
            fonts: BTreeMap::new(),
            services: BTreeMap::new(),
            service_bins,
            meta_digest: None,
        }
    }

    /// The regression guard the council demanded: serve and export mint
    /// through this one function, so the same record serializes to the
    /// SAME bytes (ed25519 signatures are deterministic) — the `/info`-
    /// adjacent `manifests/<pkg>.json` a mirror freezes can never drift
    /// from the body `/manifests/<pkg>` serves.
    #[test]
    fn one_mint_serve_and_export_serialize_byte_identically() {
        let kp = test_kp(1);
        let mut served = mint_manifest(&record());
        sign(&mut served, &kp).unwrap();
        let mut exported = mint_manifest(&record());
        sign(&mut exported, &kp).unwrap();

        // The exact serializations the two lanes emit.
        let serve_body = serde_json::to_vec_pretty(&served).unwrap();
        let export_file = serde_json::to_vec_pretty(&exported).unwrap();
        assert_eq!(serve_body, export_file);
    }

    /// The minted manifest's documented semantics (export semantics won
    /// when the mints were consolidated): `files[].path` is the sha256
    /// store identity and `executable` is the recorded-command union.
    #[test]
    fn minted_files_carry_store_identity_and_command_executable_bits() {
        let manifest = mint_manifest(&record());
        assert_eq!(manifest.target, host_target());
        assert_eq!(manifest.files.len(), 4);
        for file in &manifest.files {
            assert_eq!(file.path, file.sha256, "path = store identity");
        }
        let exe: Vec<&str> = manifest
            .files
            .iter()
            .filter(|f| f.executable)
            .map(|f| f.sha256.as_str())
            .collect();
        // The app binary, the launcher wrapper and the service binary —
        // in `files` order; the plain blob stays non-executable.
        let (aa, bb, cc) = ("aa".repeat(32), "bb".repeat(32), "cc".repeat(32));
        assert_eq!(exe, vec![aa.as_str(), bb.as_str(), cc.as_str()]);
        assert_eq!(manifest.install.apps.len(), 1);
        assert_eq!(manifest.install.requires, vec!["libc6".to_string()]);
    }

    // ── Union helpers ──

    #[test]
    fn union_inbox_keeps_only_packages_outside_the_generation() {
        let mut packages = BTreeMap::new();
        packages.insert(
            "alpha".to_string(),
            crate::runtime::InstalledPackage {
                name: "alpha".into(),
                revision: 1,
                ..record()
            },
        );
        let gen = Generation {
            n: 1,
            base_version: "test".into(),
            packages,
            created_epoch: 0,
            boot_entry: None,
        };
        let inbox = vec![
            ("alpha".to_string(), PathBuf::from("/x/alpha.json")),
            ("gamma".to_string(), PathBuf::from("/x/gamma.json")),
        ];
        let inbox_only: Vec<&(String, PathBuf)> = union_inbox(&Some(gen), &inbox);
        assert_eq!(inbox_only.len(), 1);
        assert_eq!(inbox_only[0].0, "gamma");
        assert!(
            union_inbox(&None, &inbox).len() == 2,
            "no generation → all inbox"
        );
    }
}
