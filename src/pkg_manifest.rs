//! The signed per-package shareable manifest (ADR-0033 Decision 2) — the
//! one genuinely new artifact peer sharing introduces.
//!
//! What traveled before was not enough: the generation `manifest.json`
//! (`src/runtime.rs`) records per-file sha256 hashes but is unsigned
//! derived local state; `ImageManifest` (`src/manifest.rs`) signs
//! image-level eval output against sha3-384 Snap Store pins, not store
//! blobs. A receiving peer must reconstruct an installable entry from
//! the manifest ALONE, so the snap.yaml-derived install metadata
//! recorded at install time (apps, launchers, services, confinement,
//! and the other install-time records `InstalledPackage` carries) has
//! to travel with the file hashes — metadata must travel, never be
//! re-derived.
//!
//! # Canonical bytes
//!
//! Signature input is `serde_json::to_vec` of the manifest **with the
//! `signature` field emptied** — mirroring `src/sign.rs`
//! (`canonical_bytes`, where the signatures map is emptied in place).
//! The field stays present (empty string) so the shape is byte-stable
//! and a signature never covers itself.
//!
//! Minting (who signs) is the serve/export/pull lanes' business; this
//! module owns the schema, the canonical bytes, and the sign/verify
//! wrapping over `crate::sign`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, WrapErr};
use serde::{Deserialize, Serialize};

use crate::runtime::{Generation, InstalledPackage};
use crate::sign::KeyPair;

/// One store file of a shared package: the payload path it occupied at
/// install time, the sha256 of its content-addressed blob in the store
/// (the ADR-0012 blob set — `store/<aa>/<sha256>`), and whether the
/// installed file carried the executable bit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFile {
    /// The file's path within the installed payload tree.
    pub path: String,
    /// sha256 of the store blob — the pull lane hash-checks every
    /// fetched blob against this.
    pub sha256: String,
    /// Whether the installed file was executable.
    pub executable: bool,
}

/// The install-time metadata a receiving peer needs to reconstruct an
/// installable entry from the manifest alone (ADR-0033 Decision 2):
/// exactly what `InstalledPackage` (`src/runtime.rs`) records from the
/// payload's snap.yaml at install time, minus the identity fields
/// (name/version/revision live on [`PackageManifest`]) and the per-file
/// hash list (promoted to [`ManifestFile`] with paths and the
/// executable bit). Typed throughout — no raw passthrough.
///
/// Every field carries the same serde defaults as its
/// `InstalledPackage` counterpart, so manifests minted before a field
/// existed — and minimal ones — keep parsing.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct InstallMeta {
    /// Daemon unit names this package contributed (empty for plain
    /// apps) — mirrored from `InstalledPackage::units`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub units: Vec<String>,
    /// App name → sha256 of the app's command binary in the store.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub apps: BTreeMap<String, String>,
    /// App name → sha256 of the app's confined-launcher wrapper blob.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub launchers: BTreeMap<String, String>,
    /// Multi-file app payloads: app name → the app's in-payload binary
    /// path plus sibling content recorded beside it at install time.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub assembly: BTreeMap<String, crate::farm::AppAssembly>,
    /// Package-level confinement declaration (ADR-0016): `Some` =
    /// confined, `None` = unconfined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confined: Option<crate::snap::Confinement>,
    /// Per-app confinement overrides: app name → grants, only for apps
    /// whose `confined` differs from the package default.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub app_confined: BTreeMap<String, crate::snap::Confinement>,
    /// Desktop-launcher metadata per GUI app (issue #7), parsed from
    /// the package's `.desktop` file at install time.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub desktops: BTreeMap<String, crate::runtime::DesktopLauncher>,
    /// Payload font files: path under the payload's `usr/share/fonts`
    /// → sha256 (issue #29 cutover).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fonts: BTreeMap<String, String>,
    /// Service declarations (ADR-0032) recorded verbatim from the
    /// payload's snap.yaml: service name → decl.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub services: BTreeMap<String, crate::snap::ServiceDecl>,
    /// Service name → sha256 of the service's command binary blob.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub service_bins: BTreeMap<String, String>,
    /// The package's declared runtime requires (ADR-0018), recorded so
    /// a receiving peer knows the package needs the emit-time LD
    /// wrapper without re-reading a pool it does not have.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
}

/// A signed, per-package, shareable manifest (ADR-0033 Decision 2):
/// what travels between peers, beside the store blobs it references.
/// The store's first per-package signed artifact — canonicalized and
/// signed with the same machinery as the image manifest (`crate::sign`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PackageManifest {
    /// Snap/package name (the store key; `[a-z0-9-]` per the ADR-0032
    /// collision-classifier charset the wire grammar reuses).
    pub name: String,
    pub version: String,
    /// Monotonic per name — the freshness rule (ADR-0033 Decision 7)
    /// refuses older revisions unless `--allow-downgrade` is explicit.
    pub revision: u32,
    /// GNU target triplet the payload was built for.
    pub target: String,
    /// The store blob set: every file the package contributes, with
    /// its sha256 and executable bit.
    pub files: Vec<ManifestFile>,
    /// The snap.yaml-derived install metadata (see [`InstallMeta`]).
    #[serde(default)]
    pub install: InstallMeta,
    /// The signing key id (first 16 hex chars of the public key) —
    /// verifiers match it against their trusted-key set (the peer lane
    /// enforces fail-closed `verify_trust_set` semantics).
    #[serde(default)]
    pub signer: String,
    /// The ed25519 signature over [`canonical_bytes`], as
    /// [`crate::sign::sign_bytes`] emits it (standard base64 — the
    /// encoding `crate::sign::verify` decodes).
    #[serde(default)]
    pub signature: String,
}

/// Canonical signature input: the manifest serialized with `signature`
/// emptied (see the module docs — a signature never covers itself; the
/// emptied field keeps the bytes byte-stable, the same rule
/// `crate::sign::canonical_bytes` applies to the image manifest).
pub fn canonical_bytes(pkg: &PackageManifest) -> miette::Result<Vec<u8>> {
    let mut clean = pkg.clone();
    clean.signature = String::new();
    serde_json::to_vec(&clean).map_err(|e| miette::miette!("canonical serialization: {e}"))
}

/// Sign `pkg` in place under `kp`: the ed25519 signature over the
/// canonical bytes, with the signer key id recorded beside it. Re-signing
/// replaces any previous signature — a manifest carries one author's
/// signature; multi-key trust is the verifier-side keychain's job.
pub fn sign(pkg: &mut PackageManifest, kp: &KeyPair) -> miette::Result<()> {
    // The signer id is part of the canonical body (only `signature`
    // empties out), so it is stamped BEFORE the signed bytes exist —
    // the signature binds who signed, not just what.
    pkg.signer = kp.key_id();
    let bytes = canonical_bytes(pkg)?;
    pkg.signature = crate::sign::sign_bytes(&bytes, kp);
    Ok(())
}

/// Verify `pkg`'s signature against the full public key `public_hex`
/// (64 hex chars — the manifest carries only the 16-hex key id). A
/// tampered field (canonical bytes changed), a signature that does not
/// decode, or a key whose id is not the recorded `signer` fails closed.
/// Trust (is this key BELIEVED?) is the caller's keychain decision —
/// this checks self-consistency only, wrapping [`crate::sign::verify`].
pub fn verify(pkg: &PackageManifest, public_hex: &str) -> miette::Result<()> {
    let mut signatures = BTreeMap::new();
    signatures.insert(
        pkg.signer.clone(),
        serde_json::Value::String(pkg.signature.clone()),
    );
    crate::sign::verify(&canonical_bytes(pkg)?, &signatures, public_hex)
}

/// Load the operator's signing key for manifest minting. Unlike
/// [`crate::sign::load_secret_key`] — whose `Ok(None)` means signing is
/// opt-out — minting REQUIRES a key: unsigned store entries are never
/// served (ADR-0033 Decision 2). Absence is a named error pointing at
/// the `shuttle key` ceremony.
pub fn load_signing_key(home: &Path) -> miette::Result<KeyPair> {
    crate::sign::load_secret_key(home)?.ok_or_else(|| {
        miette::miette!(
            "no signing key at {} — shareable package manifests are always signed; \
             run `shuttle key keygen` first (see `shuttle key list` for the ceremony ledger)",
            crate::sign::secret_key_path(home).display()
        )
    })
}

/// The pull-staging inbox path for one package's signed manifest:
/// `<root>/store/manifests/<pkg>.json`, where `root` is the state root
/// whose `store/` holds the content blobs.
///
/// Invariant (ADR-0033 Decision 5): `serve` and `export` publish the
/// UNION of the generation-derived manifests and this inbox — an inbox
/// entry whose name is not in the current generation is still visible.
/// This is how `pull` stages verified peer content without installing:
/// the manifest lands here, the blobs in the store, and installation
/// stays the pod workflow.
pub fn manifest_path(store_root: &Path, pkg: &str) -> PathBuf {
    store_root
        .join("store")
        .join("manifests")
        .join(format!("{pkg}.json"))
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

/// Host GNU triplet for minted `target` fields — the best target record
/// available at mint time (the pod store keeps no per-package build
/// triplet; payloads are host-arch glibc binaries).
pub fn host_target() -> String {
    format!("{}-unknown-linux-gnu", std::env::consts::ARCH)
}

/// The publishing-host identity `/info` and `index.json` carry: the
/// kernel hostname, read at `/proc/sys/kernel/hostname` (std fs, no new
/// deps). `unknown` when unreadable or empty — a label, never trust
/// state. `serve` prefers the configured `node.name` over this.
pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
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

// ── Trust-boundary validation of manifest contents ──

/// The sha256 discipline: exactly 64 lowercase hex chars — the same
/// content-address rule the store and the wire grammar use; anything
/// else is refused before it can reach a path.
pub fn validate_sha256(file: &ManifestFile) -> miette::Result<()> {
    let malformed = file.sha256.len() != 64
        || !file.sha256.bytes().all(|b| b.is_ascii_hexdigit())
        || file.sha256.bytes().any(|b| b.is_ascii_uppercase());
    if malformed {
        miette::bail!(
            "manifest file '{}' carries malformed sha256 {:?} — expected 64 lowercase hex chars",
            file.path,
            file.sha256
        );
    }
    Ok(())
}

/// Boundary validation of a manifest's declared payload path: no
/// absolute paths, no `..` segments — a manifest is untrusted wire
/// input and its paths are only ever joined under the payload root by
/// the (future) install-from-inbox consumer.
pub fn validate_payload_path(file: &ManifestFile) -> miette::Result<()> {
    use std::path::Component;
    let unsafe_path = file.path.starts_with('/')
        || Path::new(&file.path)
            .components()
            .any(|c| c == Component::ParentDir);
    if unsafe_path {
        miette::bail!(
            "manifest file carries an unsafe path {:?} — absolute paths and '..' \
             segments are refused",
            file.path
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic keypair from a single seed byte (test-only).
    fn test_kp(seed_byte: u8) -> KeyPair {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed_byte; 32]);
        KeyPair {
            seed: sk.to_bytes(),
            public: sk.verifying_key().to_bytes(),
        }
    }

    fn sample() -> PackageManifest {
        let mut apps = BTreeMap::new();
        apps.insert("hello".to_string(), "ab".repeat(32));
        let services: BTreeMap<String, crate::snap::ServiceDecl> = serde_json::from_value(
            serde_json::json!({ "srv": { "command": "bin/srv", "daemon": "simple" } }),
        )
        .unwrap();
        let confined: crate::snap::Confinement =
            serde_json::from_value(serde_json::json!({})).unwrap();
        PackageManifest {
            name: "hello".to_string(),
            version: "2.10".to_string(),
            revision: 7,
            target: "x86_64-linux-gnu".to_string(),
            files: vec![ManifestFile {
                path: "usr/bin/hello".to_string(),
                sha256: "cd".repeat(32),
                executable: true,
            }],
            install: InstallMeta {
                apps,
                services,
                confined: Some(confined),
                requires: vec!["libc6".to_string()],
                ..Default::default()
            },
            signer: String::new(),
            signature: String::new(),
        }
    }

    #[test]
    fn roundtrip_preserves_manifest() {
        let pkg = sample();
        let json = serde_json::to_string(&pkg).unwrap();
        let parsed: PackageManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, pkg);
    }

    #[test]
    fn canonical_bytes_are_stable_and_exclude_the_signature() {
        let mut pkg = sample();
        sign(&mut pkg, &test_kp(1)).unwrap();
        let canonical = canonical_bytes(&pkg).unwrap();

        // Byte-stable across calls…
        assert_eq!(canonical_bytes(&pkg).unwrap(), canonical);
        // …and identical to the unsigned shape: the signature field is
        // emptied, not removed, so re-serializing the unsigned manifest
        // matches.
        let mut unsigned = pkg.clone();
        unsigned.signature = String::new();
        assert_eq!(serde_json::to_vec(&unsigned).unwrap(), canonical);
        assert_ne!(serde_json::to_vec(&pkg).unwrap(), canonical);
    }

    #[test]
    fn verify_accepts_signed_manifest_and_refuses_tampered_signature() {
        let mut pkg = sample();
        sign(&mut pkg, &test_kp(1)).unwrap();
        let public = test_kp(1).public_hex();
        verify(&pkg, &public).expect("a freshly signed manifest must verify");

        let mut tampered = pkg.clone();
        tampered.signature.push('x');
        assert!(
            verify(&tampered, &public).is_err(),
            "a flipped signature must be refused"
        );

        // Content tampering changes the canonical bytes → refused too.
        let mut tampered = pkg.clone();
        tampered.files[0].sha256 = "ff".repeat(32);
        assert!(verify(&tampered, &public).is_err());
    }

    #[test]
    fn verify_refuses_a_different_key() {
        let mut pkg = sample();
        sign(&mut pkg, &test_kp(1)).unwrap();
        let other = test_kp(2).public_hex();
        assert!(
            verify(&pkg, &other).is_err(),
            "verifying under the wrong public key must fail closed"
        );
    }

    #[test]
    fn inbox_path_is_store_scoped_per_package() {
        let root = Path::new("/srv/shuttle-state");
        assert_eq!(
            manifest_path(root, "hello"),
            PathBuf::from("/srv/shuttle-state/store/manifests/hello.json")
        );
    }

    // ── One mint, one truth ──

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
            InstalledPackage {
                name: "alpha".into(),
                version: "1.0".into(),
                revision: 1,
                sha3_384: String::new(),
                files: vec![],
                units: vec![],
                layer: crate::farm::ClaimLayer::Own,
                apps: BTreeMap::new(),
                requires: vec![],
                launchers: BTreeMap::new(),
                assembly: BTreeMap::new(),
                confined: None,
                app_confined: BTreeMap::new(),
                desktops: BTreeMap::new(),
                fonts: BTreeMap::new(),
                services: BTreeMap::new(),
                service_bins: BTreeMap::new(),
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

    // ── Trust-boundary validators ──

    #[test]
    fn sha_validation_demands_64_lowercase_hex() {
        let ok = ManifestFile {
            path: "ab".repeat(32),
            sha256: "ab".repeat(32),
            executable: false,
        };
        validate_sha256(&ok).unwrap();
        for bad in ["AB".repeat(32), "ab".repeat(31), "zz".repeat(32)] {
            let file = ManifestFile {
                path: bad.clone(),
                sha256: bad,
                executable: false,
            };
            assert!(validate_sha256(&file).is_err(), "{:?}", file.sha256);
        }
    }

    #[test]
    fn payload_path_validation_refuses_absolute_and_parent_segments() {
        let file = |path: &str| ManifestFile {
            path: path.to_string(),
            sha256: "ab".repeat(32),
            executable: false,
        };
        validate_payload_path(&file("usr/bin/hello")).unwrap();
        validate_payload_path(&file("ab".repeat(32).as_str())).unwrap();
        for bad in [
            "/etc/passwd",
            "../../etc/passwd",
            "usr/../../etc/passwd",
            "..",
        ] {
            let err = validate_payload_path(&file(bad)).expect_err(bad);
            assert!(err.to_string().contains(bad), "{err}");
        }
    }
}
