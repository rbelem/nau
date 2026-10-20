//! Export tests. The shared fixture lives here; the assertions are
//! grouped by the job they exercise, one file per group.

use super::*;
use nau_core::pkg_manifest::{
    ClaimLayer, InstallMeta, InstalledPackage, ManifestFile, PackageManifest,
};
use nau_core::sign::KeyPair;
use sha2::Digest as _;
use std::collections::BTreeMap;

mod curation;
mod fail_closed;
mod mint;
mod reexport;
mod tree_shape;

const SHARED: &[u8] = b"shared-blob-bytes";
const ALPHA_ONLY: &[u8] = b"alpha-file-bytes";
const BETA_ONLY: &[u8] = b"beta-file-bytes";
const GAMMA_BLOB: &[u8] = b"gamma-file-bytes";

/// The real content address of `bytes` — blob names must be true
/// sha256 preimages so the copy assertions can re-hash.
fn h(bytes: &[u8]) -> String {
    format!("{:x}", sha2::Sha256::digest(bytes))
}

/// Deterministic keypair from a single seed byte (the
/// `pkg_manifest` test pattern) — mints the inbox manifest.
fn inbox_kp(seed_byte: u8) -> KeyPair {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed_byte; 32]);
    KeyPair {
        seed: sk.to_bytes(),
        public: sk.verifying_key().to_bytes(),
    }
}

fn record(name: &str, version: &str, revision: u32, files: Vec<String>) -> InstalledPackage {
    InstalledPackage {
        name: name.into(),
        version: version.into(),
        revision,
        sha3_384: "a3".repeat(48),
        files,
        units: vec![],
        layer: ClaimLayer::Own,
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
        meta_digest: None,
    }
}

fn write_blob(blobs: &BlobStore, hash: &str, bytes: &[u8]) {
    let path = blobs.blob_path(hash);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// Fabricate a pod store: two generation packages sharing one blob
/// (dedup proof) plus one signed inbox-only manifest, and a tempdir
/// home whose signing key `load_signing_key` finds.
struct Fixture {
    _home: tempfile::TempDir,
    /// The operator key `run_at` loads from `home`.
    kp: KeyPair,
    state_root: PathBuf,
    blobs: BlobStore,
    out: PathBuf,
}

fn fabricate() -> Fixture {
    let state = tempfile::tempdir().unwrap();
    let state_root = state.path().to_path_buf();
    let blobs = BlobStore::new(state_root.join("store"));

    let shared = h(SHARED);
    let alpha_hash = h(ALPHA_ONLY);
    let beta_hash = h(BETA_ONLY);
    let gamma_hash = h(GAMMA_BLOB);

    write_blob(&blobs, &shared, SHARED);
    write_blob(&blobs, &alpha_hash, ALPHA_ONLY);
    write_blob(&blobs, &beta_hash, BETA_ONLY);
    write_blob(&blobs, &gamma_hash, GAMMA_BLOB);

    let mut packages = BTreeMap::new();
    packages.insert(
        "alpha".to_string(),
        record("alpha", "1.0", 4, vec![shared.clone(), alpha_hash]),
    );
    packages.insert(
        "beta".to_string(),
        record("beta", "2.1", 9, vec![shared, beta_hash]),
    );
    let gen = nau_core::pkg_manifest::Generation {
        n: 1,
        base_version: "25.04".into(),
        packages,
        created_epoch: 0,
        boot_entry: None,
    };
    let gen_dir = nau_core::generation_view::generation_dir(&state_root, 1);
    std::fs::create_dir_all(&gen_dir).unwrap();
    std::fs::write(
        gen_dir.join("manifest.json"),
        serde_json::to_vec(&gen).unwrap(),
    )
    .unwrap();
    std::os::unix::fs::symlink("generations/1", state_root.join("active")).unwrap();

    // Inbox-only peer manifest, signed under a throwaway peer key.
    let peer = inbox_kp(9);
    let mut gamma = PackageManifest {
        name: "gamma".into(),
        version: "0.4".into(),
        revision: 3,
        target: "x86_64-unknown-linux-gnu".into(),
        files: vec![ManifestFile {
            path: gamma_hash.clone(),
            sha256: gamma_hash,
            executable: false,
        }],
        install: InstallMeta::default(),
        signer: String::new(),
        signature: String::new(),
    };
    nau_core::pkg_manifest::sign(&mut gamma, &peer).unwrap();
    let inbox_path = nau_core::pkg_manifest::manifest_path(&state_root, "gamma");
    std::fs::create_dir_all(inbox_path.parent().unwrap()).unwrap();
    std::fs::write(&inbox_path, serde_json::to_vec(&gamma).unwrap()).unwrap();

    // The operator signing key, at the real on-disk location
    // (`~/.config/nau/secret-key` under the injected home).
    let home = tempfile::tempdir().unwrap();
    let kp = nau_core::sign::create_secret_key(home.path()).unwrap();

    Fixture {
        _home: home,
        kp,
        state_root,
        blobs,
        out: state.keep().join("tree"),
    }
}
