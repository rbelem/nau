use super::*;
use std::collections::BTreeMap;
use std::io::{Read, Write};

use nau_core::pkg_manifest::{ManifestFile, PackageManifest};

use crate::oci::sha256_hex;
use crate::pull_ref::PullRef;
use crate::runtime::RuntimeStore;
use std::path::PathBuf;

/// Deterministic keypair from a single seed byte (test-only).
fn test_kp(seed_byte: u8) -> crate::sign::KeyPair {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed_byte; 32]);
    crate::sign::KeyPair {
        seed: sk.to_bytes(),
        public: sk.verifying_key().to_bytes(),
    }
}

fn blob_bytes() -> Vec<u8> {
    b"payload-bytes-for-hello".to_vec()
}

fn blob_sha() -> String {
    sha256_hex(blob_bytes())
}

fn signed_manifest(kp: &crate::sign::KeyPair) -> PackageManifest {
    let mut pkg = PackageManifest {
        name: "hello".to_string(),
        version: "2.10".to_string(),
        revision: 7,
        target: crate::pkg_manifest::host_target(),
        files: vec![ManifestFile {
            path: "usr/bin/hello".to_string(),
            sha256: blob_sha(),
            executable: true,
        }],
        install: Default::default(),
        signer: String::new(),
        signature: String::new(),
    };
    crate::pkg_manifest::sign(&mut pkg, kp).unwrap();
    pkg
}

fn manifest_source(pkg: &PackageManifest) -> Vec<u8> {
    serde_json::to_vec(pkg).unwrap()
}

/// A canned-URL transport: every route answers with fixed bytes;
/// anything else is a test failure.
struct FakeFetch {
    routes: BTreeMap<String, Vec<u8>>,
}

impl FakeFetch {
    fn peer(manifest: &[u8], blobs: &[(&str, Vec<u8>)]) -> FakeFetch {
        let mut routes = BTreeMap::new();
        routes.insert(
            "http://peer.test:7780/manifests/hello".to_string(),
            manifest.to_vec(),
        );
        for (sha, bytes) in blobs {
            routes.insert(format!("http://peer.test:7780/blobs/{sha}"), bytes.clone());
        }
        FakeFetch { routes }
    }
}

impl Fetch for FakeFetch {
    fn get(&self, url: &str) -> miette::Result<Vec<u8>> {
        self.routes
            .get(url)
            .cloned()
            .ok_or_else(|| miette::miette!("no canned response for {url}"))
    }
}

/// A store in a tempdir, its operator keychain in a second tempdir,
/// and the device-image anchor tree in a third (the anchor path is
/// `<anchor_dir>/update-key.pub`; its `trusted-keys/` and
/// `revoked-keys` siblings are what the verify walk consults). The
/// trusted operator key set is [kp]; the device set starts empty.
struct Fixture {
    _store_dir: tempfile::TempDir,
    _keys_dir: tempfile::TempDir,
    _anchor_dir: tempfile::TempDir,
    store: RuntimeStore,
    keys: PathBuf,
    anchor: PathBuf,
    anchor_dir: PathBuf,
}

impl Fixture {
    fn with_trust(kp: &crate::sign::KeyPair) -> Fixture {
        let store_dir = tempfile::tempdir().unwrap();
        let keys_dir = tempfile::tempdir().unwrap();
        let anchor_dir = tempfile::tempdir().unwrap();
        crate::sign::install_public_key(kp, keys_dir.path()).unwrap();
        let store = RuntimeStore::new(store_dir.path().to_path_buf());
        let keys = keys_dir.path().to_path_buf();
        let anchor = anchor_dir.path().join("update-key.pub");
        Fixture {
            _store_dir: store_dir,
            _keys_dir: keys_dir,
            anchor_dir: anchor_dir.path().to_path_buf(),
            _anchor_dir: anchor_dir,
            store,
            keys,
            anchor,
        }
    }

    /// Bake `kp` into the DEVICE image trust set (the trusted-keys
    /// directory beside the anchor).
    fn install_device_anchor(&self, kp: &crate::sign::KeyPair) {
        crate::sign::install_public_key(kp, &self.anchor_dir.join("trusted-keys")).unwrap();
    }

    /// List a key id in the DEVICE image revocation list.
    fn list_device_revoked(&self, key_id: &str) {
        std::fs::write(self.anchor_dir.join("revoked-keys"), format!("{key_id}\n")).unwrap();
    }

    /// List a key id in the OPERATOR revocation list.
    fn list_operator_revoked(&self, key_id: &str) {
        std::fs::write(self.keys.join("revoked-keys"), format!("{key_id}\n")).unwrap();
    }

    /// Empty the operator keychain (a device with no operator keys
    /// — trust must come from the image anchors alone).
    fn clear_operator_keychain(&self) {
        for entry in std::fs::read_dir(&self.keys).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) == Some("pub") {
                std::fs::remove_file(path).unwrap();
            }
        }
    }

    /// Write `manifest` directly into the pull-staging inbox (as a
    /// prior peer pull would have).
    /// The ship-crate view of the same store root (the transport
    /// lane takes the `BlobStore` seam, not the runtime store).
    fn blobs(&self) -> nau_core::blob_store::BlobStore {
        self.store.blob_store()
    }

    /// The freshness gate's installed-revision input, read from the
    /// seeded generation (what `run` resolves from the pod store).
    fn installed(&self, pkg: &str) -> Option<u32> {
        self.store
            .active_generation()
            .ok()
            .flatten()
            .and_then(|g| g.packages.get(pkg).map(|p| p.revision))
    }

    fn stage_inbox(&self, manifest: &PackageManifest) {
        let inbox = crate::pkg_manifest::manifest_path(self.store.root(), &manifest.name);
        std::fs::create_dir_all(inbox.parent().unwrap()).unwrap();
        std::fs::write(&inbox, serde_json::to_vec_pretty(manifest).unwrap()).unwrap();
    }

    /// Seed an active generation 1 with `pkg` installed at
    /// `revision` (the freshness gate's input).
    fn seed_installed(&self, pkg: &str, revision: u32) {
        let installed = crate::runtime::InstalledPackage {
            name: pkg.to_string(),
            version: "1.0".to_string(),
            revision,
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
            meta_digest: None,
        };
        let gen = crate::runtime::Generation {
            n: 1,
            base_version: "test".to_string(),
            packages: BTreeMap::from([(pkg.to_string(), installed)]),
            created_epoch: 0,
            boot_entry: None,
        };
        let dir = self.store.generation_dir(1);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("manifest.json"), serde_json::to_vec(&gen).unwrap()).unwrap();
        #[cfg(target_os = "linux")]
        std::os::unix::fs::symlink(&dir, self.store.root().join("active")).unwrap();
    }
}

fn peer_ref() -> PullRef {
    PullRef::parse("nau://peer.test:7780/hello").unwrap()
}

// ── Pure: the downgrade decision ──

fn static_ref() -> PullRef {
    PullRef::parse("http://mirror.test:9000/mirror/hello").unwrap()
}

fn manifest_route() -> String {
    "http://mirror.test:9000/mirror/manifests/hello.json".to_string()
}

fn blob_route(sha: &str) -> String {
    format!("http://mirror.test:9000/mirror/blobs/{sha}")
}

fn index_route() -> String {
    "http://mirror.test:9000/mirror/index.json".to_string()
}

/// A minimal index.json carrying the given rows (name, version,
/// revision).
fn index_json(rows: &[(&str, &str, u32)]) -> Vec<u8> {
    let packages: Vec<serde_json::Value> = rows
            .iter()
            .map(|(name, version, revision)| {
                serde_json::json!({ "name": name, "version": version, "revision": revision })
            })
            .collect();
    serde_json::to_vec(&serde_json::json!({ "name": "mirror.test", "packages": packages })).unwrap()
}

/// The index.json that agrees with `pkg` (same version/revision).
fn agreeing_index(pkg: &PackageManifest) -> Vec<u8> {
    index_json(&[(pkg.name.as_str(), pkg.version.as_str(), pkg.revision)])
}

/// A static-tree transport for `pkg`: manifest + blob routes, plus
/// the tree index when `index` is `Some` (a test passes `None` to
/// model a tree that cannot serve index.json at all).
fn static_fetch(
    pkg: &PackageManifest,
    blobs: &[(&str, Vec<u8>)],
    index: Option<Vec<u8>>,
) -> FakeFetch {
    let mut routes = BTreeMap::new();
    routes.insert(manifest_route(), manifest_source(pkg));
    for (sha, bytes) in blobs {
        routes.insert(blob_route(sha), bytes.clone());
    }
    if let Some(index) = index {
        routes.insert(index_route(), index);
    }
    FakeFetch { routes }
}

mod downgrade_is;
mod staged_inbox;
