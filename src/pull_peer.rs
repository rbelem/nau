//! Peer and static-lane `pull` (ADR-0033 Decisions 5, 7, 10) — the
//! ROOT-side command glue (issue #326 PR 4): the transport lane itself
//! (fetch, trust walk, tree-index gate, staging) moved to `nau-ship`
//! (`nau_ship::pull_peer`, re-exported below). This module keeps what
//! rides the pod boundary: the pod-store resolution (`run`), the
//! operator keychain location, the report printing, and the lane's
//! tests — whose fixtures drive the REAL runtime store
//! (`RuntimeStore`/`Generation`), which never enters the ship crate.

use std::path::PathBuf;

pub use nau_ship::pull_peer::*;

use crate::pod;
use crate::pull_ref::PullRef;

/// The operator's keychain dir (`~/.config/nau/keys`, HOME resolved —
/// `.` when unreadable, matching `crate::sign::keys_dir`).
fn operator_keys_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    nau_core::sign::keys_dir(&PathBuf::from(home))
}

/// Run a peer or static pull for `source` into the named pod (`None` =
/// the default pod). `allow_downgrade` lifts the freshness rule's
/// older-revision refusal (ADR-0033 Decision 7). Trust anchors come
/// from the device image (`/etc/nau/update-key.pub` — the runtime
/// anchor) AND the operator keychain. Verifies and stages;
/// installation stays the pod workflow.
///
/// Root-side because it resolves the pod's runtime store: the freshness
/// gate's installed-revision input is read HERE (the ship crate takes
/// it as a parameter — its `BlobStore` view cannot see generations).
pub fn run(source: &PullRef, pod: Option<&str>, allow_downgrade: bool) -> miette::Result<()> {
    let store = pod::resolve_pod_store(pod)?;
    let keys = operator_keys_dir();
    let anchor = PathBuf::from(crate::runtime::DEVICE_ANCHOR);
    let pkg = pkg_name(source)?.to_string();
    let installed = store
        .active_generation()?
        .and_then(|g| g.packages.get(&pkg).map(|p| p.revision));
    let blob_store = store.blob_store();
    let report = pull_into_store(
        &blob_store,
        installed,
        source,
        &anchor,
        &keys,
        allow_downgrade,
        &CurlFetch,
    )?;
    print_report(&report);
    Ok(())
}

/// JSON when `--json` set the global mode; a human summary otherwise.
fn print_report(report: &PullPeerReport) {
    if crate::output::is_json() {
        println!(
            "{}",
            serde_json::to_string_pretty(report).unwrap_or_default()
        );
        return;
    }
    crate::output::ok(format!(
        "staged {} {} revision {} from {} {} — signature verified (key {})",
        report.package,
        report.version,
        report.revision,
        report.lane,
        report.reference,
        report.signer
    ));
    crate::output::info(format!(
        "blobs: {} fetched, {} already in store",
        report.fetched.len(),
        report.already_present.len()
    ));
    crate::output::info(format!(
        "manifest staged at {} — install stays the pod workflow",
        report.staged_manifest
    ));
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn downgrade_is_refused_naming_both_revisions() {
        let err = check_downgrade(Some(9), 5, false).expect_err("newer installed must refuse");
        let msg = err.to_string();
        assert!(msg.contains('9') && msg.contains('5'), "names both: {msg}");
        assert!(msg.contains("--allow-downgrade"), "names the escape: {msg}");
    }

    #[test]
    fn downgrade_allowed_only_when_explicit() {
        check_downgrade(Some(9), 5, true).expect("explicit --allow-downgrade lifts the rule");
        check_downgrade(Some(7), 7, false).expect("equal revision is not a downgrade");
        check_downgrade(Some(3), 7, false).expect("newer incoming is fine");
        check_downgrade(None, 1, false).expect("nothing installed — nothing to regress");
    }

    // ── Pure: URL mapping ──

    #[test]
    fn peer_urls_follow_the_wire_grammar() {
        let r = peer_ref();
        assert_eq!(
            manifest_url(&r, "hello").unwrap(),
            "http://peer.test:7780/manifests/hello"
        );
        assert_eq!(
            blob_url(&r, "hello", &"ab".repeat(32)).unwrap(),
            format!("http://peer.test:7780/blobs/{}", "ab".repeat(32))
        );
    }

    /// Bracketed IPv6 literals: the parsed host is the bare literal and
    /// the built URLs re-bracket it (an unbracketed `::1` in an http
    /// URL is not parseable by curl).
    #[test]
    fn bracketed_ipv6_references_map_to_bracketed_urls() {
        let r = PullRef::parse("nau://[::1]:7780/hello").unwrap();
        match &r {
            PullRef::Peer { host, port, pkg } => {
                assert_eq!(host, "::1");
                assert_eq!(*port, 7780);
                assert_eq!(pkg, "hello");
            }
            other => panic!("expected Peer, got {other:?}"),
        }
        let default = PullRef::parse("nau://[::1]/hello").unwrap();
        match &default {
            PullRef::Peer { host, port, .. } => {
                assert_eq!(host, "::1");
                assert_eq!(*port, crate::pull_ref::DEFAULT_PEER_PORT);
            }
            other => panic!("expected Peer, got {other:?}"),
        }
        assert_eq!(
            manifest_url(&default, "hello").unwrap(),
            "http://[::1]:7780/manifests/hello"
        );
        assert_eq!(reference_string(&r), "nau://[::1]:7780/hello");
    }

    #[test]
    fn static_urls_derive_the_export_tree_dir() {
        let r = PullRef::parse("http://mirror.test:9000/mirror/vim").unwrap();
        assert_eq!(
            manifest_url(&r, "vim").unwrap(),
            "http://mirror.test:9000/mirror/manifests/vim.json"
        );
        assert_eq!(
            blob_url(&r, "vim", &"cd".repeat(32)).unwrap(),
            format!("http://mirror.test:9000/mirror/blobs/{}", "cd".repeat(32))
        );
        let nested = PullRef::parse("https://mirror.example/nau/ghi").unwrap();
        assert_eq!(
            manifest_url(&nested, "ghi").unwrap(),
            "https://mirror.example/nau/manifests/ghi.json"
        );
    }

    // ── Integration: the staged pipeline over a fake transport ──

    #[test]
    fn happy_path_stages_manifest_and_blob_then_dedups() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp);
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);

        let report = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect("a signed, fresh manifest stages");
        assert_eq!(report.fetched.len(), 1);
        assert_eq!(report.already_present.len(), 0);
        assert_eq!(report.signer, kp.key_id());
        assert_eq!(report.lane, "peer");
        assert_eq!(report.manifest_digest, sha256_hex(manifest_source(&pkg)));
        assert!(fx.store.blob_path(&blob_sha()).exists(), "blob landed");
        let inbox = crate::pkg_manifest::manifest_path(fx.store.root(), "hello");
        assert!(inbox.exists(), "manifest staged in the inbox");
        let round: PackageManifest =
            serde_json::from_slice(&std::fs::read(&inbox).unwrap()).unwrap();
        assert_eq!(round, pkg);

        // Re-pull: the blob is already present (re-verified, skipped).
        let again = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect("re-pull dedups");
        assert_eq!(again.fetched.len(), 0);
        assert_eq!(again.already_present.len(), 1);
    }

    /// The staging inbox is single-file-per-package
    /// ([`crate::pkg_manifest::manifest_path`]): staging revision N
    /// OVERWRITES the same package's older entry — that overwrite IS
    /// the same-package sweep the ADR approved (ADR-0033 Decision 5).
    #[test]
    fn restaging_a_newer_revision_overwrites_the_inbox_entry() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);

        let older = signed_manifest(&kp); // revision 7
        let fetch_old = FakeFetch::peer(&manifest_source(&older), &[(&blob_sha(), blob_bytes())]);
        pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch_old,
        )
        .expect("revision 7 stages");

        let mut newer = signed_manifest(&kp);
        newer.revision = 9;
        crate::pkg_manifest::sign(&mut newer, &kp).unwrap();
        let fetch_new = FakeFetch::peer(&manifest_source(&newer), &[(&blob_sha(), blob_bytes())]);
        pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch_new,
        )
        .expect("revision 9 stages");

        let inbox = crate::pkg_manifest::manifest_path(fx.store.root(), "hello");
        let staged: PackageManifest =
            serde_json::from_slice(&std::fs::read(&inbox).unwrap()).unwrap();
        assert_eq!(staged.revision, 9, "the newer revision owns the file");

        let siblings: Vec<String> = std::fs::read_dir(inbox.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            siblings,
            vec!["hello.json".to_string()],
            "no sibling inbox entries may appear"
        );
    }

    #[test]
    fn tampered_blob_is_refused_naming_expected_and_actual() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp);
        let evil = b"tampered-payload!!".to_vec();
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), evil)]);

        let err = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("a flipped blob must be refused");
        let msg = err.to_string();
        assert!(msg.contains(&blob_sha()), "names expected: {msg}");
        assert!(
            msg.contains(&sha256_hex(b"tampered-payload!!")),
            "names actual: {msg}"
        );
        assert!(!fx.store.blob_path(&blob_sha()).exists(), "nothing staged");
    }

    #[test]
    fn corrupt_preexisting_store_blob_is_refused() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp);
        let dest = fx.store.blob_path(&blob_sha());
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::write(&dest, b"bitrot").unwrap();
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[]);

        let err = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("corrupt store content must refuse");
        assert!(err.to_string().contains("corrupt"), "{err}");
    }

    #[test]
    fn wrong_key_manifest_is_refused_naming_the_key() {
        let trusted = test_kp(1);
        let impostor = test_kp(2);
        let fx = Fixture::with_trust(&trusted);
        let pkg = signed_manifest(&impostor);
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);

        let err = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("an untrusted signer must be refused");
        let msg = err.to_string();
        assert!(msg.contains(&impostor.key_id()), "names the key: {msg}");
        assert!(msg.contains("TOFU") || msg.contains("never"), "{msg}");
    }

    #[test]
    fn revoked_key_manifest_is_refused_via_the_revocation_list() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        fx.list_operator_revoked(&kp.key_id());
        let pkg = signed_manifest(&kp);
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);

        let err = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("a revoked signer must be refused");
        let msg = err.to_string();
        assert!(msg.contains("REVOKED"), "{msg}");
        assert!(msg.contains(&kp.key_id()), "names the key: {msg}");
    }

    /// The union rule: a key the DEVICE image revokes is refused even
    /// though the operator keychain still trusts it — either list is
    /// sufficient, neither can mask the other.
    #[test]
    fn device_revocation_refuses_even_when_the_operator_keychain_trusts() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp); // operator keychain HAS kp
        fx.list_device_revoked(&kp.key_id()); // device list revokes it
        let pkg = signed_manifest(&kp);
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);

        let err = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("a device-revoked signer must be refused");
        let msg = err.to_string();
        assert!(msg.contains("REVOKED"), "{msg}");
        assert!(msg.contains(&kp.key_id()), "names the key: {msg}");
    }

    /// The device image-baked anchor set verifies a manifest on its
    /// own: an empty operator keychain is not a refusal when the image
    /// anchors carry the key (Decision 7 consults BOTH sources).
    #[test]
    fn device_image_anchor_verifies_with_an_empty_operator_keychain() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        fx.clear_operator_keychain();
        fx.install_device_anchor(&kp);
        let pkg = signed_manifest(&kp);
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);

        let report = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect("the image-baked anchor verifies without operator keys");
        assert_eq!(report.signer, kp.key_id());
    }

    /// Nothing anchored anywhere — empty device set, empty keychain —
    /// is a named fail-closed refusal.
    #[test]
    fn no_anchors_anywhere_fails_closed_naming_both_sources() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        fx.clear_operator_keychain();
        let pkg = signed_manifest(&kp);
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);

        let err = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("an empty trust chain must fail closed");
        let msg = err.to_string();
        assert!(msg.contains("fail closed"), "{msg}");
        assert!(
            msg.contains(
                &fx.anchor_dir
                    .join("trusted-keys")
                    .to_string_lossy()
                    .to_string()
            ),
            "names the device anchors: {msg}"
        );
        assert!(
            msg.contains(&fx.keys.to_string_lossy().to_string()),
            "names the keychain: {msg}"
        );
    }

    #[test]
    fn unsigned_manifest_is_refused() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let mut pkg = signed_manifest(&kp);
        pkg.signature.clear();
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);

        assert!(
            pull_into_store(
                &fx.blobs(),
                fx.installed("hello"),
                &peer_ref(),
                &fx.anchor,
                &fx.keys,
                false,
                &fetch
            )
            .is_err(),
            "an unsigned manifest never stages"
        );
    }

    #[test]
    fn empty_keychain_fails_closed() {
        let kp = test_kp(1);
        let store_dir = tempfile::tempdir().unwrap();
        let keys_dir = tempfile::tempdir().unwrap(); // exists, but no anchors
        let anchor_dir = tempfile::tempdir().unwrap();
        let anchor = anchor_dir.path().join("update-key.pub");
        let fx_store = RuntimeStore::new(store_dir.path().to_path_buf());
        let pkg = signed_manifest(&kp);
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);

        let err = pull_into_store(
            &fx_store.blob_store(),
            None,
            &peer_ref(),
            &anchor,
            keys_dir.path(),
            false,
            &fetch,
        )
        .expect_err("an empty trust chain must fail closed");
        assert!(err.to_string().contains("fail closed"), "{err}");
    }

    #[test]
    fn downgrade_gate_reads_the_pod_generation() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        fx.seed_installed("hello", 9);
        let mut pkg = signed_manifest(&kp);
        pkg.revision = 5;
        crate::pkg_manifest::sign(&mut pkg, &kp).unwrap();
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);

        let err = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("revision 5 over installed 9 is a downgrade");
        let msg = err.to_string();
        assert!(msg.contains('9') && msg.contains('5'), "{msg}");

        pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            true,
            &fetch,
        )
        .expect("--allow-downgrade lifts the gate");
    }

    #[test]
    fn newer_and_equal_revisions_pass_the_gate() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        fx.seed_installed("hello", 7);
        let pkg = signed_manifest(&kp); // revision 7 == installed
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);
        pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect("equal revision is not a downgrade");
    }

    /// The gate reads the max of installed and STAGED revisions: a
    /// newer manifest sitting in the pull inbox blocks an older,
    /// validly-signed incoming one unless `--allow-downgrade` says
    /// otherwise — without this, a peer could silently walk a staged
    /// revision back.
    #[test]
    fn staged_inbox_revision_gates_the_downgrade_too() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);

        let mut staged = signed_manifest(&kp); // revision 7
        staged.revision = 9;
        crate::pkg_manifest::sign(&mut staged, &kp).unwrap();
        fx.stage_inbox(&staged);

        let older = signed_manifest(&kp); // revision 7, validly signed
        let fetch = FakeFetch::peer(&manifest_source(&older), &[(&blob_sha(), blob_bytes())]);

        let err = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("revision 7 over staged 9 is a downgrade");
        let msg = err.to_string();
        assert!(msg.contains('9') && msg.contains('7'), "{msg}");

        pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            true,
            &fetch,
        )
        .expect("--allow-downgrade lifts the staged gate too");
    }

    /// A manifest built for another GNU triplet is refused before any
    /// blob downloads — the fetch carries no blob routes, so reaching
    /// the target error proves the download never started.
    #[test]
    fn foreign_target_manifest_is_refused_before_any_download() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let mut pkg = signed_manifest(&kp);
        pkg.target = "mips64-unknown-linux-gnu".to_string();
        crate::pkg_manifest::sign(&mut pkg, &kp).unwrap();
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[]);

        let err = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("a foreign-target manifest must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("mips64-unknown-linux-gnu"),
            "names the manifest target: {msg}"
        );
        assert!(
            msg.contains(&crate::pkg_manifest::host_target()),
            "names the host target: {msg}"
        );
        assert!(
            !fx.store.blob_path(&blob_sha()).exists(),
            "nothing staged for a foreign target"
        );
    }

    /// Boundary validation of the declared payload paths (defense for
    /// the future install-from-inbox consumer): absolute paths and
    /// `..` segments are refused, naming the file.
    #[test]
    fn unsafe_payload_paths_are_refused_before_any_download() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        for bad in ["/etc/passwd", "../../etc/passwd", "usr/../../etc/passwd"] {
            let mut pkg = signed_manifest(&kp);
            pkg.files[0].path = bad.to_string();
            crate::pkg_manifest::sign(&mut pkg, &kp).unwrap();
            let fetch = FakeFetch::peer(&manifest_source(&pkg), &[]);

            let err = pull_into_store(
                &fx.blobs(),
                fx.installed("hello"),
                &peer_ref(),
                &fx.anchor,
                &fx.keys,
                false,
                &fetch,
            )
            .expect_err("an unsafe payload path must be refused");
            let msg = err.to_string();
            assert!(msg.contains("unsafe path"), "names the rule: {msg}");
            assert!(msg.contains(bad), "names the file: {msg}");
            assert!(
                !fx.store.blob_path(&blob_sha()).exists(),
                "nothing staged for an unsafe path"
            );
        }
    }

    // ── Static-tree fixtures (Decision 10: index + manifest + blobs) ──

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
        serde_json::to_vec(&serde_json::json!({ "name": "mirror.test", "packages": packages }))
            .unwrap()
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

    #[test]
    fn static_lane_stages_through_the_same_pipeline() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp);
        let fetch = static_fetch(
            &pkg,
            &[(&blob_sha(), blob_bytes())],
            Some(agreeing_index(&pkg)),
        );

        let report = pull_into_store(
            &fx.store.blob_store(),
            None,
            &static_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect("the static lane shares the peer verification path");
        assert_eq!(report.lane, "static");
        assert!(fx.store.blob_path(&blob_sha()).exists());
        assert!(
            crate::pkg_manifest::manifest_path(fx.store.root(), "hello").exists(),
            "the verified manifest staged"
        );
    }

    /// A corrupted blob served by the public tree is refused at the
    /// hash gate: the mirror is untrusted infrastructure, so every
    /// byte is re-hashed against the signed manifest (the same gate
    /// the peer lane exercises in
    /// `tampered_blob_is_refused_naming_expected_and_actual`).
    #[test]
    fn static_lane_corrupted_blob_fails_closed_naming_expected_and_actual() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp);
        let evil = b"mirror-supplied-bytes!!".to_vec();
        let fetch = static_fetch(&pkg, &[(&blob_sha(), evil)], Some(agreeing_index(&pkg)));

        let err = pull_into_store(
            &fx.store.blob_store(),
            None,
            &static_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("a corrupted blob from the tree must refuse");
        let msg = err.to_string();
        assert!(msg.contains(&blob_sha()), "names expected: {msg}");
        assert!(
            msg.contains(&sha256_hex(b"mirror-supplied-bytes!!")),
            "names actual: {msg}"
        );
        assert!(!fx.store.blob_path(&blob_sha()).exists(), "nothing staged");
        assert!(
            !crate::pkg_manifest::manifest_path(fx.store.root(), "hello").exists(),
            "the manifest never stages when a blob fails"
        );
    }

    /// A tampered index.json — the revision walked back — refuses the
    /// pull: the signed manifest is the authority and the tree's own
    /// index must agree with it (Decision 10 end-to-end).
    #[test]
    fn tampered_index_revision_fails_closed_naming_both_sides() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp); // revision 7
        let index = index_json(&[("hello", "2.10", 6)]); // tampered down
        let fetch = static_fetch(&pkg, &[(&blob_sha(), blob_bytes())], Some(index));

        let err = pull_into_store(
            &fx.store.blob_store(),
            None,
            &static_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("an index/manifest revision divergence must refuse");
        let msg = err.to_string();
        assert!(msg.contains("rev 6") && msg.contains("rev 7"), "{msg}");
        assert!(msg.contains("divergence"), "{msg}");
        assert!(!fx.store.blob_path(&blob_sha()).exists(), "nothing staged");
        assert!(
            !crate::pkg_manifest::manifest_path(fx.store.root(), "hello").exists(),
            "nothing staged"
        );
    }

    /// The index gate is a consistency gate, not the freshness policy:
    /// `--allow-downgrade` cannot pull from a tree whose index diverges
    /// from its own signed manifest.
    #[test]
    fn tampered_index_refuses_even_with_allow_downgrade() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp);
        let index = index_json(&[("hello", "2.10", 6)]);
        let fetch = static_fetch(&pkg, &[(&blob_sha(), blob_bytes())], Some(index));

        assert!(
            pull_into_store(
                &fx.store.blob_store(),
                fx.installed("hello"),
                &static_ref(),
                &fx.anchor,
                &fx.keys,
                true,
                &fetch
            )
            .is_err(),
            "allow-downgrade must not lift the index gate"
        );
    }

    #[test]
    fn tampered_index_version_fails_closed_naming_both_versions() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp); // version 2.10
        let index = index_json(&[("hello", "9.9", 7)]); // tampered version
        let fetch = static_fetch(&pkg, &[(&blob_sha(), blob_bytes())], Some(index));

        let err = pull_into_store(
            &fx.store.blob_store(),
            None,
            &static_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("an index/manifest version divergence must refuse");
        let msg = err.to_string();
        assert!(msg.contains("9.9") && msg.contains("2.10"), "{msg}");
        assert!(!fx.store.blob_path(&blob_sha()).exists(), "nothing staged");
    }

    /// An index that drops the package (the mirror "unlisting" content
    /// whose manifest still serves) diverges → refuse.
    #[test]
    fn index_missing_the_package_fails_closed() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp);
        let index = index_json(&[("other", "1.0", 1)]);
        let fetch = static_fetch(&pkg, &[(&blob_sha(), blob_bytes())], Some(index));

        let err = pull_into_store(
            &fx.store.blob_store(),
            None,
            &static_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("a missing index row must refuse");
        let msg = err.to_string();
        assert!(msg.contains("does not list"), "{msg}");
        assert!(msg.contains("hello"), "{msg}");
        assert!(!fx.store.blob_path(&blob_sha()).exists(), "nothing staged");
    }

    /// A mirror fronted by an error page answering 200 with HTML: the
    /// index does not parse, so the pull refuses instead of trusting a
    /// tree that cannot describe itself.
    #[test]
    fn unparseable_index_fails_closed_naming_the_url() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp);
        let fetch = static_fetch(
            &pkg,
            &[(&blob_sha(), blob_bytes())],
            Some(b"<html>502 Bad Gateway</html>".to_vec()),
        );

        let err = pull_into_store(
            &fx.store.blob_store(),
            None,
            &static_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("a non-JSON index must refuse");
        let msg = err.to_string();
        assert!(msg.contains("not a valid index.json"), "{msg}");
        assert!(msg.contains(index_route().as_str()), "{msg}");
        assert!(!fx.store.blob_path(&blob_sha()).exists(), "nothing staged");
    }

    /// The gate is not optional: a static tree that cannot serve
    /// index.json at all (a 404 becomes a fetch error through the curl
    /// seam) refuses the pull.
    #[test]
    fn static_pull_without_a_served_index_fails_closed() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp);
        let fetch = static_fetch(&pkg, &[(&blob_sha(), blob_bytes())], None);

        let err = pull_into_store(
            &fx.store.blob_store(),
            None,
            &static_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("a tree with no index must refuse");
        assert!(err.to_string().contains("fetching the tree index"), "{err}");
    }

    /// Manifest-layer fail-closed at the pull surface: flipping a byte
    /// of a signed manifest's body invalidates the signature → refused
    /// before any download (the fetch carries no blob routes — reaching
    /// the trust error proves nothing was fetched, nothing staged).
    #[test]
    fn tampered_manifest_body_fails_closed_before_any_download() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let mut pkg = signed_manifest(&kp);
        pkg.files[0].sha256 = "ee".repeat(32); // tampered AFTER signing
        let fetch = static_fetch(&pkg, &[], Some(agreeing_index(&pkg)));

        let err = pull_into_store(
            &fx.store.blob_store(),
            None,
            &static_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("a tampered manifest body must refuse");
        let msg = err.to_string();
        assert!(msg.contains("no trusted anchor"), "{msg}");
        assert!(
            !fx.store.blob_path(&"ee".repeat(32)).exists(),
            "nothing staged"
        );
        assert!(
            !crate::pkg_manifest::manifest_path(fx.store.root(), "hello").exists(),
            "nothing staged"
        );
    }

    #[test]
    fn malformed_declared_sha_is_refused_before_any_download() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let mut pkg = signed_manifest(&kp);
        pkg.files[0].sha256 = "../../etc/passwd".to_string();
        crate::pkg_manifest::sign(&mut pkg, &kp).unwrap();
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[]);

        let err = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("a non-hex blob address must be refused");
        assert!(err.to_string().contains("64 lowercase hex"), "{err}");
        // The manifest route existed but NO blob route did — reaching
        // the sha error proves the refusal happened before any fetch.
        assert!(!fx.store.blob_path(&pkg.files[0].sha256).exists());
    }

    #[test]
    fn manifest_name_must_match_the_reference() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let mut pkg = signed_manifest(&kp);
        pkg.name = "other".to_string();
        crate::pkg_manifest::sign(&mut pkg, &kp).unwrap();
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[]);

        let err = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("a manifest naming another package must refuse");
        assert!(err.to_string().contains("'other'"), "{err}");
    }

    // ── One real loopback curl test (bounded, local socket only) ──

    #[test]
    fn curl_fetch_speaks_http_to_a_loopback_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().unwrap().port();
        let body = b"loopback-blob".to_vec();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("one connection");
            let mut buf = [0u8; 2048];
            let _ = sock.read(&mut buf); // the request line; not parsed
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            sock.write_all(head.as_bytes()).unwrap();
            sock.write_all(&body).unwrap();
        });
        let got = CurlFetch
            .get(&format!(
                "http://127.0.0.1:{port}/blobs/{}",
                "aa".repeat(32)
            ))
            .expect("curl fetches from the loopback server");
        server.join().unwrap();
        assert_eq!(got, b"loopback-blob");
    }
}
