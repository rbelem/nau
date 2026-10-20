use super::*;
use nau_core::manifest_ir::ImageManifest;
use std::collections::BTreeMap;

const T0: i64 = 1_700_000_000;
const DAY: i64 = 86_400;

use ed25519_dalek::SigningKey;
use pgp::composed::SignedPublicKey;
use std::path::PathBuf;

/// Per-crate copy (ADR-0053 ruling 6): the crate-side suite owns the
/// original; the root ceremony tests stage keys through the same
/// shape.
fn temp_keypair() -> (tempfile::TempDir, KeyPair) {
    let home = tempfile::tempdir().unwrap();
    let kp = create_secret_key(home.path()).unwrap();
    (home, kp)
}

/// A minimal eval manifest (per-crate copy, ADR-0053 ruling 6 — the
/// crate-side suite owns the original).
fn minimal_manifest() -> ImageManifest {
    ImageManifest {
        manifest_version: nau_core::manifest_ir::MANIFEST_VERSION,
        inputs: BTreeMap::new(),
        outputs: BTreeMap::new(),
        images: BTreeMap::new(),
        signatures: BTreeMap::new(),
    }
}

fn chain_with(dir: &std::path::Path, kps: &[&KeyPair]) -> Keychain {
    for kp in kps {
        install_public_key(kp, dir).unwrap();
    }
    Keychain::load_dir(dir).unwrap()
}

fn manifest_with_github_input() -> ImageManifest {
    let declared = std::collections::HashMap::from([(
        "pkgs".to_string(),
        crate::snap::PackageInput {
            url: "github:owner/repo/main".into(),
            submodules: None,
        },
    )]);
    let mut lockfile = crate::lock::LockFile {
        version: 1,
        sources: std::collections::HashMap::new(),
        snaps: std::collections::HashMap::new(),
        inputs: std::collections::HashMap::new(),
        packages: std::collections::HashMap::new(),
        build_deps: std::collections::HashMap::new(),
    };
    lockfile.inputs.insert(
        "pkgs".into(),
        crate::lock::InputLockEntry {
            revision: Some("c0ffee".into()),
            sha256: Some("beef".into()),
            local: false,
            submodules: None,
        },
    );
    crate::manifest::build_manifest(
        &crate::lua::Outputs::new(),
        &std::collections::HashMap::new(),
        &declared,
        &lockfile,
        "amd64",
        "latest/stable",
        None,
    )
    .unwrap()
}

/// Deterministic keypair so the golden envelope test is stable.
fn fixed_kp() -> KeyPair {
    let seed = [0x42u8; 32];
    let signing = SigningKey::from_bytes(&seed);
    KeyPair {
        seed,
        public: signing.verifying_key().to_bytes(),
    }
}

/// Flip one provenance field inside the stored entry and write it
/// back — the tamper an attacker (or a lying signer) produces.
fn tamper_provenance(manifest: &mut ImageManifest, key_id: &str) {
    let mut entry: SignatureEntry =
        serde_json::from_value(manifest.signatures[key_id].clone()).unwrap();
    match &mut entry {
        SignatureEntry::Attested { provenance, .. } => {
            provenance.as_mut().unwrap().builder_id = "nau:0.0.0-lies".into();
        }
        SignatureEntry::Bare(_) => panic!("expected an attested entry"),
    }
    manifest
        .signatures
        .insert(key_id.to_string(), serde_json::to_value(&entry).unwrap());
}

fn sysupdate_sums() -> Vec<u8> {
    b"1111...  nau-cassini-1.0.0-amd64.img\n\
          2222...  nau-cassini-1.0.0-amd64.manifest.json\n"
        .to_vec()
}

fn with_source_date_epoch<T>(secs: u64, f: impl FnOnce() -> T) -> T {
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _held = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prior = std::env::var("SOURCE_DATE_EPOCH").ok();
    std::env::set_var("SOURCE_DATE_EPOCH", secs.to_string());
    let out = f();
    match prior {
        Some(v) => std::env::set_var("SOURCE_DATE_EPOCH", v),
        None => std::env::remove_var("SOURCE_DATE_EPOCH"),
    }
    out
}

/// The parsed members of a pubring blob: (fingerprint, Ed25519 public
/// bytes) per transferable key, refusing on anything unparsable.
fn pubring_members(pubring: &[u8]) -> Vec<[u8; 32]> {
    use pgp::composed::PublicOrSecret;
    use pgp::types::{EddsaLegacyPublicParams, KeyDetails, PublicParams};
    PublicOrSecret::from_bytes_many(std::io::Cursor::new(pubring))
        .unwrap()
        .map(|k| k.unwrap())
        .map(|k| match k {
            PublicOrSecret::Public(tpk) => match tpk.primary_key.public_params() {
                PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 { key }) => {
                    *key.as_bytes()
                }
                other => panic!("non-Ed25519 member: {other:?}"),
            },
            PublicOrSecret::Secret(_) => panic!("secret key in a device pubring"),
        })
        .collect()
}

/// Drive the real ceremony to the POST-PROMOTION overlap state: `old`
/// created and anchored (as `key keygen` does), successor minted
/// (fragments persisted), successor promoted (active; old anchor left
/// standing). Returns the temp home (keep alive!), the keys dir, and
/// both keys.
fn promoted_overlap_fixture() -> (tempfile::TempDir, PathBuf, KeyPair, KeyPair) {
    let home = tempfile::tempdir().unwrap();
    let old = create_secret_key(home.path()).unwrap();
    let dir = keys_dir(home.path());
    install_public_key(&old, &dir).unwrap();
    let successor = mint_rotation_key(home.path()).unwrap();
    promote_rotation_key(home.path(), &dir).unwrap();
    (home, dir, old, successor)
}

fn openpgp_public(kp: &KeyPair) -> [u8; 32] {
    kp.public
}

mod full_lifecycle;
mod sysupdate_manifest;
