//! Peer and static-lane `pull` (ADR-0033 Decisions 5, 7, 10): fetch a
//! signed [`crate::pkg_manifest::PackageManifest`] plus its missing
//! blobs from a `shuttle://` peer or an `http(s)://` export tree,
//! verify fail-closed (signature first against the trusted-key set,
//! then every blob hash), and stage into the named pod's store — the
//! pull-staging inbox (`crate::pkg_manifest::manifest_path`).
//! Installation stays the pod workflow, never a pull side effect.
//!
//! # Verification order (ADR-0033 Decision 7, fail-closed)
//!
//! 1. JSON parse of the fetched manifest.
//! 2. Signature: revocation check FIRST
//!    ([`crate::sign::reject_revoked`]), then the strict trust set —
//!    [`crate::pkg_manifest::verify`] is tried for every key loaded from
//!    the operator keychain ([`crate::sign::keys_dir`]). The ANY-anchor
//!    shortcut [`crate::sign::verify_keychain`] is NEVER used on this
//!    path: an unverified manifest is refused and named, never
//!    provisionally accepted, never TOFU.
//! 3. Freshness gate: an installed revision newer than the incoming
//!    one is refused unless `--allow-downgrade`.
//! 4. Every manifest blob: present in the store → its sha256 is
//!    re-verified and the download skipped; absent → fetched, hashed,
//!    hard-refused on mismatch, written atomically.
//! 5. The verified manifest lands in the staging inbox.
//!
//! Transport is the repo's one network convention: curl behind
//! [`crate::command::CommandRunner`] (`src/oci.rs` precedent), with a
//! bounded `--max-time`/`--connect-timeout` on every transfer. Tests
//! inject a fake [`Fetch`].

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, WrapErr};
use serde::Serialize;

use crate::command::{exit_code, CommandRunner, RealRunner};
use crate::oci::{sha256_file, sha256_hex, BLOB_TIMEOUT_SECS, CONNECT_TIMEOUT_SECS};
use crate::pkg_manifest::{ManifestFile, PackageManifest};
use crate::pull_ref::PullRef;
use crate::runtime::RuntimeStore;

// ── Transport (curl behind the command seam, oci.rs precedent) ──

/// One HTTP GET over the sharing lanes' wire grammar (ADR-0033
/// Decision 4: `GET /manifests/<pkg>`, `GET /blobs/<sha256>`). The
/// prod impl shells out to curl; tests inject a fake.
pub trait Fetch {
    fn get(&self, url: &str) -> miette::Result<Vec<u8>>;
}

/// The production fetcher: curl behind [`CommandRunner`]. `-f` fails
/// closed on HTTP >= 400 (the oci.rs client avoids `-f` only because
/// its Bearer handshake must read the 401 body — these lanes do plain
/// unauthenticated GETs). Every transfer is bounded: `--connect-timeout`
/// and `--max-time` per the oci.rs timeouts.
pub struct CurlFetch;

impl Fetch for CurlFetch {
    fn get(&self, url: &str) -> miette::Result<Vec<u8>> {
        let argv = vec![
            "curl".into(),
            "-fsS".into(),
            "--connect-timeout".into(),
            CONNECT_TIMEOUT_SECS.to_string(),
            "--max-time".into(),
            BLOB_TIMEOUT_SECS.to_string(),
            url.to_string(),
        ];
        let out = RealRunner
            .run(&argv)
            .map_err(|e| miette::miette!("curl not found: {e}"))?;
        let code = exit_code(&out);
        if code != 0 {
            return Err(miette::miette!(
                "fetch of {url} failed (curl exit {code}{})",
                curl_failure_hint(code)
            ));
        }
        Ok(out.stdout)
    }
}

/// Named hints for the common curl exit codes (mirrors the oci.rs
/// `curl_failure_hint` idea, trimmed to this lane's plain-GET surface).
fn curl_failure_hint(code: i32) -> &'static str {
    match code {
        6 => " — could not resolve host",
        7 => " — connection refused",
        22 => " — HTTP status >= 400",
        28 => " — timed out (transfer is bounded)",
        _ => "",
    }
}

// ── URL mapping (Decision 4 peer grammar / Decision 10 export tree) ──

/// The manifest endpoint for `pkg`: `http://host:port/manifests/<pkg>`
/// from a peer; `<dir>/manifests/<pkg>.json` from a static tree.
fn manifest_url(source: &PullRef, pkg: &str) -> miette::Result<String> {
    match source {
        PullRef::Peer { host, port, .. } => Ok(format!("http://{host}:{port}/manifests/{pkg}")),
        PullRef::Url { url, .. } => {
            let dir = url_dir(url.as_str(), pkg)?;
            Ok(format!("{dir}/manifests/{pkg}.json"))
        }
        PullRef::Oci(_) => {
            miette::bail!("OCI references ride the registry lane, not the peer lane")
        }
    }
}

/// The blob endpoint for sha256 `hash`: `http://host:port/blobs/<hash>`
/// from a peer; `<dir>/blobs/<hash>` from a static tree.
fn blob_url(source: &PullRef, pkg: &str, hash: &str) -> miette::Result<String> {
    match source {
        PullRef::Peer { host, port, .. } => Ok(format!("http://{host}:{port}/blobs/{hash}")),
        PullRef::Url { url, .. } => {
            let dir = url_dir(url.as_str(), pkg)?;
            Ok(format!("{dir}/blobs/{hash}"))
        }
        PullRef::Oci(_) => {
            miette::bail!("OCI references ride the registry lane, not the peer lane")
        }
    }
}

/// The static tree's directory: the reference minus its final
/// `/<pkg>` segment. Parse guarantees the suffix, so failure here is
/// an internal error — still refused, never guessed.
fn url_dir<'a>(raw: &'a str, pkg: &str) -> miette::Result<&'a str> {
    raw.strip_suffix(&format!("/{pkg}"))
        .ok_or_else(|| miette::miette!("static reference '{raw}' does not end in /{pkg}"))
}

/// The reference as originally spelled (report label).
fn reference_string(source: &PullRef) -> String {
    match source {
        PullRef::Peer { host, port, pkg } => format!("shuttle://{host}:{port}/{pkg}"),
        PullRef::Url { url, .. } => url.as_str().to_string(),
        PullRef::Oci(_) => "oci".to_string(),
    }
}

fn lane_name(source: &PullRef) -> &'static str {
    match source {
        PullRef::Peer { .. } => "peer",
        PullRef::Url { .. } => "static",
        PullRef::Oci(_) => "oci",
    }
}

fn pkg_name(source: &PullRef) -> miette::Result<&str> {
    match source {
        PullRef::Peer { pkg, .. } | PullRef::Url { pkg, .. } => Ok(pkg),
        PullRef::Oci(_) => {
            miette::bail!("OCI references ride the registry lane, not the peer lane")
        }
    }
}

// ── Freshness gate (Decision 7) ──

/// The freshness rule: a manifest whose revision is OLDER than the
/// installed one for that name is refused unless `--allow-downgrade`
/// is explicit. Equal or newer revisions always pass; nothing
/// installed passes.
fn check_downgrade(
    installed: Option<u32>,
    incoming: u32,
    allow_downgrade: bool,
) -> miette::Result<()> {
    let Some(installed) = installed else {
        return Ok(());
    };
    if installed <= incoming || allow_downgrade {
        return Ok(());
    }
    miette::bail!(
        "package is installed at revision {installed}; the incoming manifest is revision \
         {incoming} — refusing downgrade (pass --allow-downgrade to accept it)"
    );
}

/// The installed revision of `pkg` from the pod's current generation
/// manifest — None when nothing is installed yet.
fn installed_revision(store: &RuntimeStore, pkg: &str) -> miette::Result<Option<u32>> {
    Ok(store
        .active_generation()?
        .and_then(|g| g.packages.get(pkg).map(|p| p.revision)))
}

// ── Trust (Decision 7: fail-closed, revoked-first, never TOFU) ──

/// Verify the manifest against the operator keychain at `keys_dir`.
/// Revoked-first (a signature under a revoked id is a hard refusal
/// even before trust is consulted), then the strict trust set: the
/// manifest must carry a signature from a key that is BOTH listed in
/// the keychain AND cryptographically valid over the canonical bytes.
/// Returns the key id that verified.
fn verify_trust(pkg_manifest: &PackageManifest, keys_dir: &Path) -> miette::Result<String> {
    let signatures = BTreeMap::from([(
        pkg_manifest.signer.clone(),
        serde_json::Value::String(pkg_manifest.signature.clone()),
    )]);
    let revoked = crate::sign::read_revoked_keys(keys_dir)?;
    crate::sign::reject_revoked(&signatures, &revoked)?;

    let chain = crate::sign::Keychain::load_dir(keys_dir)?;
    if chain.is_empty() {
        return Err(miette::miette!(
            "no trusted keys loaded from {} — refusing to verify the manifest for '{}' \
             (fail closed; anchors come from the key ceremony, never the wire)",
            keys_dir.display(),
            pkg_manifest.name
        ));
    }
    if !chain.key_ids().contains(&pkg_manifest.signer) {
        return Err(miette::miette!(
            "manifest for '{}' is signed by key id '{}' which is not in the trusted set \
             at {} — refusing (unverified manifests are never provisionally accepted, \
             never TOFU)",
            pkg_manifest.name,
            pkg_manifest.signer,
            keys_dir.display()
        ));
    }
    for (key_id, public) in chain.entries_for_verify() {
        let public_hex: String = public.iter().map(|b| format!("{b:02x}")).collect();
        if crate::pkg_manifest::verify(pkg_manifest, &public_hex).is_ok() {
            return Ok(key_id);
        }
    }
    Err(miette::miette!(
        "signature of the manifest for '{}' does not verify under trusted key '{}' — \
         refusing (the manifest may be tampered or the signature malformed)",
        pkg_manifest.name,
        pkg_manifest.signer
    ))
}

// ── Blob staging ──

/// A manifest's declared blob hash must be exactly 64 lowercase hex —
/// the same content-address discipline the store and the wire grammar
/// use; anything else is refused before it can reach a path.
fn validate_sha256(file: &ManifestFile) -> miette::Result<()> {
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

/// Write `bytes` to `dest` atomically: temp file beside the
/// destination, then rename — a crash never leaves a half-written
/// blob at its content address.
fn write_atomic(dest: &Path, bytes: &[u8]) -> miette::Result<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| miette::miette!("path {} has no parent directory", dest.display()))?;
    std::fs::create_dir_all(parent)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", parent.display()))?;
    let name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = parent.join(format!(".{}.{}.part", name, std::process::id()));
    std::fs::write(&tmp, bytes)
        .into_diagnostic()
        .wrap_err_with(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, dest)
        .into_diagnostic()
        .wrap_err_with(|| format!("renaming {} into {}", tmp.display(), dest.display()))?;
    Ok(())
}

/// Stage every manifest blob into the store: already-present blobs are
/// re-hashed and skipped (dedup is free — ADR-0012 content
/// addressing); missing ones are fetched, hash-checked (mismatch = a
/// named hard error), and written atomically. Returns
/// (fetched, already_present).
fn stage_blobs<F: Fetch>(
    store: &RuntimeStore,
    source: &PullRef,
    pkg: &str,
    files: &[ManifestFile],
    fetch: &F,
) -> miette::Result<(Vec<ManifestFile>, Vec<ManifestFile>)> {
    let mut fetched = Vec::new();
    let mut already = Vec::new();
    for file in files {
        let dest = store.blob_path(&file.sha256);
        if dest.exists() {
            let actual = sha256_file(&dest)?;
            if actual != file.sha256 {
                miette::bail!(
                    "existing store blob {} is corrupt: expected sha256 {}, found {}",
                    dest.display(),
                    file.sha256,
                    actual
                );
            }
            already.push(file.clone());
            continue;
        }
        let url = blob_url(source, pkg, &file.sha256)?;
        let body = fetch
            .get(&url)
            .wrap_err_with(|| format!("fetching blob for '{}' from {url}", file.path))?;
        let actual = sha256_hex(&body);
        if actual != file.sha256 {
            miette::bail!(
                "blob sha256 mismatch for '{}': expected {}, received {} — refusing \
                 (fetched from {url})",
                file.path,
                file.sha256,
                actual
            );
        }
        write_atomic(&dest, &body)?;
        fetched.push(file.clone());
    }
    Ok((fetched, already))
}

// ── Report (shape mirrors the OCI pull report) ──

/// One staged blob of a peer/static pull.
#[derive(Debug, Serialize)]
pub struct StagedBlob {
    /// The file's path within the installed payload tree.
    pub path: String,
    /// sha256 of the store blob.
    pub sha256: String,
}

/// `shuttle pull <peer|url> --json` payload — mirrors
/// [`crate::oci::PullReportJson`]'s shape (command/reference/digest +
/// per-file records) adapted to staging.
#[derive(Debug, Serialize)]
pub struct PullPeerReport {
    pub command: String,
    pub reference: String,
    /// Which sharing lane served the content: "peer" or "static".
    pub lane: &'static str,
    pub package: String,
    pub version: String,
    pub revision: u32,
    /// Key id the verified manifest was signed by.
    pub signer: String,
    /// sha256 of the received manifest bytes (the audit pin).
    pub manifest_digest: String,
    pub fetched: Vec<StagedBlob>,
    pub already_present: Vec<StagedBlob>,
    /// Where the verified manifest was staged (the pull inbox).
    pub staged_manifest: String,
}

// ── The pipeline ──

/// Resolve the target pod store from the `pod` param the way the pod
/// commands do: named pod under the resolved pod root, `default` when
/// None.
fn resolve_pod_store(pod: Option<&str>) -> miette::Result<RuntimeStore> {
    let name = pod.unwrap_or(crate::pod::DEFAULT_POD);
    crate::pod::validate_pod_name(name)?;
    let dir = crate::pod::pod_dir(&crate::pod::pod_root(None), name);
    Ok(crate::pod::pod_store(&dir))
}

/// The operator keychain directory (`~/.config/shuttle/keys/`).
fn operator_keys_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    crate::sign::keys_dir(&PathBuf::from(home))
}

/// Run a peer or static pull for `source` into the named pod (`None` =
/// the default pod). `allow_downgrade` lifts the freshness rule's
/// older-revision refusal (ADR-0033 Decision 7). Verifies and stages;
/// installation stays the pod workflow.
pub fn run(source: &PullRef, pod: Option<&str>, allow_downgrade: bool) -> miette::Result<()> {
    let store = resolve_pod_store(pod)?;
    let keys = operator_keys_dir();
    let report = pull_into_store(&store, source, &keys, allow_downgrade, &CurlFetch)?;
    print_report(&report);
    Ok(())
}

/// The lane body over an injected store root, keychain directory and
/// transport — the testable core of [`run`].
pub fn pull_into_store<F: Fetch>(
    store: &RuntimeStore,
    source: &PullRef,
    keys_dir: &Path,
    allow_downgrade: bool,
    fetch: &F,
) -> miette::Result<PullPeerReport> {
    let pkg = pkg_name(source)?.to_string();

    // 1. Fetch the manifest, 2. parse it, 3. verify fail-closed, 4.
    // gate freshness — all BEFORE any blob moves.
    let manifest_url = manifest_url(source, &pkg)?;
    let manifest_bytes = fetch
        .get(&manifest_url)
        .wrap_err_with(|| format!("fetching package manifest for '{pkg}' from {manifest_url}"))?;
    let manifest_digest = sha256_hex(&manifest_bytes);
    let manifest: PackageManifest = serde_json::from_slice(&manifest_bytes).map_err(|e| {
        miette::miette!("package manifest from {manifest_url} is not a valid PackageManifest: {e}")
    })?;
    if manifest.name != pkg {
        miette::bail!(
            "manifest from {manifest_url} names package '{}' but the reference asked for \
             '{pkg}' — refusing",
            manifest.name
        );
    }
    let signer = verify_trust(&manifest, keys_dir)?;
    let installed = installed_revision(store, &pkg)?;
    check_downgrade(installed, manifest.revision, allow_downgrade)?;

    for file in &manifest.files {
        validate_sha256(file)?;
    }

    // 5. Stage the blobs, 6. stage the verified manifest (the inbox —
    // staging only; installation is the pod workflow, ADR-0033
    // Decision 5).
    let (fetched, already) = stage_blobs(store, source, &pkg, &manifest.files, fetch)?;
    let inbox = crate::pkg_manifest::manifest_path(store.root(), &pkg);
    let json = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| miette::miette!("serializing verified manifest: {e}"))?;
    write_atomic(&inbox, &json)?;

    Ok(PullPeerReport {
        command: "pull".to_string(),
        reference: reference_string(source),
        lane: lane_name(source),
        package: manifest.name,
        version: manifest.version,
        revision: manifest.revision,
        signer,
        manifest_digest,
        fetched: to_staged(&fetched),
        already_present: to_staged(&already),
        staged_manifest: inbox.to_string_lossy().into_owned(),
    })
}

fn to_staged(files: &[ManifestFile]) -> Vec<StagedBlob> {
    files
        .iter()
        .map(|f| StagedBlob {
            path: f.path.clone(),
            sha256: f.sha256.clone(),
        })
        .collect()
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
    use std::io::{Read, Write};

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
        sha256_hex(&blob_bytes())
    }

    fn signed_manifest(kp: &crate::sign::KeyPair) -> PackageManifest {
        let mut pkg = PackageManifest {
            name: "hello".to_string(),
            version: "2.10".to_string(),
            revision: 7,
            target: "x86_64-linux-gnu".to_string(),
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

    /// A store in a tempdir with its operator keychain in a second
    /// tempdir. The trusted key set is [kp].
    struct Fixture {
        _store_dir: tempfile::TempDir,
        _keys_dir: tempfile::TempDir,
        store: RuntimeStore,
        keys: PathBuf,
    }

    impl Fixture {
        fn with_trust(kp: &crate::sign::KeyPair) -> Fixture {
            let store_dir = tempfile::tempdir().unwrap();
            let keys_dir = tempfile::tempdir().unwrap();
            crate::sign::install_public_key(kp, keys_dir.path()).unwrap();
            let store = RuntimeStore::new(store_dir.path().to_path_buf());
            let keys = keys_dir.path().to_path_buf();
            Fixture {
                _store_dir: store_dir,
                _keys_dir: keys_dir,
                store,
                keys,
            }
        }

        fn list_revoked(&self, key_id: &str) {
            std::fs::write(self.keys.join("revoked-keys"), format!("{key_id}\n")).unwrap();
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
        PullRef::parse("shuttle://peer.test:7780/hello").unwrap()
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
        let nested = PullRef::parse("https://mirror.example/shuttle/ghi").unwrap();
        assert_eq!(
            manifest_url(&nested, "ghi").unwrap(),
            "https://mirror.example/shuttle/manifests/ghi.json"
        );
    }

    // ── Integration: the staged pipeline over a fake transport ──

    #[test]
    fn happy_path_stages_manifest_and_blob_then_dedups() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp);
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);

        let report = pull_into_store(&fx.store, &peer_ref(), &fx.keys, false, &fetch)
            .expect("a signed, fresh manifest stages");
        assert_eq!(report.fetched.len(), 1);
        assert_eq!(report.already_present.len(), 0);
        assert_eq!(report.signer, kp.key_id());
        assert_eq!(report.lane, "peer");
        assert_eq!(report.manifest_digest, sha256_hex(&manifest_source(&pkg)));
        assert!(fx.store.blob_path(&blob_sha()).exists(), "blob landed");
        let inbox = crate::pkg_manifest::manifest_path(fx.store.root(), "hello");
        assert!(inbox.exists(), "manifest staged in the inbox");
        let round: PackageManifest =
            serde_json::from_slice(&std::fs::read(&inbox).unwrap()).unwrap();
        assert_eq!(round, pkg);

        // Re-pull: the blob is already present (re-verified, skipped).
        let again = pull_into_store(&fx.store, &peer_ref(), &fx.keys, false, &fetch)
            .expect("re-pull dedups");
        assert_eq!(again.fetched.len(), 0);
        assert_eq!(again.already_present.len(), 1);
    }

    #[test]
    fn tampered_blob_is_refused_naming_expected_and_actual() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp);
        let evil = b"tampered-payload!!".to_vec();
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), evil)]);

        let err = pull_into_store(&fx.store, &peer_ref(), &fx.keys, false, &fetch)
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

        let err = pull_into_store(&fx.store, &peer_ref(), &fx.keys, false, &fetch)
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

        let err = pull_into_store(&fx.store, &peer_ref(), &fx.keys, false, &fetch)
            .expect_err("an untrusted signer must be refused");
        let msg = err.to_string();
        assert!(msg.contains(&impostor.key_id()), "names the key: {msg}");
        assert!(msg.contains("TOFU") || msg.contains("never"), "{msg}");
    }

    #[test]
    fn revoked_key_manifest_is_refused_via_the_revocation_list() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        fx.list_revoked(&kp.key_id());
        let pkg = signed_manifest(&kp);
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);

        let err = pull_into_store(&fx.store, &peer_ref(), &fx.keys, false, &fetch)
            .expect_err("a revoked signer must be refused");
        let msg = err.to_string();
        assert!(msg.contains("REVOKED"), "{msg}");
        assert!(msg.contains(&kp.key_id()), "names the key: {msg}");
    }

    #[test]
    fn unsigned_manifest_is_refused() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let mut pkg = signed_manifest(&kp);
        pkg.signature.clear();
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);

        assert!(
            pull_into_store(&fx.store, &peer_ref(), &fx.keys, false, &fetch).is_err(),
            "an unsigned manifest never stages"
        );
    }

    #[test]
    fn empty_keychain_fails_closed() {
        let kp = test_kp(1);
        let store_dir = tempfile::tempdir().unwrap();
        let keys_dir = tempfile::tempdir().unwrap(); // exists, but no anchors
        let fx_store = RuntimeStore::new(store_dir.path().to_path_buf());
        let pkg = signed_manifest(&kp);
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);

        let err = pull_into_store(&fx_store, &peer_ref(), keys_dir.path(), false, &fetch)
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

        let err = pull_into_store(&fx.store, &peer_ref(), &fx.keys, false, &fetch)
            .expect_err("revision 5 over installed 9 is a downgrade");
        let msg = err.to_string();
        assert!(msg.contains('9') && msg.contains('5'), "{msg}");

        pull_into_store(&fx.store, &peer_ref(), &fx.keys, true, &fetch)
            .expect("--allow-downgrade lifts the gate");
    }

    #[test]
    fn newer_and_equal_revisions_pass_the_gate() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        fx.seed_installed("hello", 7);
        let pkg = signed_manifest(&kp); // revision 7 == installed
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);
        pull_into_store(&fx.store, &peer_ref(), &fx.keys, false, &fetch)
            .expect("equal revision is not a downgrade");
    }

    #[test]
    fn static_lane_stages_through_the_same_pipeline() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp);
        let mut routes = BTreeMap::new();
        routes.insert(
            "http://mirror.test:9000/mirror/manifests/hello.json".to_string(),
            manifest_source(&pkg),
        );
        routes.insert(
            format!("http://mirror.test:9000/mirror/blobs/{}", blob_sha()),
            blob_bytes(),
        );
        let fetch = FakeFetch { routes };
        let r = PullRef::parse("http://mirror.test:9000/mirror/hello").unwrap();

        let report = pull_into_store(&fx.store, &r, &fx.keys, false, &fetch)
            .expect("the static lane shares the peer verification path");
        assert_eq!(report.lane, "static");
        assert!(fx.store.blob_path(&blob_sha()).exists());
    }

    #[test]
    fn malformed_declared_sha_is_refused_before_any_download() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let mut pkg = signed_manifest(&kp);
        pkg.files[0].sha256 = "../../etc/passwd".to_string();
        crate::pkg_manifest::sign(&mut pkg, &kp).unwrap();
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[]);

        let err = pull_into_store(&fx.store, &peer_ref(), &fx.keys, false, &fetch)
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

        let err = pull_into_store(&fx.store, &peer_ref(), &fx.keys, false, &fetch)
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
