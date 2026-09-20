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
//! 2. Signature: revocation check FIRST over the UNION of the device
//!    image's revocation list and the operator keychain's
//!    ([`crate::sign::reject_revoked`]), then the strict trust set —
//!    [`crate::sign::verify_trust_set`] over the merged anchor set
//!    (device image-baked trusted-keys + legacy single anchor +
//!    operator keychain, the same walk
//!    [`crate::runtime`] does for channel manifests). The ANY-anchor
//!    shortcut [`crate::sign::verify_keychain`] alone is NEVER enough
//!    here: an unverified manifest is refused and named, never
//!    provisionally accepted, never TOFU.
//! 3. Target gate: a manifest built for another GNU triplet is
//!    refused before anything downloads.
//! 4. Freshness gate: a revision older than the newest the pod holds
//!    (installed or staged-inbox) is refused unless
//!    `--allow-downgrade`.
//! 5. Every manifest blob: present in the store → its sha256 is
//!    re-verified and the download skipped; absent → fetched, hashed,
//!    hard-refused on mismatch, written atomically.
//! 6. The verified manifest lands in the staging inbox.
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

/// The host as it belongs in an http URL: IPv6 literals re-bracketed —
/// the parsed `host` is the bare literal (`::1`), URLs require `[..]`.
fn host_for_url(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// The manifest endpoint for `pkg`: `http://host:port/manifests/<pkg>`
/// from a peer; `<dir>/manifests/<pkg>.json` from a static tree.
fn manifest_url(source: &PullRef, pkg: &str) -> miette::Result<String> {
    match source {
        PullRef::Peer { host, port, .. } => Ok(format!(
            "http://{}:{port}/manifests/{pkg}",
            host_for_url(host)
        )),
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
        PullRef::Peer { host, port, .. } => {
            Ok(format!("http://{}:{port}/blobs/{hash}", host_for_url(host)))
        }
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
        PullRef::Peer { host, port, pkg } => {
            format!("shuttle://{}:{port}/{pkg}", host_for_url(host))
        }
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
/// newest revision the pod already holds for that name is refused
/// unless `--allow-downgrade` is explicit. Equal or newer revisions
/// always pass; nothing held passes.
fn check_downgrade(known: Option<u32>, incoming: u32, allow_downgrade: bool) -> miette::Result<()> {
    let Some(known) = known else {
        return Ok(());
    };
    if known <= incoming || allow_downgrade {
        return Ok(());
    }
    miette::bail!(
        "package is already at revision {known} (installed or staged in the inbox); \
         the incoming manifest is revision {incoming} — refusing downgrade \
         (pass --allow-downgrade to accept it)"
    );
}

/// The newest revision the pod already holds for `pkg`: the max of the
/// active generation's installed revision and any staged inbox
/// manifest's revision. A newer staged entry gates an older incoming
/// one exactly like an installed one — otherwise a peer could silently
/// walk a staged revision back without `--allow-downgrade`.
fn known_revision(store: &RuntimeStore, pkg: &str) -> miette::Result<Option<u32>> {
    let installed = store
        .active_generation()?
        .and_then(|g| g.packages.get(pkg).map(|p| p.revision));
    let inbox = crate::pkg_manifest::manifest_path(store.root(), pkg);
    let staged = match std::fs::read(&inbox) {
        Ok(raw) => Some(
            serde_json::from_slice::<PackageManifest>(&raw)
                .map_err(|e| {
                    miette::miette!(
                        "staged inbox manifest {} does not parse — refusing to gate against \
                     an unknown revision: {e}",
                        inbox.display()
                    )
                })?
                .revision,
        ),
        Err(_) => None,
    };
    Ok(installed.max(staged))
}

// ── Trust (Decision 7: fail-closed, revoked-first, never TOFU) ──

/// The peer-lane trust decision, walking the SAME anchors the runtime
/// install path walks (`runtime::verify_against_anchors`): the device
/// image-baked set (`<anchor-dir>/trusted-keys` + legacy single anchor)
/// AND the operator keychain. Revocation runs first over the UNION of
/// the device image's list and the operator's, so a key revoked on the
/// device image is refused even while the operator keychain still
/// carries it. Verification is the ONE strict verifier,
/// [`crate::sign::verify_trust_set`] (revoked-first + ANY-anchor over
/// the merged chain): the manifest must carry a signature from a key
/// that is BOTH anchored locally AND cryptographically valid over the
/// canonical bytes. Empty everywhere fails closed with a named refusal.
fn verify_trust(
    pkg_manifest: &PackageManifest,
    anchor: &Path,
    keys_dir: &Path,
) -> miette::Result<String> {
    let signatures = BTreeMap::from([(
        pkg_manifest.signer.clone(),
        serde_json::Value::String(pkg_manifest.signature.clone()),
    )]);
    let canonical = crate::pkg_manifest::canonical_bytes(pkg_manifest)?;

    let revoked = crate::runtime::embedded_revoked_keys(anchor, keys_dir)?;

    let mut chain = crate::sign::Keychain::load_dir(&crate::runtime::trusted_keys_dir(anchor))?;
    // The legacy single-anchor fallback (images built before the set
    // shape existed) is best-effort, exactly as on the runtime path:
    // an unreadable legacy anchor is "no legacy anchor", not an error.
    if let Ok(legacy) = crate::sign::Keychain::load_pub_file(anchor) {
        chain.merge(legacy);
    }
    chain.merge(crate::sign::Keychain::load_dir(keys_dir)?);

    crate::sign::verify_trust_set(&canonical, &signatures, &chain, &revoked).map_err(|e| {
        miette::miette!(
            "manifest for '{}' signed by key id '{}' verifies under no trusted anchor \
             (device image anchors: {}, operator keychain: {}) — refusing \
             (unverified manifests are never provisionally accepted, never TOFU): {e}",
            pkg_manifest.name,
            pkg_manifest.signer,
            crate::runtime::trusted_keys_dir(anchor).display(),
            keys_dir.display()
        )
    })
}

// ── Blob staging ──

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

/// The operator keychain directory (`~/.config/shuttle/keys/`).
fn operator_keys_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    crate::sign::keys_dir(&PathBuf::from(home))
}

/// Run a peer or static pull for `source` into the named pod (`None` =
/// the default pod). `allow_downgrade` lifts the freshness rule's
/// older-revision refusal (ADR-0033 Decision 7). Trust anchors come
/// from the device image (`/etc/shuttle/update-key.pub` — the runtime
/// anchor) AND the operator keychain. Verifies and stages;
/// installation stays the pod workflow.
pub fn run(source: &PullRef, pod: Option<&str>, allow_downgrade: bool) -> miette::Result<()> {
    let store = crate::pod::resolve_pod_store(pod)?;
    let keys = operator_keys_dir();
    let anchor = PathBuf::from(crate::runtime::DEVICE_ANCHOR);
    let report = pull_into_store(&store, source, &anchor, &keys, allow_downgrade, &CurlFetch)?;
    print_report(&report);
    Ok(())
}

/// The lane body over an injected store root, trust-anchor paths and
/// transport — the testable core of [`run`]. `anchor` is the device
/// image anchor path (its siblings `trusted-keys/` and `revoked-keys`
/// are consulted beside it, mirroring [`crate::runtime`]'s walk);
/// `keys_dir` is the operator keychain.
pub fn pull_into_store<F: Fetch>(
    store: &RuntimeStore,
    source: &PullRef,
    anchor: &Path,
    keys_dir: &Path,
    allow_downgrade: bool,
    fetch: &F,
) -> miette::Result<PullPeerReport> {
    let pkg = pkg_name(source)?.to_string();

    // 1. Fetch the manifest, 2. parse it, 3. verify fail-closed, 4.
    // gate target + freshness + boundary-validate the declared files —
    // all BEFORE any blob moves.
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
    let host = crate::pkg_manifest::host_target();
    if manifest.target != host {
        miette::bail!(
            "manifest for '{}' targets '{}' but this host is '{host}' — refusing to pull \
             foreign-target content",
            manifest.name,
            manifest.target
        );
    }
    let signer = verify_trust(&manifest, anchor, keys_dir)?;
    let known = known_revision(store, &pkg)?;
    check_downgrade(known, manifest.revision, allow_downgrade)?;

    for file in &manifest.files {
        crate::pkg_manifest::validate_payload_path(file)?;
        crate::pkg_manifest::validate_sha256(file)?;
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

    /// Bracketed IPv6 literals: the parsed host is the bare literal and
    /// the built URLs re-bracket it (an unbracketed `::1` in an http
    /// URL is not parseable by curl).
    #[test]
    fn bracketed_ipv6_references_map_to_bracketed_urls() {
        let r = PullRef::parse("shuttle://[::1]:7780/hello").unwrap();
        match &r {
            PullRef::Peer { host, port, pkg } => {
                assert_eq!(host, "::1");
                assert_eq!(*port, 7780);
                assert_eq!(pkg, "hello");
            }
            other => panic!("expected Peer, got {other:?}"),
        }
        let default = PullRef::parse("shuttle://[::1]/hello").unwrap();
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
        assert_eq!(reference_string(&r), "shuttle://[::1]:7780/hello");
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

        let report = pull_into_store(&fx.store, &peer_ref(), &fx.anchor, &fx.keys, false, &fetch)
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
        let again = pull_into_store(&fx.store, &peer_ref(), &fx.anchor, &fx.keys, false, &fetch)
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
            &fx.store,
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
            &fx.store,
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

        let err = pull_into_store(&fx.store, &peer_ref(), &fx.anchor, &fx.keys, false, &fetch)
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

        let err = pull_into_store(&fx.store, &peer_ref(), &fx.anchor, &fx.keys, false, &fetch)
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

        let err = pull_into_store(&fx.store, &peer_ref(), &fx.anchor, &fx.keys, false, &fetch)
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

        let err = pull_into_store(&fx.store, &peer_ref(), &fx.anchor, &fx.keys, false, &fetch)
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

        let err = pull_into_store(&fx.store, &peer_ref(), &fx.anchor, &fx.keys, false, &fetch)
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

        let report = pull_into_store(&fx.store, &peer_ref(), &fx.anchor, &fx.keys, false, &fetch)
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

        let err = pull_into_store(&fx.store, &peer_ref(), &fx.anchor, &fx.keys, false, &fetch)
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
            pull_into_store(&fx.store, &peer_ref(), &fx.anchor, &fx.keys, false, &fetch).is_err(),
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
            &fx_store,
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

        let err = pull_into_store(&fx.store, &peer_ref(), &fx.anchor, &fx.keys, false, &fetch)
            .expect_err("revision 5 over installed 9 is a downgrade");
        let msg = err.to_string();
        assert!(msg.contains('9') && msg.contains('5'), "{msg}");

        pull_into_store(&fx.store, &peer_ref(), &fx.anchor, &fx.keys, true, &fetch)
            .expect("--allow-downgrade lifts the gate");
    }

    #[test]
    fn newer_and_equal_revisions_pass_the_gate() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        fx.seed_installed("hello", 7);
        let pkg = signed_manifest(&kp); // revision 7 == installed
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);
        pull_into_store(&fx.store, &peer_ref(), &fx.anchor, &fx.keys, false, &fetch)
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

        let err = pull_into_store(&fx.store, &peer_ref(), &fx.anchor, &fx.keys, false, &fetch)
            .expect_err("revision 7 over staged 9 is a downgrade");
        let msg = err.to_string();
        assert!(msg.contains('9') && msg.contains('7'), "{msg}");

        pull_into_store(&fx.store, &peer_ref(), &fx.anchor, &fx.keys, true, &fetch)
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

        let err = pull_into_store(&fx.store, &peer_ref(), &fx.anchor, &fx.keys, false, &fetch)
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

            let err = pull_into_store(&fx.store, &peer_ref(), &fx.anchor, &fx.keys, false, &fetch)
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

        let report = pull_into_store(&fx.store, &r, &fx.anchor, &fx.keys, false, &fetch)
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

        let err = pull_into_store(&fx.store, &peer_ref(), &fx.anchor, &fx.keys, false, &fetch)
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

        let err = pull_into_store(&fx.store, &peer_ref(), &fx.anchor, &fx.keys, false, &fetch)
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
