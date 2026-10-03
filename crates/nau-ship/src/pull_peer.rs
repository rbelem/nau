//! Peer and static-lane `pull` (ADR-0033 Decisions 5, 7, 10): fetch a
//! signed [`nau_core::pkg_manifest::PackageManifest`] plus its missing
//! blobs from a `nau://` peer or an `http(s)://` export tree,
//! verify fail-closed (signature first against the trusted-key set,
//! then the static tree's index cross-check, then every blob hash),
//! and stage into the named pod's store — the pull-staging inbox
//! (`nau_core::pkg_manifest::manifest_path`). Installation stays the pod
//! workflow, never a pull side effect.
//!
//! # Verification order (ADR-0033 Decisions 7 + 10, fail-closed)
//!
//! 1. JSON parse of the fetched manifest.
//! 2. Signature: revocation check FIRST over the UNION of the device
//!    image's revocation list and the operator keychain's
//!    ([`nau_core::sign::reject_revoked`]), then the strict trust set —
//!    [`nau_core::sign::verify_trust_set`] over the merged anchor set
//!    (device image-baked trusted-keys + legacy single anchor +
//!    operator keychain, the same walk
//!    [`nau_core::sign`] does for channel manifests). The ANY-anchor
//!    shortcut [`nau_core::sign::verify_keychain`] alone is NEVER enough
//!    here: an unverified manifest is refused and named, never
//!    provisionally accepted, never TOFU.
//! 3. Target gate: a manifest built for another GNU triplet is
//!    refused before anything downloads.
//! 4. Tree-index gate (static lane only, Decision 10 end-to-end): the
//!    tree's `index.json` must advertise exactly the package the
//!    verified manifest describes — the row must exist with the same
//!    version and revision. The index is unsigned, so it carries no
//!    trust of its own; the signature on the manifest is the
//!
//! (Issue #326 PR 4: the transport lane lives here; `run`/`print_report`
//! — the pod-store resolution and the report printing — stay in the
//! root crate's `pull_peer` module, which re-exports this one.)

use std::collections::BTreeMap;
use std::path::Path;

use miette::{IntoDiagnostic, WrapErr};
use serde::{Deserialize, Serialize};

use nau_core::blob_store::BlobStore;
use nau_core::pkg_manifest::{canonical_bytes, manifest_path, ManifestFile, PackageManifest};
use nau_core::sign::{embedded_revoked_keys, trusted_keys_dir, verify_trust_set, Keychain};
use nau_infra::command::{exit_code, CommandRunner, RealRunner};

use crate::oci::{sha256_file, sha256_hex, BLOB_TIMEOUT_SECS, CONNECT_TIMEOUT_SECS};
use crate::pull_ref::PullRef;

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
pub fn manifest_url(source: &PullRef, pkg: &str) -> miette::Result<String> {
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
pub fn blob_url(source: &PullRef, pkg: &str, hash: &str) -> miette::Result<String> {
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
pub fn url_dir<'a>(raw: &'a str, pkg: &str) -> miette::Result<&'a str> {
    raw.strip_suffix(&format!("/{pkg}"))
        .ok_or_else(|| miette::miette!("static reference '{raw}' does not end in /{pkg}"))
}

/// The reference as originally spelled (report label).
pub fn reference_string(source: &PullRef) -> String {
    match source {
        PullRef::Peer { host, port, pkg } => {
            format!("nau://{}:{port}/{pkg}", host_for_url(host))
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

pub fn pkg_name(source: &PullRef) -> miette::Result<&str> {
    match source {
        PullRef::Peer { pkg, .. } | PullRef::Url { pkg, .. } => Ok(pkg),
        PullRef::Oci(_) => {
            miette::bail!("OCI references ride the registry lane, not the peer lane")
        }
    }
}

// ── Tree-index gate (Decision 10: the static tree verifies end to end) ──

/// One package row of the static tree's `index.json` — the pull lane's
/// wire view of the shape the export lane freezes and `/info` serves.
#[derive(Debug, Deserialize)]
struct TreeIndexPackage {
    name: String,
    version: String,
    revision: u32,
}

/// The static tree's `index.json` (the frozen `/info` payload). The
/// publishing-host `name` is a label, not trust state — only the
/// package rows are checked here.
#[derive(Debug, Deserialize)]
struct TreeIndex {
    packages: Vec<TreeIndexPackage>,
}

/// The static-tree index gate (ADR-0033 Decision 10, fail-closed): the
/// tree's `index.json` must advertise exactly the package the verified
/// manifest describes — a row for the name, carrying the same version
/// and the same revision. The index is unsigned and carries no trust
/// of its own; the signature on the manifest is the authority, and
/// this gate makes a tampered or torn index refuse the pull instead of
/// letting the tree mis-describe itself. Peer lanes (Decision 4) serve
/// dynamic views with no frozen index — the gate is static-only.
fn verify_tree_index<F: Fetch>(
    source: &PullRef,
    pkg: &str,
    manifest: &PackageManifest,
    fetch: &F,
) -> miette::Result<()> {
    let PullRef::Url { url, .. } = source else {
        return Ok(());
    };
    let dir = url_dir(url.as_str(), pkg)?;
    let index_url = format!("{dir}/index.json");
    let raw = fetch
        .get(&index_url)
        .wrap_err_with(|| format!("fetching the tree index from {index_url}"))?;
    let index: TreeIndex = serde_json::from_slice(&raw).map_err(|e| {
        miette::miette!(
            "tree index from {index_url} is not a valid index.json — refusing the pull \
             (a public tree must describe itself correctly): {e}"
        )
    })?;
    let Some(row) = index.packages.iter().find(|p| p.name == pkg) else {
        miette::bail!(
            "tree index at {index_url} does not list package '{pkg}' though its signed \
             manifest exists — refusing the pull (index/manifest divergence)"
        );
    };
    let (index_version, index_revision) = (&row.version, row.revision);
    let (manifest_version, manifest_revision) = (&manifest.version, manifest.revision);
    if index_version != manifest_version || index_revision != manifest_revision {
        miette::bail!(
            "tree index at {index_url} advertises {pkg} {index_version} rev \
             {index_revision} but the signed manifest is {manifest_version} rev \
             {manifest_revision} — refusing the pull (index/manifest divergence)"
        );
    }
    Ok(())
}

// ── Freshness gate (Decision 7) ──

/// The freshness rule: a manifest whose revision is OLDER than the
/// newest revision the pod already holds for that name is refused
/// unless `--allow-downgrade` is explicit. Equal or newer revisions
/// always pass; nothing held passes.
pub fn check_downgrade(
    known: Option<u32>,
    incoming: u32,
    allow_downgrade: bool,
) -> miette::Result<()> {
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
fn known_revision(root: &Path, installed: Option<u32>, pkg: &str) -> miette::Result<Option<u32>> {
    let inbox = manifest_path(root, pkg);
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
/// [`nau_core::sign::verify_trust_set`] (revoked-first + ANY-anchor over
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
    let canonical = canonical_bytes(pkg_manifest)?;

    let revoked = embedded_revoked_keys(anchor, keys_dir)?;

    let mut chain = Keychain::load_dir(&trusted_keys_dir(anchor))?;
    // The legacy single-anchor fallback (images built before the set
    // shape existed) is best-effort, exactly as on the runtime path:
    // an unreadable legacy anchor is "no legacy anchor", not an error.
    if let Ok(legacy) = nau_core::sign::Keychain::load_pub_file(anchor) {
        chain.merge(legacy);
    }
    chain.merge(nau_core::sign::Keychain::load_dir(keys_dir)?);

    verify_trust_set(&canonical, &signatures, &chain, &revoked).map_err(|e| {
        miette::miette!(
            "manifest for '{}' signed by key id '{}' verifies under no trusted anchor \
             (device image anchors: {}, operator keychain: {}) — refusing \
             (unverified manifests are never provisionally accepted, never TOFU): {e}",
            pkg_manifest.name,
            pkg_manifest.signer,
            trusted_keys_dir(anchor).display(),
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
    store: &BlobStore,
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
            verify_existing_blob(&dest, &file.sha256)?;
            mark_executable(&dest, file.executable)?;
            already.push(file.clone());
            continue;
        }
        fetch_and_stage_blob(store, source, pkg, file, fetch)?;
        fetched.push(file.clone());
    }
    Ok((fetched, already))
}

/// The already-present arm: re-hash the store blob against the
/// manifest's pin (corruption here is a named hard error — ADR-0012
/// fail-closed).
fn verify_existing_blob(dest: &Path, expected: &str) -> miette::Result<()> {
    let actual = sha256_file(dest)?;
    if actual != expected {
        miette::bail!(
            "existing store blob {} is corrupt: expected sha256 {}, found {}",
            dest.display(),
            expected,
            actual
        );
    }
    Ok(())
}

/// The missing arm: fetch, hash-check against the manifest pin, write
/// atomically.
fn fetch_and_stage_blob<F: Fetch>(
    store: &BlobStore,
    source: &PullRef,
    pkg: &str,
    file: &ManifestFile,
    fetch: &F,
) -> miette::Result<()> {
    let dest = store.blob_path(&file.sha256);
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
    mark_executable(&dest, file.executable)
}

/// The manifest's executable bit must survive staging: the bin farm
/// links a wrapper-managed command straight at its store blob, so a
/// non-executable blob is a farm entry that dies with EACCES at
/// invocation (live 2026-10-02, codecanary via the static lane). The
/// already-present arm runs the same mark, so blobs staged by an
/// older build self-heal on the next pull.
fn mark_executable(dest: &Path, executable: bool) -> miette::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if executable { 0o755 } else { 0o644 };
        std::fs::set_permissions(dest, std::fs::Permissions::from_mode(mode))
            .into_diagnostic()
            .wrap_err_with(|| format!("setting the mode of {}", dest.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (dest, executable);
    }
    Ok(())
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

/// `nau pull <peer|url> --json` payload — mirrors
/// [`nau_ship::oci::PullReportJson`]'s shape (command/reference/digest +
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

/// The lane body over a blob store, trust-anchor paths and transport —
/// the testable core of [`run`]. `store` must be the runtime store's
/// blob root (`<state-root>/store`, what `RuntimeStore::blob_store()`
/// hands over): the staged inbox is derived from the blob root's parent.
/// `anchor` is the device image anchor path (its siblings `trusted-keys/`
/// and `revoked-keys` are consulted beside it, mirroring
/// [`crate::runtime`]'s walk); `keys_dir` is the operator keychain.
pub fn pull_into_store<F: Fetch>(
    store: &BlobStore,
    installed: Option<u32>,
    source: &PullRef,
    anchor: &Path,
    keys_dir: &Path,
    allow_downgrade: bool,
    fetch: &F,
) -> miette::Result<PullPeerReport> {
    let pkg = pkg_name(source)?.to_string();

    // 1. Fetch the manifest, 2. parse it, 3. verify fail-closed, 4.
    // gate target + tree index + freshness + boundary-validate the
    // declared files — all BEFORE any blob moves.
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
    let host = nau_core::pkg_manifest::host_target();
    if manifest.target != host {
        miette::bail!(
            "manifest for '{}' targets '{}' but this host is '{host}' — refusing to pull \
             foreign-target content",
            manifest.name,
            manifest.target
        );
    }
    let signer = verify_trust(&manifest, anchor, keys_dir)?;
    // 4. The static tree's index must agree with the verified manifest
    // before anything else moves (Decision 10 end-to-end).
    verify_tree_index(source, &pkg, &manifest, fetch)?;
    // 5. Freshness gate over the state-root view (the blob store's
    // parent — the runtime store layout nests `store/` under it).
    let state_root = store.root().parent().unwrap_or(store.root());
    let known = known_revision(state_root, installed, &pkg)?;
    check_downgrade(known, manifest.revision, allow_downgrade)?;

    for file in &manifest.files {
        nau_core::pkg_manifest::validate_payload_path(file)?;
        nau_core::pkg_manifest::validate_sha256(file)?;
    }

    // 6. Stage the blobs, 7. stage the verified manifest (the inbox —
    // staging only; installation is the pod workflow, ADR-0033
    // Decision 5).
    let (fetched, already) = stage_blobs(store, source, &pkg, &manifest.files, fetch)?;
    // The staging inbox sits beside the blob shards, under the state
    // root (the runtime store layout: `<state>/store/{<aa>,manifests}`).
    let state_root = store.root().parent().unwrap_or(store.root());
    let inbox = manifest_path(state_root, &pkg);
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
