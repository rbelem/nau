//! The release seam (ADR-0052 Decision 5): turn a built `.snap` into a
//! signed [`nau_core::pkg_manifest::PackageManifest`] plus blobs uploaded
//! to rustfs (S3 API, [`crate::s3`]), served by the Caddy front as the
//! static tree `nau pull` already consumes.
//!
//! # The puller's contract, mirrored (fail-closed)
//!
//! A manifest that would not pass `pull_peer`'s verify chain is never
//! uploaded. Every gate the pull lane runs has a release-side twin:
//!
//! - identity: the payload's `meta/snap.yaml` name/version must match
//!   `input.package`/`input.version` exactly (the runtime's
//!   `unpack_payload` precedent — unsquashfs + a two-shape yaml read);
//! - shape: the manifest is minted by [`nau_core::pkg_manifest::mint_manifest`]
//!   (one mint, one truth — the same function `serve`/`export` mint
//!   from), so `target` is [`nau_core::pkg_manifest::host_target`] and
//!   `files[].path` is the sha256 store identity by construction;
//! - per-file: [`nau_core::pkg_manifest::validate_payload_path`] +
//!   [`nau_core::pkg_manifest::validate_sha256`] run on the built
//!   manifest before anything uploads;
//! - signature: ed25519 over the canonical bytes via
//!   [`nau_core::pkg_manifest::sign`] with the update-manifest key at
//!   `input.signing_key` (the exact key `pull_peer::verify_trust`
//!   verifies against), re-checked with
//!   [`nau_core::pkg_manifest::verify`] before upload;
//! - tree layout: object keys are EXACTLY the URLs the static lane
//!   constructs — `manifests/<pkg>.json`
//!   ([`crate::pull_peer::manifest_url`]), `blobs/<sha256>`
//!   ([`crate::pull_peer::blob_url`]), and `index.json` (the Decision-10
//!   tree-index gate) under the bucket backing `input.tree_base`;
//! - freshness: the revision continues the tree's — the existing
//!   `manifests/<pkg>.json` (if any) must parse and is bumped by one, so
//!   a release is never a downgrade.
//!
//! # Upload order
//!
//! Blobs FIRST, the signed manifest second, `index.json` LAST (the
//! export lane's write-order rule: the tree never advertises content
//! that has not landed). A torn upload leaves orphaned blobs — never an
//! unsigned manifest, never a stale index advertising a new manifest.
//!
//! # Known deviations (deliberate)
//!
//! - `install.assembly`, `install.desktops`, and `install.fonts` stay
//!   empty: their runtime derivations (`sibling_assembly`,
//!   `record_desktops`, `record_fonts`) are private to nau-runtime. The
//!   apps/launchers/units/services records below ride the same PUBLIC
//!   planner APIs the runtime calls (`plan_app`, `Confinement::for_app`,
//!   `launcher_sibling_rel_path`), so they cannot drift from install.
//! - Payload symlinks are not part of the blob set (the runtime's
//!   `entry_hashes` records regular files only).
//! - Distinct payload files with identical content collapse to one
//!   manifest entry — the manifest is a content-addressed BLOB set.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use miette::{bail, IntoDiagnostic, WrapErr};
use serde::{Deserialize, Serialize};

use nau_core::pkg_manifest::{
    self, host_target, hostname, mint_manifest, validate_payload_path, validate_sha256, ClaimLayer,
    InstalledPackage, PackageManifest,
};
use nau_core::sign::{parse_secret_key, KeyPair};
use nau_core::snap_types::{launcher_sibling_rel_path, Confinement};
use nau_core::units::{plan_app, resolve_command_path, spec_from_payload_app, PayloadSnap};

use crate::oci::sha256_file;
use crate::s3::S3Client;

/// One rustfs (S3-compatible) target: the API endpoint base, the bucket
/// that backs the static tree, and the credentials the drain's release
/// step signs requests with.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct S3Target {
    /// S3 API base, e.g. `https://s3.internal.example` (no bucket path).
    pub endpoint: String,
    pub bucket: String,
    /// SigV4 region string (rustfs accepts any consistent value).
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
}

/// Everything the drain hands to [`release`]: the built artifact, its
/// identity, the update-manifest signing key, the S3 target, and the
/// public base URL the Caddy front serves the tree under (what
/// `manifest_url`/`blob_urls` are reported against).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReleaseInput {
    /// Built `.snap` artifact to publish.
    pub snap_path: PathBuf,
    /// Package name (e.g. `opencode-bin`).
    pub package: String,
    /// Released version (must match the snap's declared version).
    pub version: String,
    /// Update-manifest signing key material (the trust root the puller
    /// already verifies against; see `pull_peer::verify_trust`).
    pub signing_key: PathBuf,
    pub s3: S3Target,
    /// Public static-tree base, e.g. `https://download.example/nau`.
    pub tree_base: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReleaseOutput {
    /// URL the signed PackageManifest is served at.
    pub manifest_url: String,
    /// URLs every uploaded blob is served at (sha256-addressed).
    pub blob_urls: Vec<String>,
}

// ── Static-tree keys (the puller's URL construction, mirrored) ──

/// `pull_peer::manifest_url` serves a static tree's manifest from
/// `{tree}/manifests/<pkg>.json` — this is that object's key.
fn manifest_key(pkg: &str) -> String {
    format!("manifests/{pkg}.json")
}

/// `pull_peer::blob_url` serves a static tree's blob from
/// `{tree}/blobs/<sha256>` — this is that object's key.
fn blob_key(sha256: &str) -> String {
    format!("blobs/{sha256}")
}

/// The tree index the puller's Decision-10 gate fetches from
/// `{tree}/index.json`.
const INDEX_KEY: &str = "index.json";

/// A public static-tree URL: `tree_base` (trailing slash tolerated)
/// joined with an object key — the reported shape of
/// `ReleaseOutput::manifest_url`/`blob_urls`.
fn tree_url(tree_base: &str, key: &str) -> String {
    format!("{}/{}", tree_base.trim_end_matches('/'), key)
}

// ── The wire shapes of the tree's index.json ──
//
// The export lane (nau-peer) freezes `{name, packages}`; the pull lane
// reads the same shape through `pull_peer`'s `TreeIndex` (which checks
// only `packages`). Release reads and upserts the full shape so an
// existing index keeps its publishing-host name and other rows.

/// One package row of `index.json`.
#[derive(Debug, Serialize, Deserialize)]
struct IndexRow {
    name: String,
    version: String,
    revision: u32,
}

/// `index.json` — the static tree's `/info` payload.
#[derive(Debug, Serialize, Deserialize)]
struct TreeIndexJson {
    name: String,
    packages: Vec<IndexRow>,
}

/// The `meta/snap.yaml` version probe (the runtime's `MetaVersion`
/// shape — a second, minimal read beside [`PayloadSnap`]).
#[derive(Debug, Deserialize)]
struct MetaVersion {
    #[serde(default)]
    version: Option<String>,
}

/// Sign and publish one artifact: verify the snap's identity against
/// `input.package`/`input.version`, build the `PackageManifest` with
/// sha256-addressed blobs, sign it with the update-manifest key, upload
/// manifest + blobs to rustfs (SigV4 PUT), and report the public URLs.
///
/// Fail-closed rules mirror the puller's verify chain: a manifest that
/// would not pass `pull_peer`'s parse/target/trust gates is never
/// uploaded. Partial uploads are harmless (orphaned blobs, no manifest).
pub fn release(input: &ReleaseInput) -> miette::Result<ReleaseOutput> {
    let client = S3Client::new(input.s3.clone())?;
    release_with(input, &client)
}

/// The testable core of [`release`] — identical pipeline over an
/// injected rustfs client (the `pull_into_store` seam shape).
fn release_with(input: &ReleaseInput, client: &S3Client) -> miette::Result<ReleaseOutput> {
    // 1. The signing key: the update-manifest secret (the file shape
    // `nau key keygen` writes; `pull_peer::verify_trust` is the verify
    // side of exactly this key).
    let kp = load_signing_key_file(&input.signing_key)?;

    // 2. Unpack + identity (fail-closed on mismatch); the verified
    // declared version is the manifest's version.
    let work = tempfile::tempdir()
        .into_diagnostic()
        .wrap_err("creating the release scratch dir")?;
    let extract = work.path().join("extract");
    let (meta, meta_version) = unpack_payload(&input.snap_path, &extract)?;
    let version = verify_identity(&meta, &meta_version, input)?;

    // 3. Content-address the payload (packaging metadata excluded —
    // the runtime's install walk skips meta/ the same way).
    let walked = walk_payload_tree(&extract)?;

    // 4. The revision continues the tree's: never a downgrade.
    let revision = existing_revision(client, &input.package)?;

    // 5. Mint + sign, then mirror the puller's gates BEFORE anything
    // uploads.
    let manifest = build_manifest(input, &meta, &version, revision, &walked, &kp)?;
    mirror_puller_gates(&manifest, &kp)?;

    // 6. Upload: blobs FIRST, manifest second (a torn upload leaves
    // orphaned blobs, never an unsigned manifest), index LAST (the tree
    // must not advertise what has not landed).
    let blob_urls = upload_content(client, input, &manifest, &extract, &walked)?;
    upsert_index(client, input, &version, revision)?;

    Ok(ReleaseOutput {
        manifest_url: tree_url(&input.tree_base, &manifest_key(&input.package)),
        blob_urls,
    })
}

// ── Step 1: the key ──

/// Load the update-manifest secret from an explicit file (the on-disk
/// shape `nau key keygen` writes: comment line + hex seed).
fn load_signing_key_file(path: &Path) -> miette::Result<KeyPair> {
    let text = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading the signing key {}", path.display()))?;
    parse_secret_key(&text).wrap_err_with(|| format!("parsing {}", path.display()))
}

// ── Step 2: unpack + identity ──

/// Resolve a bare tool on PATH (the devbox floor carries
/// squashfs-tools; the farm drain runs under it).
fn find_on_path(tool: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(tool))
        .find(|candidate| candidate.is_file())
}

/// Extract the payload with unsquashfs (the runtime `unpack_payload`
/// precedent: same tool, same flags) and read `meta/snap.yaml` twice —
/// once into the planner's shape, once for the version field.
fn unpack_payload(snap: &Path, extract: &Path) -> miette::Result<(PayloadSnap, MetaVersion)> {
    let unsquashfs = find_on_path("unsquashfs").ok_or_else(|| {
        miette::miette!(
            "no unsquashfs on PATH — release cannot inspect the built payload; \
             install squashfs-tools"
        )
    })?;
    let status = std::process::Command::new(&unsquashfs)
        .args([
            "-d",
            &extract.to_string_lossy(),
            "-no-xattrs",
            &snap.to_string_lossy(),
        ])
        .status()
        .map_err(|e| miette::miette!("unsquashfs: {e}"))?;
    if !status.success() {
        bail!("unsquashfs failed to extract payload '{}'", snap.display());
    }
    let yaml_path = extract.join("meta").join("snap.yaml");
    let yaml_text = std::fs::read_to_string(&yaml_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading {}", yaml_path.display()))?;
    let meta: PayloadSnap = serde_yaml::from_str(&yaml_text)
        .map_err(|e| miette::miette!("meta/snap.yaml parse for '{}': {e}", snap.display()))?;
    let version: MetaVersion = serde_yaml::from_str(&yaml_text)
        .map_err(|e| miette::miette!("meta/snap.yaml version parse: {e}"))?;
    Ok((meta, version))
}

/// The identity gate: the payload's declared name/version must exist and
/// match `input.package`/`input.version` exactly — a release that would
/// mislabel the tree is refused, never coerced. Returns the verified
/// declared version.
fn verify_identity(
    meta: &PayloadSnap,
    meta_version: &MetaVersion,
    input: &ReleaseInput,
) -> miette::Result<String> {
    let declared_name = meta.name.as_deref().ok_or_else(|| {
        miette::miette!(
            "payload's meta/snap.yaml carries no name — refusing to release '{}'",
            input.package
        )
    })?;
    if declared_name != input.package {
        bail!(
            "payload declares name '{declared_name}' but the release asked for '{}' — \
             refusing (identity mismatch)",
            input.package
        );
    }
    let declared_version = meta_version.version.as_deref().ok_or_else(|| {
        miette::miette!(
            "payload's meta/snap.yaml carries no version — refusing to release '{}'",
            input.package
        )
    })?;
    if declared_version != input.version {
        bail!(
            "payload declares version '{declared_version}' but the release asked for \
             '{}' — refusing (identity mismatch)",
            input.version
        );
    }
    Ok(declared_version.to_string())
}

// ── Step 3: the content walk ──

/// Walk an extracted payload tree, sha256-addressing every regular
/// file: payload-relative path → hash. Sorted (deterministic), symlinks
/// skipped (not blob content — the runtime's `entry_hashes` records
/// regular files only), the top-level `meta/` packaging subtree
/// excluded, anything else a named error.
fn walk_payload(
    root: &Path,
    dir: &Path,
    is_top: bool,
    out: &mut BTreeMap<String, String>,
) -> miette::Result<()> {
    for entry in std::fs::read_dir(dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading {}", dir.display()))?
    {
        let entry = entry.into_diagnostic().wrap_err("walking payload")?;
        walk_entry(root, &entry.path(), is_top, out)?;
    }
    Ok(())
}

/// Classify and record one walked entry (the runtime `ingest_entry`
/// shape, release-scoped).
fn walk_entry(
    root: &Path,
    path: &Path,
    is_top: bool,
    out: &mut BTreeMap<String, String>,
) -> miette::Result<()> {
    let file_type = std::fs::symlink_metadata(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("statting {}", path.display()))?
        .file_type();
    let rel = path
        .strip_prefix(root)
        .expect("walk paths are under root")
        .to_string_lossy()
        .into_owned();
    if file_type.is_symlink() {
        return Ok(());
    }
    if file_type.is_dir() {
        if is_top && rel == "meta" {
            return Ok(());
        }
        walk_payload(root, path, false, out)?;
    } else if file_type.is_file() {
        let sha256 = sha256_file(path)?;
        out.insert(rel, sha256);
    } else {
        bail!(
            "unsupported file type at {} (fifos/sockets/devices are not \
             releasable payload content)",
            path.display()
        );
    }
    Ok(())
}

fn walk_payload_tree(extract: &Path) -> miette::Result<BTreeMap<String, String>> {
    let mut walked = BTreeMap::new();
    walk_payload(extract, extract, true, &mut walked)?;
    Ok(walked)
}

/// The blob hash of one payload-relative path — the runtime
/// `blob_hash_for` shape: a declared path missing from the payload is a
/// hard, named error, never a skip.
fn hash_for_rel(
    walked: &BTreeMap<String, String>,
    rel: &str,
    snap_name: &str,
) -> miette::Result<String> {
    walked
        .get(rel)
        .cloned()
        .ok_or_else(|| miette::miette!("command binary '{rel}' not found in payload '{snap_name}'"))
}

// ── Step 4: the revision ──

/// The revision this release mints: one past the tree's current
/// manifest for the package (the freshness rule the puller runs refuses
/// non-monotonic revisions — a release must never mint one). A missing
/// manifest is the first release (revision 1); a present-but-unparseable
/// one is a named refusal, never a guess.
fn existing_revision(client: &S3Client, pkg: &str) -> miette::Result<u32> {
    let Some(bytes) = client.get(&manifest_key(pkg))? else {
        return Ok(1);
    };
    let existing: PackageManifest = serde_json::from_slice(&bytes).map_err(|e| {
        miette::miette!(
            "the tree's existing manifest for '{pkg}' does not parse — refusing to \
             guess the next revision: {e}"
        )
    })?;
    existing.revision.checked_add(1).ok_or_else(|| {
        miette::miette!(
            "the tree's existing manifest for '{pkg}' is at revision {} — no next \
             revision exists",
            existing.revision
        )
    })
}

// ── Step 5: mint + sign + the puller's gates ──

/// Derive the app-side install records with the SAME public planner
/// APIs the runtime's install path calls (`plan_payload_runtime` is
/// private to nau-runtime; `plan_app` and the confinement helpers are
/// core vocabulary): app binaries, launcher wrappers for confined apps,
/// per-app confinement overrides, daemon unit names.
#[allow(clippy::type_complexity)]
fn derive_apps(
    snap_name: &str,
    meta: &PayloadSnap,
    walked: &BTreeMap<String, String>,
) -> miette::Result<(
    Vec<String>,
    BTreeMap<String, String>,
    BTreeMap<String, String>,
    BTreeMap<String, Confinement>,
)> {
    let mut units = Vec::new();
    let mut apps = BTreeMap::new();
    let mut launchers = BTreeMap::new();
    let mut app_confined = BTreeMap::new();
    let snap_plugs: Vec<_> = meta
        .plugs
        .iter()
        .map(|(plug_name, plug)| plug.to_plug_ref(plug_name))
        .collect();
    for (app_name, app) in &meta.apps {
        let spec = spec_from_payload_app(snap_name, app_name, app, snap_plugs.clone());
        let plan = plan_app(&spec);
        let hash = hash_for_rel(walked, &plan.in_snap_binary, snap_name)?;
        apps.insert(plan.app.clone(), hash);
        if let Some(unit) = plan.daemon {
            units.push(unit.unit_name);
        }
        // Ticket #11 mirror: a confined app records its launcher-wrapper
        // blob and its confinement override when one is declared.
        if Confinement::for_app(app.confined.as_ref(), meta.confined.as_ref()).is_some() {
            let launcher_rel = launcher_sibling_rel_path(&plan.in_snap_binary);
            let launcher_hash = hash_for_rel(walked, &launcher_rel, snap_name)?;
            launchers.insert(plan.app.clone(), launcher_hash);
            if let Some(override_conf) = &app.confined {
                app_confined.insert(plan.app.clone(), override_conf.clone());
            }
        }
    }
    Ok((units, apps, launchers, app_confined))
}

/// Derive the service records (ADR-0032) — the runtime
/// `plan_payload_services` gates mirrored, so release refuses what
/// install would refuse: a confined package cannot declare services,
/// and a service command must be a single payload path.
fn derive_services(
    snap_name: &str,
    meta: &PayloadSnap,
    walked: &BTreeMap<String, String>,
) -> miette::Result<BTreeMap<String, String>> {
    let mut service_bins = BTreeMap::new();
    for (svc_name, decl) in &meta.services {
        if meta.confined.is_some() {
            bail!(
                "service '{svc_name}' of package '{snap_name}': confined packages cannot \
                 declare services in v1 — the wrapper machinery is app-scoped; track an \
                 unconfined variant or split the package"
            );
        }
        if decl.command.trim().is_empty() || decl.command.split_whitespace().count() != 1 {
            bail!(
                "service '{svc_name}' of package '{snap_name}': command must be a single \
                 path with no arguments — put arguments in 'args' (ADR-0032 Decision 2)"
            );
        }
        let rel = resolve_command_path(&decl.command).ok_or_else(|| {
            miette::miette!(
                "service '{svc_name}' of package '{snap_name}': command does not name a \
                 payload path"
            )
        })?;
        let hash = hash_for_rel(walked, &rel, snap_name)?;
        service_bins.insert(svc_name.clone(), hash);
    }
    Ok(service_bins)
}

/// sha3-384 of the built artifact — the record's snap-level content
/// pin (the store's own digest discipline), streamed.
fn sha3_384_file(path: &Path) -> miette::Result<String> {
    use sha3::Digest;
    let mut file = std::fs::File::open(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading {}", path.display()))?;
    let mut hasher = sha3::Sha3_384::new();
    std::io::copy(&mut file, &mut hasher)
        .into_diagnostic()
        .wrap_err_with(|| format!("hashing {}", path.display()))?;
    Ok(nau_core::sign::to_hex(&hasher.finalize()))
}

/// Build the signed [`PackageManifest`]: assemble the install record
/// from the payload + planner, mint through the ONE mint function
/// (`serve`/`export` mint from the same code), and sign with the
/// update-manifest key.
fn build_manifest(
    input: &ReleaseInput,
    meta: &PayloadSnap,
    version: &str,
    revision: u32,
    walked: &BTreeMap<String, String>,
    kp: &KeyPair,
) -> miette::Result<PackageManifest> {
    let snap_name = meta.name.clone().unwrap_or_else(|| input.package.clone());
    let (units, apps, launchers, app_confined) = derive_apps(&snap_name, meta, walked)?;
    let service_bins = derive_services(&snap_name, meta, walked)?;

    // The blob set: content-addressed, sorted, one entry per distinct
    // hash (the store identity `mint_manifest` turns into
    // `files[].path == files[].sha256`).
    let files: Vec<String> = walked
        .values()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .cloned()
        .collect();

    let record = InstalledPackage {
        name: input.package.clone(),
        version: version.to_string(),
        revision,
        sha3_384: sha3_384_file(&input.snap_path)?,
        files,
        units,
        layer: ClaimLayer::Own,
        apps,
        requires: meta.requires.clone(),
        launchers,
        assembly: BTreeMap::new(),
        confined: meta.confined.clone(),
        app_confined,
        desktops: BTreeMap::new(),
        fonts: BTreeMap::new(),
        services: meta.services.clone(),
        service_bins,
        meta_digest: None,
    };

    let mut manifest = mint_manifest(&record);
    pkg_manifest::sign(&mut manifest, kp)?;
    Ok(manifest)
}

/// The release-side twin of the puller's verify chain: target gate,
/// per-file boundary/hash validators, and a cryptographic self-check
/// (the signature must verify under the very key that signed it — what
/// `pull_peer::verify_trust` would require against a trusted anchor).
fn mirror_puller_gates(manifest: &PackageManifest, kp: &KeyPair) -> miette::Result<()> {
    if manifest.target != host_target() {
        bail!(
            "minted manifest for '{}' targets '{}' but this host is '{}' — refusing \
             to release foreign-target content",
            manifest.name,
            manifest.target,
            host_target()
        );
    }
    for file in &manifest.files {
        validate_payload_path(file)?;
        validate_sha256(file)?;
    }
    pkg_manifest::verify(manifest, &kp.public_hex())
        .wrap_err("the built manifest fails its own signature check — refusing to release")
}

// ── Step 6: the upload ──

/// PUT every blob, then the signed manifest — blobs FIRST (a torn
/// upload leaves orphaned blobs, never a manifest). Reported URLs are
/// `input.tree_base` joined with the same keys.
fn upload_content(
    client: &S3Client,
    input: &ReleaseInput,
    manifest: &PackageManifest,
    extract: &Path,
    walked: &BTreeMap<String, String>,
) -> miette::Result<Vec<String>> {
    let mut by_sha: BTreeMap<&str, &str> = BTreeMap::new();
    for (rel, sha) in walked {
        by_sha.entry(sha.as_str()).or_insert(rel.as_str());
    }
    let mut blob_urls = Vec::new();
    for file in &manifest.files {
        let rel = by_sha.get(file.sha256.as_str()).ok_or_else(|| {
            miette::miette!(
                "internal: manifest references hash {} with no payload file",
                file.sha256
            )
        })?;
        let body = std::fs::read(extract.join(rel))
            .into_diagnostic()
            .wrap_err_with(|| format!("reading payload file {rel} for upload"))?;
        client.put(&blob_key(&file.sha256), &body)?;
        blob_urls.push(tree_url(&input.tree_base, &blob_key(&file.sha256)));
    }
    let manifest_bytes = serde_json::to_vec_pretty(manifest)
        .into_diagnostic()
        .wrap_err("serializing the signed manifest")?;
    client.put(&manifest_key(&input.package), &manifest_bytes)?;
    Ok(blob_urls)
}

/// Upsert the tree's `index.json` — the Decision-10 gate the puller
/// runs (`verify_tree_index`: the row must exist with the same version
/// AND revision, or the whole pull refuses). Written LAST: the index
/// never advertises content that has not landed. An existing-but-
/// unparseable index is a refusal, not a rebuild opportunity.
fn upsert_index(
    client: &S3Client,
    input: &ReleaseInput,
    version: &str,
    revision: u32,
) -> miette::Result<()> {
    let mut index = match client.get(INDEX_KEY)? {
        None => TreeIndexJson {
            name: hostname(),
            packages: Vec::new(),
        },
        Some(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
            miette::miette!(
                "the tree's {} does not parse — refusing to rewrite an unreadable \
                 index (fail-closed, not a rebuild): {e}",
                INDEX_KEY
            )
        })?,
    };
    index.packages.retain(|row| row.name != input.package);
    index.packages.push(IndexRow {
        name: input.package.clone(),
        version: version.to_string(),
        revision,
    });
    index.packages.sort_by(|a, b| a.name.cmp(&b.name));
    let bytes = serde_json::to_vec_pretty(&index)
        .into_diagnostic()
        .wrap_err("serializing the tree index")?;
    client.put(INDEX_KEY, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::RunnerOutput;
    use nau_infra::command::CommandRunner;
    use std::io;
    use std::sync::{Arc, Mutex};

    // ── test key + fixture ──

    /// Deterministic keypair from a single seed byte (the
    /// nau-core test precedent).
    fn test_kp(seed_byte: u8) -> KeyPair {
        nau_core::sign::derive_pair(&[seed_byte; 32])
    }

    /// Write a secret-key file in the `nau key keygen` shape.
    fn write_test_key(dir: &Path, seed_byte: u8) -> PathBuf {
        let kp = test_kp(seed_byte);
        let path = dir.join("secret-key");
        std::fs::write(
            &path,
            format!("untrusted comment: test\n{}\n", kp.seed_hex()),
        )
        .unwrap();
        path
    }

    fn has_tool(tool: &str) -> bool {
        find_on_path(tool).is_some()
    }

    /// Skip guard for the squashfs-backed tests (issue #134 style: a
    /// skip is loud, never silent).
    fn squashfs_available() -> bool {
        let ok = has_tool("mksquashfs") && has_tool("unsquashfs");
        if !ok {
            eprintln!("skipping: mksquashfs/unsquashfs unavailable");
        }
        ok
    }

    /// Build a real minimal `.snap` with mksquashfs: meta/snap.yaml
    /// (name/version/apps/services), two binaries, one plain blob.
    fn build_test_snap(dir: &Path, name: &str, version: &str) -> PathBuf {
        let payload = dir.join("payload");
        std::fs::create_dir_all(payload.join("meta")).unwrap();
        std::fs::create_dir_all(payload.join("bin")).unwrap();
        std::fs::create_dir_all(payload.join("usr/share/doc")).unwrap();
        std::fs::write(
            payload.join("meta/snap.yaml"),
            format!(
                "name: {name}\nversion: {version}\nrequires:\n  - libc6\n\
                 apps:\n  hello:\n    command: bin/hello\n    daemon: simple\n\
                 services:\n  srv:\n    command: bin/srv\n    daemon: simple\n"
            ),
        )
        .unwrap();
        std::fs::write(payload.join("bin/hello"), b"hello payload binary").unwrap();
        std::fs::write(payload.join("bin/srv"), b"srv payload binary").unwrap();
        std::fs::write(payload.join("usr/share/doc/readme"), b"readme blob").unwrap();
        let snap = dir.join(format!("{name}_{version}_test.snap"));
        let status = std::process::Command::new("mksquashfs")
            .args([
                payload.to_str().unwrap(),
                snap.to_str().unwrap(),
                "-noappend",
                "-no-progress",
                "-no-xattrs",
            ])
            .output()
            .expect("run mksquashfs");
        assert!(
            status.status.success(),
            "mksquashfs failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );
        snap
    }

    fn test_input(
        dir: &Path,
        snap: &Path,
        package: &str,
        version: &str,
        endpoint: &str,
    ) -> ReleaseInput {
        ReleaseInput {
            snap_path: snap.to_path_buf(),
            package: package.to_string(),
            version: version.to_string(),
            signing_key: write_test_key(dir, 7),
            s3: S3Target {
                endpoint: endpoint.to_string(),
                bucket: "nau-tree".into(),
                region: "us-east-1".into(),
                access_key: "AKIDEXAMPLE".into(),
                secret_key: "test-secret".into(),
            },
            tree_base: "https://download.example/nau".into(),
        }
    }

    // ── the fake rustfs (curl-argv seam, oci.rs FakeRunner precedent) ──

    fn arg_after<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
        argv.iter()
            .position(|a| a == flag)
            .and_then(|i| argv.get(i + 1))
            .map(String::as_str)
    }

    /// The object key from the client's path-style URL (after
    /// /<bucket>/).
    fn key_of(url: &str, bucket: &str) -> String {
        url.split_once(&format!("/{bucket}/"))
            .map(|(_, rest)| rest.to_string())
            .unwrap_or_default()
    }

    /// Emulates curl against an in-memory tree: GET answers from
    /// `gets` (404 when absent), PUT records into a shared log. The
    /// log handle outlives the boxed runner so assertions can query it.
    struct FakeRustfs {
        bucket: String,
        gets: BTreeMap<String, (u16, Vec<u8>)>,
        puts: PutLog,
    }

    /// A shared handle on the fake's recorded PUTs.
    type PutEntries = Vec<(String, Vec<u8>)>;

    #[derive(Clone, Default)]
    struct PutLog(Arc<Mutex<PutEntries>>);

    impl PutLog {
        fn keys(&self) -> Vec<String> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .map(|(k, _)| k.clone())
                .collect()
        }

        fn body(&self, key: &str) -> Vec<u8> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, b)| b.clone())
                .unwrap_or_else(|| panic!("no PUT recorded for {key}"))
        }
    }

    impl FakeRustfs {
        fn new(gets: BTreeMap<String, (u16, Vec<u8>)>) -> FakeRustfs {
            FakeRustfs {
                bucket: "nau-tree".into(),
                gets,
                puts: PutLog::default(),
            }
        }
    }

    impl CommandRunner for FakeRustfs {
        fn run(&self, argv: &[String]) -> io::Result<RunnerOutput> {
            let method = arg_after(argv, "-X").expect("client always passes -X");
            let url = argv.last().expect("client always appends the URL");
            let key = key_of(url, &self.bucket);
            let (status, body) = match method {
                "GET" => self.gets.get(&key).cloned().unwrap_or((404, Vec::new())),
                "PUT" => {
                    let upload = arg_after(argv, "--data-binary")
                        .expect("client always stages the body")
                        .trim_start_matches('@')
                        .to_string();
                    let bytes = std::fs::read(&upload)?;
                    self.puts.0.lock().unwrap().push((key, bytes));
                    (200, Vec::new())
                }
                other => panic!("unexpected method {other}"),
            };
            let header_file = arg_after(argv, "-D").expect("client always dumps headers");
            std::fs::write(header_file, format!("HTTP/1.1 {status} X\r\n\r\n"))?;
            let body_file = arg_after(argv, "-o").expect("client always names an output");
            std::fs::write(body_file, body)?;
            Ok(RunnerOutput {
                code: 0,
                stdout: Vec::new(),
                stderr: String::new(),
            })
        }
    }

    // ── the puller's gates, asserted from the release side ──

    /// The shared happy-path run: release `hello` 2.10 against the
    /// in-memory tree, return (output, the fake's PUT log).
    fn release_hello(
        dir: &Path,
        gets: BTreeMap<String, (u16, Vec<u8>)>,
    ) -> (ReleaseOutput, PutLog) {
        let snap = build_test_snap(dir, "hello", "2.10");
        let input = test_input(dir, &snap, "hello", "2.10", "https://s3.internal.example");
        let fake = FakeRustfs::new(gets);
        let puts = fake.puts.clone();
        let client = S3Client::with_runner(input.s3.clone(), Box::new(fake)).unwrap();
        let out = release_with(&input, &client).expect("release must succeed");
        (out, puts)
    }

    #[test]
    fn builds_a_manifest_the_puller_chain_accepts() {
        if !squashfs_available() {
            return;
        }
        let work = tempfile::tempdir().unwrap();
        let (out, fake) = release_hello(work.path(), BTreeMap::new());

        // The tree got: blobs (sorted) → manifest → index.
        let keys = fake.keys();
        assert_eq!(
            keys.last().map(String::as_str),
            Some(INDEX_KEY),
            "index.json lands LAST: {keys:?}"
        );
        assert_eq!(
            keys[keys.len() - 2].as_str(),
            "manifests/hello.json",
            "manifest lands after every blob: {keys:?}"
        );
        for key in &keys[..keys.len() - 2] {
            assert!(key.starts_with("blobs/"), "blob key shape: {key}");
        }

        // The uploaded manifest parses, verifies under the signing key,
        // and passes the puller's per-file validators.
        let bytes = fake.body("manifests/hello.json");
        let manifest: PackageManifest = serde_json::from_slice(&bytes).expect("parses");
        assert_eq!(manifest.name, "hello");
        assert_eq!(manifest.version, "2.10");
        assert_eq!(manifest.revision, 1, "first release → revision 1");
        assert_eq!(manifest.target, host_target());
        for file in &manifest.files {
            validate_payload_path(file).unwrap();
            validate_sha256(file).unwrap();
            assert_eq!(file.path, file.sha256, "blob-addressed store identity");
        }
        let kp = test_kp(7);
        pkg_manifest::verify(&manifest, &kp.public_hex()).expect("signature verifies");

        // Content addresses match the fixture's bytes; service + app
        // records ride the planner.
        let expect = |content: &[u8]| crate::oci::sha256_hex(content);
        let hello_hash = expect(b"hello payload binary");
        let srv_hash = expect(b"srv payload binary");
        let readme_hash = expect(b"readme blob");
        let hashes: Vec<&str> = manifest.files.iter().map(|f| f.sha256.as_str()).collect();
        assert_eq!(
            hashes,
            vec![hello_hash.as_str(), readme_hash.as_str(), srv_hash.as_str()]
                .into_iter()
                .collect::<Vec<_>>()
                .as_slice(),
            "files sorted by hash"
        );
        assert_eq!(manifest.install.apps.get("hello").unwrap(), &hello_hash);
        assert_eq!(manifest.install.service_bins.get("srv").unwrap(), &srv_hash);
        assert!(manifest
            .install
            .units
            .contains(&"hello-hello.service".to_string()));
        assert_eq!(manifest.install.requires, vec!["libc6".to_string()]);
        // The executable union: both recorded command binaries.
        for file in &manifest.files {
            let exe = file.sha256 == hello_hash || file.sha256 == srv_hash;
            assert_eq!(file.executable, exe, "exec bit for {}", file.sha256);
        }

        // Every blob body landed content-identical.
        for file in &manifest.files {
            let body = fake.body(&blob_key(&file.sha256));
            assert_eq!(crate::oci::sha256_hex(&body), file.sha256);
        }

        // The reported URLs join tree_base with the puller's keys.
        assert_eq!(
            out.manifest_url,
            "https://download.example/nau/manifests/hello.json"
        );
        assert_eq!(out.blob_urls.len(), manifest.files.len());
        for (url, file) in out.blob_urls.iter().zip(&manifest.files) {
            assert_eq!(
                url,
                &format!("https://download.example/nau/blobs/{}", file.sha256)
            );
        }
    }

    #[test]
    fn identity_mismatch_is_fail_closed() {
        if !squashfs_available() {
            return;
        }
        let work = tempfile::tempdir().unwrap();
        let snap = build_test_snap(work.path(), "hello", "2.10");

        let wrong_name = test_input(
            work.path(),
            &snap,
            "other",
            "2.10",
            "https://s3.internal.example",
        );
        let err = release(&wrong_name).unwrap_err().to_string();
        assert!(err.contains("'other'"), "{err}");
        assert!(err.contains("hello"), "{err}");

        let wrong_version = test_input(
            work.path(),
            &snap,
            "hello",
            "9.9",
            "https://s3.internal.example",
        );
        let err = release(&wrong_version).unwrap_err().to_string();
        assert!(err.contains("9.9"), "{err}");
        assert!(err.contains("2.10"), "{err}");
    }

    #[test]
    fn missing_declared_identity_is_fail_closed() {
        if !squashfs_available() {
            return;
        }
        let work = tempfile::tempdir().unwrap();
        // A snap.yaml with no name: release must not fall back to the
        // requested package — it refuses.
        let payload = work.path().join("payload");
        std::fs::create_dir_all(payload.join("meta")).unwrap();
        std::fs::write(payload.join("meta/snap.yaml"), "version: 1.0\n").unwrap();
        let snap = work.path().join("anon.snap");
        let status = std::process::Command::new("mksquashfs")
            .args([
                payload.to_str().unwrap(),
                snap.to_str().unwrap(),
                "-noappend",
                "-no-progress",
                "-no-xattrs",
            ])
            .output()
            .expect("run mksquashfs");
        assert!(
            status.status.success(),
            "mksquashfs failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );

        let input = test_input(
            work.path(),
            &snap,
            "hello",
            "1.0",
            "https://s3.internal.example",
        );
        let err = release(&input).unwrap_err().to_string();
        assert!(err.contains("carries no name"), "{err}");
    }

    #[test]
    fn revision_continues_from_the_existing_tree_manifest() {
        if !squashfs_available() {
            return;
        }
        let work = tempfile::tempdir().unwrap();
        // The tree already holds a manifest at revision 7 — the puller
        // only needs it to PARSE (trust is the puller's gate, not the
        // probe's), so a minimal shape suffices.
        let existing = serde_json::json!({
            "name": "hello", "version": "2.10", "revision": 7,
            "target": host_target(), "files": [],
            "signer": "", "signature": ""
        })
        .to_string()
        .into_bytes();
        let gets = BTreeMap::from([("manifests/hello.json".to_string(), (200u16, existing))]);
        let (_out, fake) = release_hello(work.path(), gets);
        let bytes = fake.body("manifests/hello.json");
        let manifest: PackageManifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(manifest.revision, 8, "tree revision 7 → release 8");
    }

    #[test]
    fn tree_index_upsert_preserves_other_rows_and_sorts() {
        if !squashfs_available() {
            return;
        }
        let work = tempfile::tempdir().unwrap();
        let existing_index = serde_json::json!({
            "name": "farm-0",
            "packages": [
                { "name": "hello", "version": "1.0", "revision": 3 },
                { "name": "zeta", "version": "0.4", "revision": 2 }
            ]
        })
        .to_string()
        .into_bytes();
        let gets = BTreeMap::from([("index.json".to_string(), (200u16, existing_index))]);
        let (_out, fake) = release_hello(work.path(), gets);
        let bytes = fake.body(INDEX_KEY);
        let index: TreeIndexJson = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(index.name, "farm-0", "the publishing-host name stays");
        let names: Vec<&str> = index.packages.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["hello", "zeta"], "sorted, other rows kept");
        let hello = index.packages.iter().find(|r| r.name == "hello").unwrap();
        assert_eq!(hello.version, "2.10");
        assert_eq!(hello.revision, 1);
    }

    #[test]
    fn unparseable_existing_tree_manifest_is_a_refusal() {
        if !squashfs_available() {
            return;
        }
        let work = tempfile::tempdir().unwrap();
        let gets = BTreeMap::from([(
            "manifests/hello.json".to_string(),
            (200u16, b"not json".to_vec()),
        )]);
        let snap = build_test_snap(work.path(), "hello", "2.10");
        let input = test_input(
            work.path(),
            &snap,
            "hello",
            "2.10",
            "https://s3.internal.example",
        );
        let fake = FakeRustfs::new(gets);
        let puts = fake.puts.clone();
        let client = S3Client::with_runner(input.s3.clone(), Box::new(fake)).unwrap();
        let err = release_with(&input, &client).unwrap_err().to_string();
        assert!(err.contains("does not parse"), "{err}");
        assert!(puts.keys().is_empty(), "nothing uploaded: {err}");
    }

    // ── loopback end-to-end (real curl, no TLS, no external network) ──

    /// The recorded tree of the fake S3 listener.
    #[derive(Default)]
    struct FakeTree {
        objects: BTreeMap<String, Vec<u8>>,
        order: Vec<(String, String)>, // (method, key)
    }

    /// A hand-rolled S3 listener (the secrets.rs TcpListener
    /// precedent): answers GET from `objects`, records PUTs into it,
    /// and logs the request order.
    fn spawn_fake_s3(bucket: &'static str) -> (u16, std::sync::Arc<Mutex<FakeTree>>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let tree = std::sync::Arc::new(Mutex::new(FakeTree::default()));
        let tree_thread = tree.clone();
        std::thread::spawn(move || {
            for sock in listener.incoming().flatten() {
                let mut sock = sock;
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                // Read until the end of the headers.
                let header_end = loop {
                    match sock.read(&mut chunk) {
                        Ok(0) => break buf.len(),
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                                break pos + 4;
                            }
                        }
                        Err(_) => return,
                    }
                };
                let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
                let request_line = head.lines().next().unwrap_or_default().to_string();
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or_default().to_string();
                let path = parts.next().unwrap_or_default().to_string();
                let key = path
                    .split_once(&format!("/{bucket}/"))
                    .map(|(_, rest)| rest.to_string())
                    .unwrap_or_default();
                let content_length = head
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                    .and_then(|l| l.split(':').nth(1))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if head.to_ascii_lowercase().contains("expect: 100-continue") {
                    let _ = sock.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
                }
                let mut body = buf[header_end..].to_vec();
                while body.len() < content_length {
                    match sock.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => body.extend_from_slice(&chunk[..n]),
                        Err(_) => return,
                    }
                }
                let response = match method.as_str() {
                    "GET" => tree_thread.lock().unwrap().objects.get(&key).map(|bytes| {
                        (
                            200u16,
                            format!("Content-Length: {}", bytes.len()),
                            bytes.clone(),
                        )
                    }),
                    "PUT" => {
                        tree_thread
                            .lock()
                            .unwrap()
                            .objects
                            .insert(key.clone(), body);
                        tree_thread
                            .lock()
                            .unwrap()
                            .order
                            .push((method.clone(), key.clone()));
                        Some((200, "Content-Length: 0".to_string(), Vec::new()))
                    }
                    _ => None,
                };
                let (status, extra, resp_body) =
                    response.unwrap_or((404, "Content-Length: 0".to_string(), Vec::new()));
                let _ = sock.write_all(
                    format!("HTTP/1.1 {status} X\r\n{extra}\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                );
                let _ = sock.write_all(&resp_body);
            }
        });
        (port, tree)
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    #[test]
    fn loopback_fake_s3_end_to_end() {
        if !squashfs_available() {
            return;
        }
        if !has_tool("curl") {
            eprintln!("skipping: curl unavailable");
            return;
        }
        let work = tempfile::tempdir().unwrap();
        let snap = build_test_snap(work.path(), "hello", "2.10");
        let (port, tree) = spawn_fake_s3("nau-tree");
        let input = test_input(
            work.path(),
            &snap,
            "hello",
            "2.10",
            &format!("http://127.0.0.1:{port}"),
        );
        let out = release(&input).expect("release over loopback rustfs");

        let tree = tree.lock().unwrap();
        // Ordering: blobs first, manifest, then the index.
        let kinds: Vec<&str> = tree
            .order
            .iter()
            .map(|(_, key)| {
                if key.starts_with("blobs/") {
                    "blob"
                } else if key.starts_with("manifests/") {
                    "manifest"
                } else {
                    "index"
                }
            })
            .collect();
        assert_eq!(
            kinds,
            vec!["blob", "blob", "blob", "manifest", "index"],
            "PUT order: {:?}",
            tree.order
        );

        // The served tree is pullable: the manifest the listener stored
        // parses, verifies, and its blobs hash-match.
        let manifest_bytes = tree.objects.get("manifests/hello.json").unwrap();
        let manifest: PackageManifest = serde_json::from_slice(manifest_bytes).unwrap();
        let kp = test_kp(7);
        pkg_manifest::verify(&manifest, &kp.public_hex()).expect("stored manifest verifies");
        for file in &manifest.files {
            let stored = tree.objects.get(&blob_key(&file.sha256)).unwrap();
            assert_eq!(crate::oci::sha256_hex(stored), file.sha256);
        }
        assert_eq!(
            out.manifest_url,
            "https://download.example/nau/manifests/hello.json"
        );
    }
}
