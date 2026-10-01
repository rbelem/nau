//! `nau export` — the static-HTTP lane (ADR-0033 Decision 10):
//! freeze a pod store's shareable content as a plain directory tree
//! (`index.json`, `manifests/<pkg>.json`, `blobs/<sha256>`) any web
//! server can serve — the same layout the `serve` endpoints expose, one
//! to one. `index.json` is the `/info` payload; the manifests are
//! signed [`PackageManifest`]s (ADR-0033 Decision 2); the blobs are the
//! content-addressed store set, copied (never moved — the store keeps
//! its own copies).
//!
//! # Union rule (ADR-0033 Decision 5 invariant)
//!
//! Export publishes the UNION of the active generation's packages and
//! the pull-staging inbox (`nau_core::pkg_manifest::manifest_path`): an
//! inbox manifest whose name is not in the generation is still visible,
//! copied VERBATIM (it arrived signed from a peer — re-signing it here
//! would rewrite provenance). Names present in the generation are
//! minted fresh from the generation records and signed under this
//! host's key.
//!
//! # Fail-closed
//!
//! A missing store blob is a hard error naming the package and the hash
//! — never a skip: a mirror publishing a partial tree would hand peers
//! unverifiable content. An empty store (no generation packages, no
//! inbox) is a clear error, not an empty tree.
//!
//! # Ownership and pruning (ADR-0033 Decision 10)
//!
//! Every export writes a `.nau-export` marker at the out root
//! (content: the tree format version). On a re-export of a directory
//! that HAS the marker, stale entries are pruned: manifests and blobs
//! no longer part of the exportable set are removed, so a mirror never
//! advertises packages the pod dropped. A directory WITHOUT the marker
//! was not written by nau — it accumulates exactly as before,
//! deleting nothing it did not write (and gets claimed by the marker
//! from that export on).
//!
//! # Curation (the per-mission mirror, #275)
//!
//! `run_mission` exports a CURATED tree: only the packages one mission
//! pins. The pin set is the mission's existing `image()` declaration —
//! the names [`nau_core::manifest_ir::ImageDeclaration::all_snaps`]
//! collects (base, kernel, gadget, declared snaps) — no new schema. A
//! pinned name the pool does not hold is a hard, named error BEFORE
//! anything is written: a mirror missing a mission's pinned package
//! would hand its users an unverifiable tree. The pull-staging inbox is
//! out of scope for a curated export — a mission pins a closed set;
//! staged peer content is not the released pool.
//!
//! # Determinism
//!
//! A re-export of the same pool + mission is byte-identical: packages
//! iterate in `BTreeMap` order, JSON is written in struct field order,
//! and the ed25519 signature is deterministic (RFC 8032) — same store,
//! same key, same bytes.
//!
//! Issue #326 PR 5 (crate extraction): the env-reading pod roots stay
//! root — the caller resolves `pod_root(None)` and hands it in; the
//! store view consumed here is the narrow core seam
//! ([`nau_core::blob_store::BlobStore`] + the generation view), never
//! the root `RuntimeStore`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, WrapErr};
use nau_core::blob_store::BlobStore;
use nau_core::generation_view;
use nau_core::manifest_ir::ImageDeclaration;
use nau_core::pkg_manifest::{self, Generation, PackageManifest};
use nau_core::sign::KeyPair;
use serde::{Deserialize, Serialize};

/// The per-mission curation list (#275): the package names one mission
/// pins, applied at export time. A set — the base/kernel/gadget refs
/// may repeat a name, and set semantics keep the resolved pin set
/// canonical.
pub type Curation = BTreeSet<String>;

/// The curation list of one mission: the names its `image()`
/// declaration pins. This is the existing mission schema — the same
/// declaration `nau image --output-name` builds from; export adds
/// no new pin format.
pub fn mission_curation(image: &ImageDeclaration) -> Curation {
    image
        .all_snaps()
        .into_iter()
        .map(|snap| snap.name.clone())
        .collect()
}

/// Resolve a curation list against the pool's generation: every pinned
/// name must be exportable, fail-closed (naming the missing pins —
/// sorted, since `Curation` iteration is ordered). Returns the keep
/// set the generation walk filters on.
fn resolve_pins(
    generation: &Option<Generation>,
    pins: &Curation,
) -> miette::Result<BTreeSet<String>> {
    if pins.is_empty() {
        miette::bail!("mission pins no packages — nothing to curate");
    }
    let mut resolved = BTreeSet::new();
    let mut missing = Vec::new();
    for name in pins {
        if generation
            .as_ref()
            .is_some_and(|g| g.packages.contains_key(name))
        {
            resolved.insert(name.clone());
        } else {
            missing.push(name.clone());
        }
    }
    if !missing.is_empty() {
        miette::bail!(
            "mission pool is missing pinned package(s): {} — refusing \
             to export an incomplete curated tree",
            missing.join(", ")
        );
    }
    Ok(resolved)
}

/// One package row of `index.json`.
#[derive(Debug, Serialize, Deserialize)]
struct IndexPackage {
    name: String,
    version: String,
    revision: u32,
}

/// `index.json` — the static mirror's `/info` payload (ADR-0033
/// Decision 10): the publishing host name plus every exportable
/// package.
#[derive(Debug, Serialize, Deserialize)]
struct IndexJson {
    name: String,
    packages: Vec<IndexPackage>,
}

/// The ownership marker written at the out root on every export
/// (ADR-0033 Decision 10): its presence proves nau wrote the tree,
/// licensing re-export pruning.
const MARKER_FILE: &str = ".nau-export";

/// The marker's content: the export-tree format version, one line.
const MARKER_VERSION: &str = "v1";

/// Run `nau export` into `out` for the named pod (`None` = the
/// default pod). `pod_root` is the pod state root the flag resolves
/// under — resolved by the root glue (the env-reading `pod_root` stays
/// root).
pub fn run(out: &str, pod_root: &Path, pod: Option<&str>) -> miette::Result<()> {
    export_at(out, pod_root, pod, None)
}

/// Run a CURATED `nau export` (#275): only the packages `curation`
/// pins, for the named pod. Every pinned name must be in the pool —
/// anything else is a named, fail-closed error before the tree is
/// touched.
pub fn run_mission(
    out: &str,
    pod_root: &Path,
    pod: Option<&str>,
    curation: &Curation,
) -> miette::Result<()> {
    export_at(out, pod_root, pod, Some(curation))
}

fn export_at(
    out: &str,
    pod_root: &Path,
    pod: Option<&str>,
    curation: Option<&Curation>,
) -> miette::Result<()> {
    let pod_name = pod.unwrap_or(nau_core::paths::DEFAULT_POD);
    let dir = nau_core::paths::pod_dir(pod_root, pod_name);
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
    run_at(
        Path::new(out),
        &dir,
        // The store dir half of the runtime state layout
        // (`<state root>/store` — the component the inbox helpers
        // derive from), built straight over it via the core seam.
        &BlobStore::new(dir.join("store")),
        &home,
        curation,
    )
}

/// Export the pod store rooted at `state_root` into `out`, signing
/// minted manifests with the operator key under `home`. Split from
/// [`run`] so tests can inject the store root and signing-key home.
/// `curation` narrows the export to a mission's pinned set (`None` =
/// the whole exportable store, the historical behavior).
fn run_at(
    out: &Path,
    state_root: &Path,
    blobs: &BlobStore,
    home: &Path,
    curation: Option<&Curation>,
) -> miette::Result<()> {
    let generation = generation_view::active_generation(state_root)?;
    // Curation resolves BEFORE the tree is touched: a mission pinning a
    // package the pool does not hold is a named error, never a partial
    // mirror.
    let keep = curation
        .map(|pins| resolve_pins(&generation, pins))
        .transpose()?;
    let (inbox, generation_has_packages) = select_pool(state_root, &generation, &keep)?;
    let inbox_only = pkg_manifest::union_inbox(&generation, &inbox);
    ensure_exportable(state_root, generation_has_packages, &inbox_only)?;
    let (manifests_dir, blobs_dir) = prepare_dirs(out)?;
    // Ownership is decided from the directory AS FOUND: a tree nau
    // wrote before (marker present) gets stale-entry pruning this
    // export; a foreign directory accumulates, deleting nothing.
    let owned = out.join(MARKER_FILE).exists();

    let (copied, mut packages) = write_tree(
        blobs,
        &Sinks {
            manifests: &manifests_dir,
            blobs: &blobs_dir,
            home,
        },
        &generation,
        &inbox_only,
        keep.as_ref(),
    )?;

    // Canonical index order regardless of generation-vs-inbox split.
    packages.sort_by(|a, b| a.name.cmp(&b.name));

    // Prune BEFORE the index lands: an owned tree briefly carrying a
    // fresh index beside stale entries is the one state that lets a
    // mirror advertise content the pod dropped.
    if owned {
        prune_stale(
            &manifests_dir,
            &blobs_dir,
            &manifest_names(&packages),
            &copied,
        )?;
    }
    write_marker(out)?;

    // index.json is written LAST: a half-updated mirror never advertises
    // packages whose manifests/blobs have not landed yet.
    let index = IndexJson {
        name: pkg_manifest::hostname(),
        packages,
    };
    write_json(&out.join("index.json"), &index)
}

/// The exportable pool split for this run: the staged-inbox additions
/// (empty under curation — a mission pins a closed set, staged peer
/// content is not the released pool) and whether the generation itself
/// carries anything to export.
fn select_pool(
    state_root: &Path,
    generation: &Option<Generation>,
    keep: &Option<BTreeSet<String>>,
) -> miette::Result<(Vec<(String, PathBuf)>, bool)> {
    match keep {
        Some(keep) => Ok((Vec::new(), !keep.is_empty())),
        None => {
            let inbox = pkg_manifest::inbox_manifests(state_root)?;
            let generation_has_packages =
                generation.as_ref().is_some_and(|g| !g.packages.is_empty());
            Ok((inbox, generation_has_packages))
        }
    }
}

/// The write destinations of one export run: the tree's `manifests/`
/// and `blobs/` directories plus the signing-key home. Bundled so the
/// walk helpers take one destination argument, not three.
struct Sinks<'a> {
    manifests: &'a Path,
    blobs: &'a Path,
    home: &'a Path,
}

/// Export every manifest + blob of the current exportable set into the
/// tree. Returns the copied blob hashes (the `blobs/` keep set) and
/// the index rows (from which the `manifests/` keep set derives).
fn write_tree(
    blobs: &BlobStore,
    sinks: &Sinks,
    generation: &Option<Generation>,
    inbox_only: &[&(String, PathBuf)],
    keep: Option<&BTreeSet<String>>,
) -> miette::Result<(BTreeSet<String>, Vec<IndexPackage>)> {
    // Dedup across packages: a shared blob is copied once (content
    // addressing makes re-copies byte-identical, so this is purely
    // fewer syscalls — never a divergence risk).
    let mut copied: BTreeSet<String> = BTreeSet::new();
    let mut packages: Vec<IndexPackage> = Vec::new();

    if let Some(gen) = generation {
        export_generation(blobs, sinks, gen, keep, &mut copied, &mut packages)?;
    }
    export_inbox(blobs, sinks, inbox_only, &mut copied, &mut packages)?;
    Ok((copied, packages))
}

/// Claim (or re-assert) ownership of `out`: the marker is written on
/// EVERY export, so the next export may prune (ADR-0033 Decision 10).
/// A first export into a foreign directory claims it from then on.
fn write_marker(out: &Path) -> miette::Result<()> {
    let path = out.join(MARKER_FILE);
    std::fs::write(&path, format!("{MARKER_VERSION}\n"))
        .into_diagnostic()
        .wrap_err_with(|| format!("writing {}", path.display()))
}

/// The manifest file names the current exportable set owns — the keep
/// set for `manifests/` pruning.
fn manifest_names(packages: &[IndexPackage]) -> BTreeSet<String> {
    packages
        .iter()
        .map(|p| format!("{}.json", p.name))
        .collect()
}

/// Remove manifests and blobs left over from earlier exports that the
/// current exportable set no longer covers. Only ever called on an
/// owned tree (the [`MARKER_FILE`] gate): entries the current export
/// wrote are exactly the keep sets, everything else is a straggler.
fn prune_stale(
    manifests_dir: &Path,
    blobs_dir: &Path,
    keep_manifests: &BTreeSet<String>,
    keep_blobs: &BTreeSet<String>,
) -> miette::Result<()> {
    prune_dir(manifests_dir, keep_manifests)?;
    prune_dir(blobs_dir, keep_blobs)
}

/// Remove the plain files of `dir` whose names are not in `keep`.
/// Anything not a plain file (a foreign subdirectory, say) is left
/// alone — pruning reclaims nau's own stale entries, nothing else.
fn prune_dir(dir: &Path, keep: &BTreeSet<String>) -> miette::Result<()> {
    for entry in std::fs::read_dir(dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading {}", dir.display()))?
    {
        let entry = entry
            .into_diagnostic()
            .wrap_err_with(|| format!("reading {}", dir.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_file = entry.file_type().map(|t| t.is_file()).unwrap_or(false);
        if keep.contains(&name) || !is_file {
            continue;
        }
        std::fs::remove_file(entry.path())
            .into_diagnostic()
            .wrap_err_with(|| format!("pruning stale export entry {}", entry.path().display()))?;
    }
    Ok(())
}

/// An empty store is a clear error, not an empty tree: nothing is
/// exportable when the generation carries no packages AND the inbox is
/// empty. `generation_has_packages` arrives pre-computed (under
/// curation it reflects the resolved keep set, not the raw generation).
fn ensure_exportable(
    store_root: &Path,
    generation_has_packages: bool,
    inbox_only: &[&(String, PathBuf)],
) -> miette::Result<()> {
    if !generation_has_packages && inbox_only.is_empty() {
        miette::bail!(
            "pod store {} is empty — no installed packages and no staged \
             peer manifests; nothing to export",
            store_root.display()
        );
    }
    Ok(())
}

/// Create the tree's directories. Idempotent: create and overwrite in
/// place; never clear `out` — an operator may hold unrelated files
/// beside the tree.
fn prepare_dirs(out: &Path) -> miette::Result<(PathBuf, PathBuf)> {
    let manifests_dir = out.join("manifests");
    let blobs_dir = out.join("blobs");
    std::fs::create_dir_all(&manifests_dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", manifests_dir.display()))?;
    std::fs::create_dir_all(&blobs_dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", blobs_dir.display()))?;
    Ok((manifests_dir, blobs_dir))
}

/// Mint + sign one manifest per generation package and copy its blobs
/// (ADR-0033 Decision 2: unsigned store entries are never served — the
/// signing key is required and its absence is a named error). `keep`
/// narrows the walk to a mission's pinned names (`None` = all).
fn export_generation(
    blobs: &BlobStore,
    sinks: &Sinks,
    gen: &Generation,
    keep: Option<&BTreeSet<String>>,
    copied: &mut BTreeSet<String>,
    packages: &mut Vec<IndexPackage>,
) -> miette::Result<()> {
    let mut signing: Option<KeyPair> = None;
    // BTreeMap iteration: sorted by name — deterministic tree, and the
    // first missing-blob error is the alphabetically first package.
    for record in gen.packages.values() {
        if let Some(keep) = keep {
            if !keep.contains(&record.name) {
                continue;
            }
        }
        if signing.is_none() {
            signing = Some(pkg_manifest::load_signing_key(sinks.home)?);
        }
        let mut manifest = pkg_manifest::mint_manifest(record);
        pkg_manifest::sign(&mut manifest, signing.as_ref().expect("key loaded above"))?;
        write_json(
            &sinks.manifests.join(format!("{}.json", record.name)),
            &manifest,
        )?;
        for hash in &record.files {
            copy_blob(blobs, sinks.blobs, hash, &record.name, copied)?;
        }
        packages.push(IndexPackage {
            name: record.name.clone(),
            version: record.version.clone(),
            revision: record.revision,
        });
    }
    Ok(())
}

/// Copy the inbox-only manifests VERBATIM plus their blobs. The stored
/// manifest is read only to learn the blob set and index row — it is
/// never altered or re-signed (it arrived signed from a peer). Its
/// declared blob addresses are still trust-boundary-validated before
/// anything touches `store.blob_path` — a malformed sha256 in a staged
/// manifest never becomes a path.
fn export_inbox(
    blobs: &BlobStore,
    sinks: &Sinks,
    inbox_only: &[&(String, PathBuf)],
    copied: &mut BTreeSet<String>,
    packages: &mut Vec<IndexPackage>,
) -> miette::Result<()> {
    for (name, path) in inbox_only {
        export_one_staged(blobs, sinks, name, path, copied, packages)?;
    }
    Ok(())
}

/// One staged manifest, verbatim + its blob set, into the tree.
fn export_one_staged(
    blobs: &BlobStore,
    sinks: &Sinks,
    name: &str,
    path: &PathBuf,
    copied: &mut BTreeSet<String>,
    packages: &mut Vec<IndexPackage>,
) -> miette::Result<()> {
    let raw = std::fs::read(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading staged manifest {}", path.display()))?;
    let manifest: PackageManifest = serde_json::from_slice(&raw).map_err(|e| {
        miette::miette!(
            "staged manifest {} for package '{name}' does not parse: {e}",
            path.display()
        )
    })?;
    validate_staged_hashes(name, &manifest)?;
    std::fs::copy(path, sinks.manifests.join(format!("{name}.json")))
        .into_diagnostic()
        .wrap_err_with(|| format!("copying staged manifest for '{name}'"))?;
    for file in &manifest.files {
        copy_blob(blobs, sinks.blobs, &file.sha256, name, copied)?;
    }
    packages.push(IndexPackage {
        name: name.to_string(),
        version: manifest.version,
        revision: manifest.revision,
    });
    Ok(())
}

/// Trust-boundary validation of a staged manifest's declared blob
/// addresses BEFORE any of them becomes a path: 64 lowercase hex, each.
fn validate_staged_hashes(name: &str, manifest: &PackageManifest) -> miette::Result<()> {
    for file in &manifest.files {
        pkg_manifest::validate_sha256(file)
            .wrap_err_with(|| format!("staged manifest for package '{name}'"))?;
    }
    Ok(())
}

/// Copy one content blob from the store into the tree. Already-copied
/// hashes are skipped (dedup); a missing source is a HARD error naming
/// the package and hash — a partial tree must never be published
/// (fail-closed, ADR-0033 Decision 10).
fn copy_blob(
    blobs: &BlobStore,
    blobs_dir: &Path,
    sha256: &str,
    pkg: &str,
    copied: &mut BTreeSet<String>,
) -> miette::Result<()> {
    if !copied.insert(sha256.to_string()) {
        return Ok(());
    }
    let src = blobs.blob_path(sha256);
    if !src.exists() {
        miette::bail!(
            "package '{pkg}': store blob {sha256} is missing at {} — \
             refusing to export an incomplete tree",
            src.display()
        );
    }
    let dst = blobs_dir.join(sha256);
    std::fs::copy(&src, &dst)
        .into_diagnostic()
        .wrap_err_with(|| format!("copying blob {} → {}", src.display(), dst.display()))?;
    Ok(())
}

// Minting lives in [`pkg_manifest::mint_manifest`] — the one mint both
// serve and export call, so a mirror's `manifests/<pkg>.json` is byte-
// identical to what `/manifests/<pkg>` serves (ADR-0033 Decision 2).
// The inbox listing is [`pkg_manifest::inbox_manifests`] and the
// publishing host name [`pkg_manifest::hostname`] — both shared with
// `serve /info`.

/// Stable serde JSON to disk (struct field order + BTreeMap key order =
/// deterministic bytes; pretty-printed for mirror inspection).
fn write_json<T: Serialize>(path: &Path, value: &T) -> miette::Result<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| miette::miette!("serialize {}: {e}", path.display()))?;
    std::fs::write(path, bytes)
        .into_diagnostic()
        .wrap_err_with(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nau_core::generation_view;
    use nau_core::pkg_manifest::{ClaimLayer, InstallMeta, InstalledPackage, ManifestFile};
    use sha2::Digest as _;
    use std::collections::BTreeMap;

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
        let gen = Generation {
            n: 1,
            base_version: "25.04".into(),
            packages,
            created_epoch: 0,
            boot_entry: None,
        };
        let gen_dir = generation_view::generation_dir(&state_root, 1);
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
        pkg_manifest::sign(&mut gamma, &peer).unwrap();
        let inbox_path = pkg_manifest::manifest_path(&state_root, "gamma");
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

    #[test]
    fn tree_shape_index_manifests_and_deduped_blobs() {
        let fx = fabricate();
        run_at(&fx.out, &fx.state_root, &fx.blobs, fx._home.path(), None).unwrap();

        // index.json parses and lists every exportable package.
        let index: IndexJson =
            serde_json::from_str(&std::fs::read_to_string(fx.out.join("index.json")).unwrap())
                .unwrap();
        assert!(!index.name.is_empty());
        let rows: Vec<(&str, &str, u32)> = index
            .packages
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str(), p.revision))
            .collect();
        assert_eq!(
            rows,
            vec![("alpha", "1.0", 4), ("beta", "2.1", 9), ("gamma", "0.4", 3),]
        );

        // Generation manifests verify under the operator key; the
        // verbatim inbox manifest under its original peer key.
        let operator = fx.kp.public_hex();
        let peer = inbox_kp(9).public_hex();
        for (name, key) in [("alpha", &operator), ("beta", &operator), ("gamma", &peer)] {
            let manifest: PackageManifest = serde_json::from_str(
                &std::fs::read_to_string(fx.out.join("manifests").join(format!("{name}.json")))
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(manifest.name, name);
            pkg_manifest::verify(&manifest, key)
                .unwrap_or_else(|e| panic!("{name} must verify: {e}"));
        }

        // Blobs: exactly the union set — the shared blob copied ONCE —
        // and every file's bytes hash to its content address.
        let mut blobs: Vec<String> = std::fs::read_dir(fx.out.join("blobs"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        blobs.sort();
        let mut expected = vec![h(SHARED), h(ALPHA_ONLY), h(BETA_ONLY), h(GAMMA_BLOB)];
        expected.sort();
        assert_eq!(blobs, expected, "shared blob must be copied exactly once");

        for name in &blobs {
            let bytes = std::fs::read(fx.out.join("blobs").join(name)).unwrap();
            let digest = sha2::Sha256::digest(&bytes);
            assert_eq!(format!("{digest:x}"), *name, "blob {name} bytes mismatch");
        }
    }

    /// A staged inbox manifest carrying a malformed blob address is
    /// refused BEFORE the address becomes a store path — trust-
    /// boundary validation on export's verbatim-inbox lane.
    #[test]
    fn export_refuses_a_staged_manifest_with_malformed_blob_hashes() {
        let fx = fabricate();
        let inbox_path = pkg_manifest::manifest_path(&fx.state_root, "gamma");
        let mut gamma: PackageManifest =
            serde_json::from_str(&std::fs::read_to_string(&inbox_path).unwrap()).unwrap();
        gamma.files[0].sha256 = "../../etc/passwd".to_string();
        std::fs::write(&inbox_path, serde_json::to_vec(&gamma).unwrap()).unwrap();

        let err = run_at(&fx.out, &fx.state_root, &fx.blobs, fx._home.path(), None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("64 lowercase hex"), "names the rule: {msg}");
        assert!(msg.contains("gamma"), "names the package: {msg}");
        assert!(
            !fx.out.join("manifests").join("gamma.json").exists(),
            "nothing copied for a malformed staged manifest"
        );
    }

    #[test]
    fn missing_blob_names_package_and_hash() {
        let fx = fabricate();
        let alpha_hash = h(ALPHA_ONLY);
        std::fs::remove_file(fx.blobs.blob_path(&alpha_hash)).unwrap();

        let err = run_at(&fx.out, &fx.state_root, &fx.blobs, fx._home.path(), None).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("alpha"), "error must name the package: {msg}");
        assert!(msg.contains(&alpha_hash), "error must name the hash: {msg}");
    }

    #[test]
    fn empty_store_is_a_clear_error_not_an_empty_tree() {
        let state = tempfile::tempdir().unwrap();
        let blobs = BlobStore::new(state.path().join("store"));
        let home = tempfile::tempdir().unwrap();
        let out = state.path().join("tree");

        let err = run_at(&out, state.path(), &blobs, home.path(), None).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("empty"), "error must say empty: {msg}");
        assert!(
            !out.join("index.json").exists(),
            "no tree may be written for an empty store"
        );
    }

    #[test]
    fn run_is_idempotent_and_never_clears_out() {
        let fx = fabricate();
        let keep = fx.out.join("operator-file.txt");
        std::fs::create_dir_all(&fx.out).unwrap();
        std::fs::write(&keep, b"mine").unwrap();

        run_at(&fx.out, &fx.state_root, &fx.blobs, fx._home.path(), None).unwrap();
        run_at(&fx.out, &fx.state_root, &fx.blobs, fx._home.path(), None).unwrap();

        assert_eq!(std::fs::read(&keep).unwrap(), b"mine");
        assert_eq!(
            std::fs::read(fx.out.join("blobs").join(h(SHARED))).unwrap(),
            b"shared-blob-bytes"
        );
    }

    /// An owned tree (marker present) prunes on re-export: a package
    /// removed from the store loses its manifest and its no-longer-
    /// shared blobs; survivors stay byte-intact (ADR-0033 Decision 10).
    #[test]
    fn owned_reexport_prunes_removed_packages() {
        let fx = fabricate();
        run_at(&fx.out, &fx.state_root, &fx.blobs, fx._home.path(), None).unwrap();
        assert_eq!(
            std::fs::read_to_string(fx.out.join(MARKER_FILE))
                .unwrap()
                .trim(),
            MARKER_VERSION,
            "every export writes the ownership marker"
        );

        // beta leaves the store: generation 1 is rewritten with alpha.
        let gen_dir = generation_view::generation_dir(&fx.state_root, 1);
        let mut gen: Generation =
            serde_json::from_str(&std::fs::read_to_string(gen_dir.join("manifest.json")).unwrap())
                .unwrap();
        gen.packages.remove("beta");
        std::fs::write(
            gen_dir.join("manifest.json"),
            serde_json::to_vec(&gen).unwrap(),
        )
        .unwrap();

        run_at(&fx.out, &fx.state_root, &fx.blobs, fx._home.path(), None).unwrap();

        assert!(
            !fx.out.join("manifests").join("beta.json").exists(),
            "stale manifest pruned"
        );
        assert!(
            !fx.out.join("blobs").join(h(BETA_ONLY)).exists(),
            "stale blob pruned"
        );
        assert!(
            fx.out.join("manifests").join("alpha.json").exists()
                && fx.out.join("manifests").join("gamma.json").exists(),
            "surviving manifests intact"
        );
        for keep in [h(SHARED), h(ALPHA_ONLY), h(GAMMA_BLOB)] {
            assert!(
                fx.out.join("blobs").join(&keep).exists(),
                "surviving blob {keep} intact"
            );
        }
        let index: IndexJson =
            serde_json::from_str(&std::fs::read_to_string(fx.out.join("index.json")).unwrap())
                .unwrap();
        assert!(index.packages.iter().all(|p| p.name != "beta"));
    }

    /// A directory without the marker is foreign: re-export accumulates
    /// and deletes nothing (a stray manifest and blob pre-seeded beside
    /// the operator's file survive) — and it is claimed by the marker,
    /// so the NEXT export prunes those stragglers.
    #[test]
    fn foreign_directory_accumulates_then_gets_claimed() {
        let fx = fabricate();
        std::fs::create_dir_all(fx.out.join("manifests")).unwrap();
        std::fs::create_dir_all(fx.out.join("blobs")).unwrap();
        let foreign = fx.out.join("operator-file.txt");
        std::fs::write(&foreign, b"mine").unwrap();
        let stray_manifest = fx.out.join("manifests").join("ghost.json");
        let stray_blob = fx.out.join("blobs").join("0".repeat(64));
        std::fs::write(&stray_manifest, b"{}").unwrap();
        std::fs::write(&stray_blob, b"stray").unwrap();

        // First export: no marker found → zero deletions.
        run_at(&fx.out, &fx.state_root, &fx.blobs, fx._home.path(), None).unwrap();
        assert_eq!(std::fs::read(&foreign).unwrap(), b"mine");
        assert!(stray_manifest.exists(), "marker-less dir: no deletions");
        assert!(stray_blob.exists(), "marker-less dir: no deletions");

        // Claimed by the first export: the next one prunes the strays.
        run_at(&fx.out, &fx.state_root, &fx.blobs, fx._home.path(), None).unwrap();
        assert!(!stray_manifest.exists(), "owned now: stale manifest pruned");
        assert!(!stray_blob.exists(), "owned now: stale blob pruned");
        assert_eq!(
            std::fs::read(&foreign).unwrap(),
            b"mine",
            "out-root files are never touched"
        );
    }

    /// The minted manifest carries the generation record's install
    /// metadata (Decision 2: metadata must travel) — spot-check via the
    /// apps map and the record's `requires`.
    #[test]
    fn minted_manifest_travels_install_metadata() {
        let shared = h(SHARED);
        let bin_hash = h(b"hello-bin-bytes");
        let mut apps = BTreeMap::new();
        apps.insert("hello".to_string(), bin_hash.clone());
        let mut rec = record("alpha", "1.0", 4, vec![shared, bin_hash.clone()]);
        rec.apps = apps.clone();
        rec.requires = vec!["libc6".into()];

        let manifest = pkg_manifest::mint_manifest(&rec);
        assert_eq!(manifest.install.apps, apps);
        assert_eq!(manifest.install.requires, vec!["libc6".to_string()]);
        // The command binary is the one file marked executable.
        let exe: Vec<&ManifestFile> = manifest.files.iter().filter(|f| f.executable).collect();
        assert_eq!(exe.len(), 1);
        assert_eq!(exe[0].sha256, bin_hash);
    }

    // ── #275: the per-mission mirror — curation + determinism ──

    use nau_core::manifest_ir::KernelEntry;
    use nau_core::snap_types::SnapRef;

    /// A mission declaration in the image-module test shape: base +
    /// kernel + one extra snap. The pin set export curates from — the
    /// same `image()` schema `nau image` consumes, no new format.
    fn mission() -> ImageDeclaration {
        ImageDeclaration {
            name: "workstation".into(),
            version: "1.0".into(),
            base: SnapRef {
                name: "alpha".into(),
                revision: None,
                sha3_384: None,
            },
            kernel: Some(KernelEntry {
                snap: SnapRef {
                    name: "beta".into(),
                    revision: None,
                    sha3_384: None,
                },
                params: vec![],
                modules: vec![],
                modprobe_config: None,
                channel: None,
            }),
            gadget: None,
            gadget_channel: None,
            extra_snaps: vec![SnapRef {
                name: "gamma".into(),
                revision: None,
                sha3_384: None,
            }],
            bootloader: None,
            disk: None,
            sysctl: vec![],
            update_source: None,
            files: vec![],
            boot_health_exec: None,
        }
    }

    fn set(names: &[&str]) -> Curation {
        names.iter().map(|n| n.to_string()).collect()
    }

    /// Recursive map of every file under `dir`: relative path → bytes.
    /// The byte-for-byte comparison the determinism test asserts on.
    fn tree_bytes(dir: &Path) -> BTreeMap<String, Vec<u8>> {
        fn walk(root: &Path, dir: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                if path.is_dir() {
                    walk(root, &path, files);
                } else {
                    let rel = path
                        .strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned();
                    files.insert(rel, std::fs::read(&path).unwrap());
                }
            }
        }
        let mut files = BTreeMap::new();
        walk(dir, dir, &mut files);
        files
    }

    #[test]
    fn mission_curation_collects_the_pinned_names() {
        let curation = mission_curation(&mission());
        assert_eq!(
            curation,
            set(&["alpha", "beta", "gamma"]),
            "base + kernel + declared snaps, set-deduped"
        );
    }

    /// A curated export writes ONLY the pinned packages: index rows,
    /// manifests, and blobs exactly the pin set — the unpinned
    /// generation packages and the staged inbox manifest never appear.
    #[test]
    fn curated_export_writes_only_the_pinned_pool() {
        let fx = fabricate();
        let curation = set(&["alpha"]);
        run_at(
            &fx.out,
            &fx.state_root,
            &fx.blobs,
            fx._home.path(),
            Some(&curation),
        )
        .unwrap();

        let index: IndexJson =
            serde_json::from_str(&std::fs::read_to_string(fx.out.join("index.json")).unwrap())
                .unwrap();
        let rows: Vec<&str> = index.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(rows, vec!["alpha"], "index carries exactly the pins");

        let manifests: Vec<String> = std::fs::read_dir(fx.out.join("manifests"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(manifests, vec!["alpha.json"], "unpinned + staged: absent");

        let blobs: Vec<String> = std::fs::read_dir(fx.out.join("blobs"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        let mut expected = vec![h(SHARED), h(ALPHA_ONLY)];
        expected.sort();
        assert_eq!(blobs, expected, "exactly the pinned package's blobs");
    }

    /// A pin the pool does not hold fails the export BEFORE anything is
    /// written — a mirror missing a mission's pinned package would hand
    /// its users an unverifiable tree.
    #[test]
    fn curated_export_missing_pin_fails_closed_before_writing() {
        let fx = fabricate();
        let curation = set(&["alpha", "ghost"]);
        let err = run_at(
            &fx.out,
            &fx.state_root,
            &fx.blobs,
            fx._home.path(),
            Some(&curation),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("ghost"), "names the missing pin: {msg}");
        assert!(
            msg.contains("missing pinned package"),
            "names the rule: {msg}"
        );
        assert!(
            !fx.out.join("index.json").exists(),
            "no tree may be written for unresolved pins"
        );
        assert!(
            !fx.out.join("manifests").join("alpha.json").exists(),
            "nothing copied for unresolved pins"
        );
    }

    #[test]
    fn empty_curation_is_an_error() {
        let fx = fabricate();
        let curation = Curation::new();
        let err = run_at(
            &fx.out,
            &fx.state_root,
            &fx.blobs,
            fx._home.path(),
            Some(&curation),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("pins no packages"), "names the rule: {msg}");
    }

    /// Re-export of the same pool + mission is byte-identical: two
    /// fresh exports AND a re-export into an already-owned tree produce
    /// the same bytes everywhere (BTreeMap order, struct-order JSON,
    /// deterministic ed25519).
    #[test]
    fn curated_reexport_is_byte_identical() {
        let fx = fabricate();
        let curation = set(&["alpha"]);
        let out_b = fx.out.parent().unwrap().join("tree-b");

        run_at(
            &fx.out,
            &fx.state_root,
            &fx.blobs,
            fx._home.path(),
            Some(&curation),
        )
        .unwrap();
        run_at(
            &out_b,
            &fx.state_root,
            &fx.blobs,
            fx._home.path(),
            Some(&curation),
        )
        .unwrap();
        assert_eq!(
            tree_bytes(&fx.out),
            tree_bytes(&out_b),
            "two fresh exports of one pool+mission: identical bytes"
        );

        // Re-export into the owned tree: still identical (pruning
        // rewrites nothing that survives).
        run_at(
            &fx.out,
            &fx.state_root,
            &fx.blobs,
            fx._home.path(),
            Some(&curation),
        )
        .unwrap();
        assert_eq!(
            tree_bytes(&fx.out),
            tree_bytes(&out_b),
            "re-export into an owned tree: identical bytes"
        );
    }
}
