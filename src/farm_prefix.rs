//! The farm-side build prefix (rbelem/nau#338): one request's
//! `requires` ∪ `build_deps` closure resolved against the released tree
//! FIRST, local builds only for tree misses.
//!
//! The pod twin (`pod_build_prefix` → `ensure_pod_dep_payload`) builds
//! every dep locally into the pod's downloads cache. The farm sits beside
//! the tree it serves, so the released per-file blobs are the cheaper and
//! more honest source: content-verified on fetch, no rebuild, no host
//! floor. The ecosystem-deps closures (`deps = { … }`) stay pod-only —
//! they have no tree representation yet (#338 follow-up).
//!
//! Trust boundary: this lane verifies CONTENT (every blob against its
//! manifest sha256 pin, the manifest against the recipe's version and the
//! host target) but not the manifest's ed25519 signature — the same
//! content-trust level as the pod dep lane, inside the farm's own trust
//! domain (the queue-token boundary). Signature-verifying the farm lane
//! needs a worker-side keychain decision and stays open on #338.

use std::path::{Path, PathBuf};

use nau_ship::s3::S3Client;

/// The tree reads the farm dep ensure needs — a thin seam over
/// [`S3Client`] so tests fake the tree without a network (the
/// `BuildStep`/`Releaser` seam pattern).
pub(crate) trait TreeSource {
    /// The package's signed manifest bytes; `None` when unreleased.
    fn manifest(&self, pkg: &str) -> miette::Result<Option<Vec<u8>>>;

    /// One content blob by sha256. A pinned blob that is missing is a
    /// broken tree, not a miss — a hard error, never a fallback.
    fn blob(&self, sha256: &str) -> miette::Result<Vec<u8>>;
}

/// The production tree source: the drain's S3 target.
pub(crate) struct S3Tree {
    client: S3Client,
}

impl S3Tree {
    pub(crate) fn new(client: S3Client) -> Self {
        S3Tree { client }
    }
}

impl TreeSource for S3Tree {
    fn manifest(&self, pkg: &str) -> miette::Result<Option<Vec<u8>>> {
        self.client.get(&format!("manifests/{pkg}.json"))
    }

    fn blob(&self, sha256: &str) -> miette::Result<Vec<u8>> {
        let key = format!("blobs/{sha256}");
        self.client.get(&key)?.ok_or_else(|| {
            miette::miette!("tree blob '{key}' is missing though the manifest pins it")
        })
    }
}

/// The cache marker naming the tree manifest a materialized payload dir
/// came from (`rbelem/nau#344`'s class designed out: a re-release mints a
/// new manifest digest, the marker mismatches, the cache re-materializes —
/// no operator cleanup, no stale adoption).
fn marker_path(cache: &Path, name: &str, version: &str, arch: &str) -> PathBuf {
    cache.join(format!("{name}_{version}_{arch}.manifest-sha256"))
}

fn payload_dir(cache: &Path, name: &str, version: &str, arch: &str) -> PathBuf {
    cache.join(format!("{name}_{version}_{arch}.payload"))
}

/// Ensure one `requires`/`build_deps` member's payload for the merged farm
/// prefix: the released tree first (materialized straight from its
/// content blobs into the cache dir), a fresh local build only for a tree
/// miss or a version/target mismatch.
///
/// Local builds are deliberately NOT cached: an unreleased dep is about to
/// ride this very pipeline to a release, and the next build hits the tree
/// — a persistent local cache would re-create the stale-adoption class the
/// manifest marker exists to prevent.
fn ensure_farm_dep_payload<T: TreeSource>(
    tree: &T,
    cache: &Path,
    name: &str,
    dep_meta: &crate::snap::SnapMeta,
    arch: &str,
    building: &mut Vec<String>,
) -> miette::Result<crate::build_prefix::Payload> {
    std::fs::create_dir_all(cache)
        .map_err(|e| miette::miette!("creating the farm dep cache {}: {e}", cache.display()))?;

    let manifest_bytes = tree.manifest(name)?;
    if let Some(version) = tree_payload(tree, cache, name, dep_meta, arch, &manifest_bytes)? {
        return Ok(crate::build_prefix::Payload {
            pkg: name.to_string(),
            source: crate::build_prefix::PayloadSource::Dir(payload_dir(
                cache, name, &version, arch,
            )),
        });
    }
    build_farm_dep_payload(tree, cache, name, dep_meta, arch, building)
}

/// The tree lane: `Some(version)` when the manifest serves this dep at the
/// recipe's version for this host target, with the payload dir ensured
/// (reused when its manifest-digest marker matches, re-materialized
/// otherwise). `None` hands the dep to the local-build lane.
fn tree_payload<T: TreeSource>(
    tree: &T,
    cache: &Path,
    name: &str,
    dep_meta: &crate::snap::SnapMeta,
    arch: &str,
    manifest_bytes: &Option<Vec<u8>>,
) -> miette::Result<Option<String>> {
    let Some(bytes) = manifest_bytes else {
        return Ok(None);
    };
    let manifest: nau_core::pkg_manifest::PackageManifest =
        serde_json::from_slice(bytes).map_err(|e| {
            miette::miette!("tree manifest for '{name}' does not parse — refusing it: {e}")
        })?;
    if manifest.name != name {
        miette::bail!(
            "tree manifest at manifests/{name}.json names package '{}' — refusing \
             the mismatched manifest",
            manifest.name
        );
    }
    let host = nau_core::pkg_manifest::host_target();
    if manifest.version != dep_meta.version || manifest.target != host {
        crate::output::status(format!(
            "tree serves {name} {} ({}), recipe wants {} {host} — building locally",
            manifest.version, manifest.target, dep_meta.version,
        ));
        return Ok(None);
    }

    let digest = nau_core::cache_key::sha256_hex(bytes);
    let marker = marker_path(cache, name, &manifest.version, arch);
    let fresh = std::fs::read_to_string(&marker).is_ok_and(|recorded| recorded.trim() == digest);
    if !fresh {
        materialize_tree_payload(
            tree,
            &manifest,
            &payload_dir(cache, name, &manifest.version, arch),
        )?;
        std::fs::write(&marker, &digest)
            .map_err(|e| miette::miette!("writing the dep cache marker for '{name}': {e}"))?;
        crate::output::status(format!(
            "tree payload for {name} {} materialized (revision {})",
            manifest.version, manifest.revision,
        ));
    }
    Ok(Some(manifest.version))
}

/// Fetch + verify every manifest file blob into `dir` (atomic: staged in
/// a sibling temp dir INSIDE the cache — a /tmp staging would cross a
/// mount point and `rename` would fail with EXDEV — then renamed in). The
/// marker is written by the caller AFTER this returns, so a torn
/// materialization leaves no marker and re-runs.
fn materialize_tree_payload<T: TreeSource>(
    tree: &T,
    manifest: &nau_core::pkg_manifest::PackageManifest,
    dir: &Path,
) -> miette::Result<()> {
    let cache = dir
        .parent()
        .ok_or_else(|| miette::miette!("dep cache dir {} has no parent", dir.display()))?;
    let staging = tempfile::TempDir::new_in(cache)
        .map_err(|e| miette::miette!("dep cache staging dir: {e}"))?;
    for file in &manifest.files {
        write_verified_file(tree, file, staging.path())?;
    }
    if dir.exists() {
        std::fs::remove_dir_all(dir)
            .map_err(|e| miette::miette!("replacing the dep cache dir {}: {e}", dir.display()))?;
    }
    // TempDir's Drop removes its path — now empty after the rename.
    std::fs::rename(staging.path(), dir)
        .map_err(|e| miette::miette!("finalizing the dep cache dir {}: {e}", dir.display()))?;
    Ok(())
}

/// One manifest file: fetch its blob, verify the pinned sha256, write it
/// at its declared payload path with the declared exec bit.
fn write_verified_file<T: TreeSource>(
    tree: &T,
    file: &nau_core::pkg_manifest::ManifestFile,
    staging: &Path,
) -> miette::Result<()> {
    nau_core::pkg_manifest::validate_payload_path(file)?;
    nau_core::pkg_manifest::validate_sha256(file)?;
    let body = tree.blob(&file.sha256)?;
    let actual = nau_core::cache_key::sha256_hex(&body);
    if actual != file.sha256 {
        miette::bail!(
            "tree blob sha256 mismatch for '{}': expected {}, received {}",
            file.path,
            file.sha256,
            actual
        );
    }
    let dest = staging.join(&file.path);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("creating {}: {e}", parent.display()))?;
    }
    std::fs::write(&dest, &body).map_err(|e| miette::miette!("writing {}: {e}", dest.display()))?;
    if file.executable {
        std::fs::set_permissions(&dest, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .map_err(|e| miette::miette!("chmod {}: {e}", dest.display()))?;
    }
    Ok(())
}

/// The local-build lane: build the dep fresh (its own prefix first), pack
/// into the cache dir, return the snap payload.
fn build_farm_dep_payload<T: TreeSource>(
    tree: &T,
    cache: &Path,
    name: &str,
    dep_meta: &crate::snap::SnapMeta,
    arch: &str,
    building: &mut Vec<String>,
) -> miette::Result<crate::build_prefix::Payload> {
    if building.iter().any(|n| n == name) {
        miette::bail!(
            "circular dependency while building '{name}': {} → {name}",
            building.join(" → ")
        );
    }
    building.push(name.to_string());

    let dep_prefix = farm_build_prefix(tree, cache, dep_meta, arch, building)?;
    let scan_listings = match &dep_prefix {
        Some(p) => Some(crate::leak_scan::listings_for_build(dep_meta, p)?),
        None => Some(crate::leak_scan::PayloadListings::default()),
    };
    let stage =
        tempfile::tempdir().map_err(|e| miette::miette!("farm dep stage dir for {name}: {e}"))?;
    let result = match crate::snap::build_snap(
        dep_meta,
        stage.path(),
        cache,
        arch,
        crate::snap::StagePolicy::Default,
        // No pod store on the farm: no ELF repair, no build wrappers.
        None,
        // Ecosystem-deps closures stay pod-only (#338 follow-up).
        None,
        dep_prefix.as_ref().map(|p| p.path()),
        scan_listings.as_ref(),
        // Not a drift-observation point.
        false,
        Some(&crate::build_orch::SeamSourceFetcher),
    ) {
        Ok(result) => result,
        // Pop on the way out too — a leaked name would report a false
        // circular dependency on the next member.
        Err(e) => {
            building.pop();
            return Err(e);
        }
    };
    building.pop();
    Ok(crate::build_prefix::Payload {
        pkg: name.to_string(),
        source: crate::build_prefix::PayloadSource::Snap(cache.join(&result.snap_filename)),
    })
}

/// The farm twin of `pod_build_prefix`: the request meta's `requires` ∪
/// `build_deps` closure, each member ensured against the tree first.
/// `None` for fetch-only metas and empty closures — the same early-outs
/// the pod path runs.
pub(crate) fn farm_build_prefix<T: TreeSource>(
    tree: &T,
    cache: &Path,
    meta: &crate::snap::SnapMeta,
    arch: &str,
    building: &mut Vec<String>,
) -> miette::Result<Option<crate::build_prefix::MergedPrefix>> {
    // Only source builds consume a build prefix — meta/store snaps and
    // fetch-only declarations never run a build command.
    if meta.build.is_none() && meta.parts.is_none() {
        return Ok(None);
    }
    let seeds = crate::deps::build_dep_seeds(meta);
    if seeds.is_empty() {
        return Ok(None);
    }
    // Constraint-aware closure (ADR-0047): members load with the line
    // their edge selected, exactly like the pod path.
    let closure = crate::deps::resolve_dep_specs(&seeds, true)?;
    let mut payloads = Vec::new();
    for member in closure {
        let dep_meta = crate::deps::load_meta_for(&member.name, member.constraint.as_deref())?;
        payloads.push(ensure_farm_dep_payload(
            tree,
            cache,
            &member.name,
            &dep_meta,
            arch,
            building,
        )?);
    }
    let merged = crate::build_prefix::materialize_merged_prefix(&payloads)?;
    if !payloads.is_empty() {
        let names: Vec<&str> = payloads.iter().map(|p| p.pkg.as_str()).collect();
        crate::output::status(format!(
            "farm build prefix: merged {} payload(s) — {}",
            payloads.len(),
            names.join(", ")
        ));
    }
    Ok(Some(merged))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    /// An in-memory tree: manifests + content blobs, with a fetch counter
    /// the reuse assertions read.
    struct FakeTree {
        manifests: BTreeMap<String, Vec<u8>>,
        blobs: BTreeMap<String, Vec<u8>>,
        blob_gets: Cell<usize>,
    }

    impl FakeTree {
        fn new() -> Self {
            FakeTree {
                manifests: BTreeMap::new(),
                blobs: BTreeMap::new(),
                blob_gets: Cell::new(0),
            }
        }

        fn release(&mut self, pkg: &str, version: &str, revision: u32, content: &[u8]) {
            let sha = nau_core::cache_key::sha256_hex(content);
            let manifest = nau_core::pkg_manifest::PackageManifest {
                name: pkg.into(),
                version: version.into(),
                revision,
                target: nau_core::pkg_manifest::host_target(),
                files: vec![nau_core::pkg_manifest::ManifestFile {
                    path: "usr/bin/tool".into(),
                    sha256: sha.clone(),
                    executable: true,
                }],
                install: Default::default(),
                signer: String::new(),
                signature: String::new(),
            };
            self.blobs.insert(sha, content.to_vec());
            self.manifests
                .insert(pkg.to_string(), serde_json::to_vec(&manifest).unwrap());
        }
    }

    impl TreeSource for FakeTree {
        fn manifest(&self, pkg: &str) -> miette::Result<Option<Vec<u8>>> {
            Ok(self.manifests.get(pkg).cloned())
        }

        fn blob(&self, sha256: &str) -> miette::Result<Vec<u8>> {
            self.blob_gets.set(self.blob_gets.get() + 1);
            self.blobs
                .get(sha256)
                .cloned()
                .ok_or_else(|| miette::miette!("missing blob {sha256}"))
        }
    }

    fn bare_meta(name: &str, version: &str) -> crate::snap::SnapMeta {
        crate::snap::SnapMeta {
            name: name.into(),
            version: version.into(),
            summary: None,
            description: None,
            license: None,
            source: None,
            sources: None,
            build: None,
            parts: None,
            architectures: None,
            grade: "stable".into(),
            confinement: "strict".into(),
            type_: None,
            adopt_info: None,
            version_adopted: false,
            icon_source: None,
            icon: None,
            compression: None,
            compression_level: None,
            environment: None,
            layout: None,
            hooks: None,
            plugs: None,
            slots: None,
            aliases: vec![],
            requires: vec![],
            build_deps: vec![],
            leaks_ok: vec![],
            target: None,
            toolchain: None,
            inputs: None,
            confined: None,
            apps: BTreeMap::new(),
            services: BTreeMap::new(),
            deps: None,
            floating: false,
            definition_dir: None,
        }
    }

    fn dir_entry(payload: &crate::build_prefix::Payload) -> &Path {
        match &payload.source {
            crate::build_prefix::PayloadSource::Dir(dir) => dir,
            crate::build_prefix::PayloadSource::Snap(_) => {
                panic!("the tree lane must produce a dir payload")
            }
        }
    }

    #[test]
    fn tree_hit_materializes_the_dir_then_reuses_without_refetch() {
        let mut tree = FakeTree::new();
        tree.release("dep", "1.0", 1, b"tool v1 bytes");
        let cache = tempfile::tempdir().unwrap();
        let meta = bare_meta("dep", "1.0");
        let mut building = Vec::new();

        let payload =
            ensure_farm_dep_payload(&tree, cache.path(), "dep", &meta, "amd64", &mut building)
                .unwrap();
        let tool = dir_entry(&payload).join("usr/bin/tool");
        assert_eq!(std::fs::read(&tool).unwrap(), b"tool v1 bytes");
        let mode = std::fs::metadata(&tool).unwrap().permissions().mode();
        assert_ne!(mode & 0o111, 0, "the declared exec bit survives");

        let marker = marker_path(cache.path(), "dep", "1.0", "amd64");
        let after_first = tree.blob_gets.get();
        assert!(marker.exists(), "the manifest-digest marker is written");

        // Second ensure: the marker matches — no blob leaves the tree.
        let again =
            ensure_farm_dep_payload(&tree, cache.path(), "dep", &meta, "amd64", &mut building)
                .unwrap();
        assert_eq!(dir_entry(&again), dir_entry(&payload));
        assert_eq!(
            tree.blob_gets.get(),
            after_first,
            "a marker hit must not refetch"
        );
    }

    #[test]
    fn rerelease_supersedes_the_cached_payload() {
        // The #344 regression: a same-version re-release mints a new tree
        // manifest; the cache must re-materialize, never adopt stale.
        let mut tree = FakeTree::new();
        tree.release("dep", "1.0", 1, b"tool v1 bytes");
        let cache = tempfile::tempdir().unwrap();
        let meta = bare_meta("dep", "1.0");
        let mut building = Vec::new();

        let first =
            ensure_farm_dep_payload(&tree, cache.path(), "dep", &meta, "amd64", &mut building)
                .unwrap();
        assert_eq!(
            std::fs::read(dir_entry(&first).join("usr/bin/tool")).unwrap(),
            b"tool v1 bytes"
        );

        tree.release("dep", "1.0", 2, b"tool v2 bytes");
        let second =
            ensure_farm_dep_payload(&tree, cache.path(), "dep", &meta, "amd64", &mut building)
                .unwrap();
        assert_eq!(
            std::fs::read(dir_entry(&second).join("usr/bin/tool")).unwrap(),
            b"tool v2 bytes",
            "the re-release supersedes the cache"
        );
    }

    #[test]
    fn version_mismatch_hands_the_dep_to_the_local_lane() {
        let mut tree = FakeTree::new();
        tree.release("dep", "2.0", 1, b"tool v2 bytes");
        let cache = tempfile::tempdir().unwrap();
        let meta = bare_meta("dep", "1.0");

        let served = tree_payload(
            &tree,
            cache.path(),
            "dep",
            &meta,
            "amd64",
            &tree.manifest("dep").unwrap(),
        )
        .unwrap();
        assert_eq!(served, None, "a version mismatch is not a tree hit");
    }

    #[test]
    fn missing_pinned_blob_is_a_hard_error_not_a_fallback() {
        let mut tree = FakeTree::new();
        tree.release("dep", "1.0", 1, b"tool v1 bytes");
        tree.blobs.clear(); // a broken tree: manifest pins, blobs gone
        let cache = tempfile::tempdir().unwrap();
        let meta = bare_meta("dep", "1.0");
        let mut building = Vec::new();

        let err =
            ensure_farm_dep_payload(&tree, cache.path(), "dep", &meta, "amd64", &mut building)
                .expect_err("a pinned-but-missing blob is a broken tree");
        assert!(err.to_string().contains("missing"), "{err}");
    }
}
