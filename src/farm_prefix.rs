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

/// The tree reads and publishes the farm dep ensure's objects — a thin
/// seam over [`S3Client`] so tests fake the tree without a network (the
/// `BuildStep`/`Releaser` seam pattern).
pub(crate) trait TreeSource {
    /// The package's signed manifest bytes; `None` when unreleased.
    fn manifest(&self, pkg: &str) -> miette::Result<Option<Vec<u8>>>;

    /// One content blob; `None` when absent. The caller decides whether
    /// absence is a miss to fill (a closure first build) or a broken
    /// tree (a manifest-pinned payload blob — use [`Self::blob`]).
    fn blob_opt(&self, sha256: &str) -> miette::Result<Option<Vec<u8>>>;

    /// One content blob by sha256. A pinned blob that is missing is a
    /// broken tree, not a miss — a hard error, never a fallback.
    fn blob(&self, sha256: &str) -> miette::Result<Vec<u8>> {
        self.blob_opt(sha256)?.ok_or_else(|| {
            miette::miette!("tree blob 'blobs/{sha256}' is missing though the manifest pins it")
        })
    }

    /// The recorded interpreted-deps pin doc for `pkg` (#338-b), `None`
    /// when the tree has none — the first-build case that then publishes.
    fn closure_pin(&self, pkg: &str) -> miette::Result<Option<ClosurePin>>;

    /// Publish bytes at an exact object key (`blobs/<sha256>`,
    /// `closures/<pkg>.json`). Idempotent: content-addressed keys carry
    /// the same bytes from every writer.
    fn put_object(&self, key: &str, bytes: &[u8]) -> miette::Result<()>;
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

    fn blob_opt(&self, sha256: &str) -> miette::Result<Option<Vec<u8>>> {
        self.client.get(&format!("blobs/{sha256}"))
    }

    fn closure_pin(&self, pkg: &str) -> miette::Result<Option<ClosurePin>> {
        let Some(bytes) = self.client.get(&format!("closures/{pkg}.json"))? else {
            return Ok(None);
        };
        let pin: ClosurePin = serde_json::from_slice(&bytes).map_err(|e| {
            miette::miette!(
                "tree closure pin at closures/{pkg}.json does not parse — refusing it: {e}"
            )
        })?;
        Ok(Some(pin))
    }

    fn put_object(&self, key: &str, bytes: &[u8]) -> miette::Result<()> {
        self.client.put(key, bytes)
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

/// The tree's recorded interpreted-deps pin for one package (#338-b):
/// `closures/<pkg>.json` names the blob the closure builds from AND the
/// recipe-dep key it was resolved from — a recipe or recipe-lock edit
/// mints a new key, the recorded one mismatches, and the closure
/// re-resolves (the #344 class designed out on this lane too). A doc
/// from before keys existed parses with an empty key, which matches
/// nothing — a graceful one-time re-resolve.
///
/// Trust boundary, stated precisely: the doc is worker-published but
/// UNSIGNED — unlike the signed manifests, tree-write alone (leaked S3
/// creds, a non-signing component with PUT access) can repoint the pin
/// at an attacker blob that the next build mounts. Only whole-worker
/// compromise equals the manifest's attacker class. Signing with the
/// release keypair is the filed follow-up.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct ClosurePin {
    deps_hash: String,
    #[serde(default)]
    key: String,
}

/// The recipe-dep key the pin doc is validated against: the recipe bytes,
/// the deps declaration, and every recipe-local lockfile's bytes — the
/// inputs farm-side resolution is pinned by. A change to any of them
/// invalidates the recorded closure (the in-source lockfile bytes of a
/// FLOATING source are the documented gap: they are only knowable after
/// a fetch, so a floating recipe with in-source locks re-resolves on
/// recipe edits but not upstream lock drift — filed follow-up).
pub(crate) fn recipe_dep_key(
    recipe: &Path,
    meta: &crate::snap::SnapMeta,
) -> miette::Result<String> {
    let mut material = std::fs::read(recipe)
        .map_err(|e| miette::miette!("reading the recipe {}: {e}", recipe.display()))?;
    let mut decl = String::new();
    if let Some(deps) = meta.deps.as_ref() {
        for (name, spec) in [
            ("cargo", deps.cargo.as_ref()),
            ("go", deps.go.as_ref()),
            ("npm", deps.npm.as_ref()),
            ("pip", deps.pip.as_ref()),
        ] {
            let Some(spec) = spec else { continue };
            decl.push_str(&format!("{name}={spec:?}\n"));
            let recipe_dir = recipe
                .parent()
                .ok_or_else(|| miette::miette!("recipe {} has no parent dir", recipe.display()))?;
            let mut push_lock = |declared: &str| -> miette::Result<()> {
                if let Some(rest) = declared.strip_prefix("recipe/") {
                    let path = recipe_dir.join(rest);
                    let bytes = std::fs::read(&path).map_err(|e| {
                        miette::miette!("reading the recipe-local lock {}: {e}", path.display())
                    })?;
                    material.extend_from_slice(&bytes);
                }
                Ok(())
            };
            push_lock(&spec.lock)?;
            if let Some(sum) = &spec.sum {
                push_lock(sum)?;
            }
        }
    }
    material.extend_from_slice(decl.as_bytes());
    Ok(nau_core::cache_key::sha256_hex(&material))
}

/// The interpreted-deps closure for a farm build (#338-b), the tree-first
/// shape of the payload lane: the tree's `closures/<pkg>.json` names the
/// pin and `blobs/<deps_hash>` serves the bytes after the first build
/// published them; a miss runs `resolve` — the same resolver path the pod
/// runs, pinned by the recipe's shipped input locks — and PUBLISHES both
/// objects, so every later build (and every other worker) skips the
/// resolvers.
///
/// Publish order mirrors the release lane: the blob lands BEFORE the pin
/// doc names it, so a torn publish leaves no pin and re-resolves. The
/// materialized dir is named `deps-<pin>` in the (worker-persistent) dep
/// cache: the pin IS the completion record. A build unpacks through a
/// sibling staging dir renamed in atomically, so a torn unpack leaves no
/// complete-looking dir and two concurrent drains cannot poison each
/// other — the rename loser adopts the winner's dir, whose bytes are
/// identical by content addressing. A blob whose bytes do not hash to
/// the pin is a broken tree — hard error, never a fallback.
pub(crate) fn ensure_farm_deps_closure<T: TreeSource, R>(
    tree: &T,
    cache: &Path,
    meta: &crate::snap::SnapMeta,
    dep_key: &str,
    resolve: R,
) -> miette::Result<Option<PathBuf>>
where
    R: FnOnce() -> miette::Result<Vec<u8>>,
{
    if meta.deps.is_none() {
        return Ok(None);
    }
    std::fs::create_dir_all(cache)
        .map_err(|e| miette::miette!("creating the farm dep cache {}: {e}", cache.display()))?;

    let hit = match tree.closure_pin(&meta.name)? {
        Some(recorded) if recorded.key == dep_key => {
            require_sha256_grammar(&recorded.deps_hash, &meta.name)?;
            let dir = cache.join(format!("deps-{}", recorded.deps_hash));
            if !dir.is_dir() {
                let bytes = tree.blob_opt(&recorded.deps_hash)?.ok_or_else(|| {
                    miette::miette!(
                        "closures/{}.json names blob {} but the tree does not serve it — \
                             a broken tree, refusing to resolve over it",
                        meta.name,
                        recorded.deps_hash
                    )
                })?;
                materialize_closure(&bytes, &recorded.deps_hash, cache)?;
                crate::output::status(format!(
                    "closure for {} staged from the tree ({:.12}…)",
                    meta.name, recorded.deps_hash
                ));
            }
            Some(dir)
        }
        Some(_) => {
            crate::output::status(format!(
                "closure for {} was resolved from an earlier recipe state — re-resolving",
                meta.name
            ));
            None
        }
        None => None,
    };
    if let Some(dir) = hit {
        prune_stale_closures(cache, Some(&dir));
        return Ok(Some(dir));
    }

    let bytes = resolve()?;
    let pin = nau_core::cache_key::sha256_hex(&bytes);
    // Blob first, pin doc second: a torn publish leaves no pin and the
    // next build re-resolves (the release lane's blobs-first rule).
    tree.put_object(&format!("blobs/{pin}"), &bytes)?;
    let doc = serde_json::to_vec(&ClosurePin {
        deps_hash: pin.clone(),
        key: dep_key.to_string(),
    })
    .map_err(|e| miette::miette!("serializing the closure pin for '{}': {e}", meta.name))?;
    tree.put_object(&format!("closures/{}.json", meta.name), &doc)?;
    let dir = cache.join(format!("deps-{pin}"));
    if !dir.is_dir() {
        materialize_closure(&bytes, &pin, cache)?;
    }
    crate::output::status(format!(
        "closure for {} resolved + published to the tree ({:.12}…) — later builds skip the resolvers",
        meta.name, pin
    ));
    prune_stale_closures(cache, Some(&dir));
    Ok(Some(dir))
}

/// A pin becomes a filesystem path segment and a blob key — a non-sha256
/// pin is a broken or hostile tree object, refused before use. Lowercase
/// only: the publisher writes lowercase, S3 keys are case-sensitive, and
/// an uppercase pin would pass here only to 404 as a confusing
/// broken-tree error.
fn require_sha256_grammar(pin: &str, pkg: &str) -> miette::Result<()> {
    if pin.len() == 64
        && pin
            .bytes()
            .all(|b: u8| b.is_ascii_digit() || b.is_ascii_lowercase())
    {
        return Ok(());
    }
    miette::bail!(
        "tree closure pin for '{pkg}' is not a lowercase sha256: '{pin}' — refusing the \
         closures/<pkg>.json object"
    )
}

/// Unpack the verified closure bytes into `cache/deps-<pin>` via a
/// sibling staging dir renamed in atomically (the payload lane's EXDEV
/// rule: stage INSIDE the cache). An existing target dir is a concurrent
/// winner — its bytes are identical by content addressing, so losing the
/// rename is success.
fn materialize_closure(bytes: &[u8], pin: &str, cache: &Path) -> miette::Result<()> {
    let actual = nau_core::cache_key::sha256_hex(bytes);
    if actual != pin {
        miette::bail!(
            "dependency closure hash mismatch: expected {pin}, found {actual} — the tree \
             entry is corrupted or tampered with; refusing to build against it"
        );
    }
    let staging = tempfile::TempDir::new_in(cache)
        .map_err(|e| miette::miette!("closure cache staging dir: {e}"))?;
    nau_chart::dep_fetch::unpack_canonical(std::io::Cursor::new(bytes), staging.path())?;
    let dir = cache.join(format!("deps-{pin}"));
    match std::fs::rename(staging.path(), &dir) {
        Ok(()) => Ok(()),
        Err(_) if dir.is_dir() => Ok(()),
        Err(e) => Err(miette::miette!(
            "finalizing the closure cache dir {}: {e}",
            dir.display()
        )),
    }
}

/// Lossless eviction of stale closure dirs: content-addressed dirs
/// re-fetch from the tree by construction, so age-based removal is safe.
/// The deps lane is the one with unbounded growth (a floating recipe
/// mints a new pin per moved closure); best-effort, never fails a build.
/// `exclude` names the dir this call is about to return — reuse does not
/// refresh mtime, so without the exclusion a 14-day-old hit would be
/// evicted out from under the build it was just handed to.
fn prune_stale_closures(cache: &Path, exclude: Option<&Path>) {
    const PRUNE_AFTER: std::time::Duration = std::time::Duration::from_secs(14 * 24 * 3600);
    let Ok(entries) = std::fs::read_dir(cache) else {
        return;
    };
    for entry in entries.flatten() {
        if exclude.is_some_and(|keep| entry.path() == keep) {
            continue;
        }
        let name = entry.file_name();
        let Some(rest) = name.to_str().and_then(|n| n.strip_prefix("deps-")) else {
            continue;
        };
        if rest.len() != 64 || !rest.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let fresh = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .map(|m| m.elapsed().map_or(true, |age| age <= PRUNE_AFTER))
            .unwrap_or(true);
        if !fresh {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
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
        // #347: the fallthrough itself must be loud — an unreleased member
        // (a gcc nobody asked for) is otherwise untraceable in the drain log.
        crate::output::status(format!(
            "no tree manifest for {name} {} — building it locally",
            dep_meta.version,
        ));
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
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    /// An in-memory tree: manifests + content blobs + closure pins, with
    /// a fetch counter the reuse assertions read and a PUT log the
    /// publish-order assertions read.
    struct FakeTree {
        manifests: BTreeMap<String, Vec<u8>>,
        blobs: RefCell<BTreeMap<String, Vec<u8>>>,
        closure_pins: RefCell<BTreeMap<String, ClosurePin>>,
        blob_gets: Cell<usize>,
        puts: RefCell<Vec<(String, Vec<u8>)>>,
    }

    impl FakeTree {
        fn new() -> Self {
            FakeTree {
                manifests: BTreeMap::new(),
                blobs: RefCell::new(BTreeMap::new()),
                closure_pins: RefCell::new(BTreeMap::new()),
                blob_gets: Cell::new(0),
                puts: RefCell::new(Vec::new()),
            }
        }

        /// Record the closure blob + pin doc the way the real publish
        /// path does (content-addressed, key bound).
        fn publish_closure(&mut self, pkg: &str, bytes: &[u8], key: &str) {
            let pin = nau_core::cache_key::sha256_hex(bytes);
            self.blobs.borrow_mut().insert(pin.clone(), bytes.to_vec());
            self.closure_pins.borrow_mut().insert(
                pkg.to_string(),
                ClosurePin {
                    deps_hash: pin,
                    key: key.to_string(),
                },
            );
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
            self.blobs.borrow_mut().insert(sha, content.to_vec());
            self.manifests
                .insert(pkg.to_string(), serde_json::to_vec(&manifest).unwrap());
        }
    }

    impl TreeSource for FakeTree {
        fn manifest(&self, pkg: &str) -> miette::Result<Option<Vec<u8>>> {
            Ok(self.manifests.get(pkg).cloned())
        }

        fn blob_opt(&self, sha256: &str) -> miette::Result<Option<Vec<u8>>> {
            self.blob_gets.set(self.blob_gets.get() + 1);
            Ok(self.blobs.borrow().get(sha256).cloned())
        }

        fn closure_pin(&self, pkg: &str) -> miette::Result<Option<ClosurePin>> {
            Ok(self.closure_pins.borrow().get(pkg).cloned())
        }

        fn put_object(&self, key: &str, bytes: &[u8]) -> miette::Result<()> {
            self.puts
                .borrow_mut()
                .push((key.to_string(), bytes.to_vec()));
            if let Some(sha) = key.strip_prefix("blobs/") {
                self.blobs
                    .borrow_mut()
                    .insert(sha.to_string(), bytes.to_vec());
            } else if let Some(pkg) = key
                .strip_prefix("closures/")
                .and_then(|rest| rest.strip_suffix(".json"))
            {
                let pin: ClosurePin = serde_json::from_slice(bytes)
                    .map_err(|e| miette::miette!("test tree: bad pin doc for {pkg}: {e}"))?;
                self.closure_pins.borrow_mut().insert(pkg.to_string(), pin);
            }
            Ok(())
        }
    }

    /// A minimal canonical (SHDEP) archive: one file, `hello`, with
    /// `world` as its content.
    fn tiny_closure_blob() -> Vec<u8> {
        b"F 100644 5 hello\nworldEND\n".to_vec()
    }

    /// A meta that declares (empty) deps — enough to reach the closure
    /// lane without any resolver.
    fn deps_meta(name: &str, version: &str) -> crate::snap::SnapMeta {
        let mut meta = bare_meta(name, version);
        meta.deps = Some(nau_core::snap_types::PackageDeps {
            npm: None,
            pip: None,
            cargo: None,
            go: None,
        });
        meta
    }

    /// A package with no deps never touches the tree or the resolver.
    #[test]
    fn deps_none_yields_no_tree_traffic() {
        let tree = FakeTree::new();
        let meta = bare_meta("app", "1.0.0");
        let cache = tempfile::tempdir().unwrap();
        let out =
            crate::farm_prefix::ensure_farm_deps_closure(&tree, cache.path(), &meta, "k1", || {
                panic!("the resolver must not run without declared deps")
            })
            .unwrap();
        assert!(out.is_none());
        assert_eq!(tree.blob_gets.get(), 0);
        assert!(tree.puts.borrow().is_empty());
    }

    /// The tree's pin serves the closure: materialized from the blob,
    /// reused without a second GET on the next ensure, never republished.
    #[test]
    fn tree_pin_serves_materialized_closure() {
        let mut tree = FakeTree::new();
        tree.publish_closure("app", &tiny_closure_blob(), "k1");
        let meta = deps_meta("app", "1.0.0");
        let cache = tempfile::tempdir().unwrap();

        let out =
            crate::farm_prefix::ensure_farm_deps_closure(&tree, cache.path(), &meta, "k1", || {
                panic!("a tree hit must not resolve")
            })
            .unwrap()
            .expect("a tree hit yields a dir");
        let content = std::fs::read_to_string(out.join("hello")).unwrap();
        assert_eq!(content, "world", "the canonical archive unpacked");
        assert_eq!(tree.blob_gets.get(), 1);
        assert!(
            tree.puts.borrow().is_empty(),
            "a tree hit publishes nothing"
        );

        let again =
            crate::farm_prefix::ensure_farm_deps_closure(&tree, cache.path(), &meta, "k1", || {
                panic!("a complete cache dir must not resolve")
            })
            .unwrap()
            .expect("the second ensure returns the same dir");
        assert_eq!(again, out);
        assert_eq!(tree.blob_gets.get(), 1, "the complete dir skips the GET");
    }

    /// A tree miss resolves, publishes blob-then-pin-doc, materializes,
    /// and a second ensure takes the pin path (no second resolve).
    #[test]
    fn tree_miss_resolves_publishes_and_materializes() {
        let tree = FakeTree::new();
        let meta = deps_meta("app", "1.0.0");
        let cache = tempfile::tempdir().unwrap();
        let resolved = std::cell::Cell::new(0);

        let out =
            crate::farm_prefix::ensure_farm_deps_closure(&tree, cache.path(), &meta, "k1", || {
                resolved.set(resolved.get() + 1);
                Ok(tiny_closure_blob())
            })
            .unwrap()
            .expect("a resolved closure yields a dir");

        let pin = nau_core::cache_key::sha256_hex(tiny_closure_blob());
        assert!(out.ends_with(format!("deps-{pin}")), "dir named by the pin");
        let puts = tree.puts.borrow();
        assert_eq!(puts.len(), 2, "blob + pin doc: {:?}", puts);
        assert_eq!(puts[0].0, format!("blobs/{pin}"), "blob lands first");
        assert_eq!(puts[1].0, "closures/app.json", "pin doc lands second");
        assert_eq!(
            puts[1].1,
            format!("{{\"deps_hash\":\"{pin}\",\"key\":\"k1\"}}").into_bytes(),
            "the pin doc names the blob"
        );
        drop(puts);
        assert_eq!(resolved.get(), 1);

        // The published pin serves the next build: no second resolve, no
        // second publish.
        let again =
            crate::farm_prefix::ensure_farm_deps_closure(&tree, cache.path(), &meta, "k1", || {
                panic!("the published pin must preempt resolution")
            })
            .unwrap()
            .expect("the pin doc yields the dir");
        assert_eq!(again, out);
        assert_eq!(tree.puts.borrow().len(), 2, "nothing republished");
    }

    /// A pin that is not a lowercase sha256 is refused before it becomes
    /// a path segment or a blob key — the grammar gate on the pin doc.
    #[test]
    fn malformed_closure_pin_refuses() {
        let tree = FakeTree::new();
        tree.closure_pins.borrow_mut().insert(
            "app".into(),
            ClosurePin {
                deps_hash: "short-and-dirty".into(),
                key: "k1".into(),
            },
        );
        let meta = deps_meta("app", "1.0.0");
        let cache = tempfile::tempdir().unwrap();

        let err =
            crate::farm_prefix::ensure_farm_deps_closure(&tree, cache.path(), &meta, "k1", || {
                panic!("a malformed pin must fall hard, never to the resolver")
            })
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("is not a lowercase sha256"),
            "{err:#}"
        );
    }

    /// A recipe-dep key change (a recipe or recipe-lock edit) invalidates
    /// the recorded pin: the closure re-resolves and republishes — the
    /// farm never freezes at its first resolution (#344's class, this
    /// lane's version).
    #[test]
    fn recipe_change_republishes() {
        let mut tree = FakeTree::new();
        tree.publish_closure("app", &tiny_closure_blob(), "k1");
        let meta = deps_meta("app", "1.0.0");
        let cache = tempfile::tempdir().unwrap();

        // The recipe changed: the recorded key no longer matches.
        let out =
            crate::farm_prefix::ensure_farm_deps_closure(&tree, cache.path(), &meta, "k2", || {
                Ok(b"F 100644 6 hello2\nworld2END\n".to_vec())
            })
            .unwrap()
            .expect("a re-resolve yields the new dir");

        let new_blob = b"F 100644 6 hello2\nworld2END\n";
        let new_pin = nau_core::cache_key::sha256_hex(new_blob);
        assert!(
            out.ends_with(format!("deps-{new_pin}")),
            "the dir is named by the NEW pin: {}",
            out.display()
        );
        let puts = tree.puts.borrow();
        assert_eq!(puts.len(), 2, "the stale pair is overwritten: {puts:?}");
        assert_eq!(puts[0].0, format!("blobs/{new_pin}"));
        assert_eq!(
            puts[1].1,
            format!("{{\"deps_hash\":\"{new_pin}\",\"key\":\"k2\"}}").into_bytes(),
            "the republished doc binds the new key"
        );
    }

    /// A blob whose bytes do not hash to the recorded pin is a broken
    /// tree — hard error, never a fallback to the resolver.
    #[test]
    fn corrupt_closure_blob_refuses() {
        let tree = FakeTree::new();
        let pin = nau_core::cache_key::sha256_hex(b"");
        tree.blobs
            .borrow_mut()
            .insert(pin.clone(), b"not the empty string".to_vec());
        tree.closure_pins.borrow_mut().insert(
            "app".into(),
            ClosurePin {
                deps_hash: pin,
                key: "k1".into(),
            },
        );
        let meta = deps_meta("app", "1.0.0");
        let cache = tempfile::tempdir().unwrap();

        let err =
            crate::farm_prefix::ensure_farm_deps_closure(&tree, cache.path(), &meta, "k1", || {
                panic!("a broken tree must fall hard, never to the resolver")
            })
            .unwrap_err();
        assert!(format!("{err:#}").contains("hash mismatch"), "{err:#}");
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
        tree.blobs.borrow_mut().clear(); // a broken tree: manifest pins, blobs gone
        let cache = tempfile::tempdir().unwrap();
        let meta = bare_meta("dep", "1.0");
        let mut building = Vec::new();

        let err =
            ensure_farm_dep_payload(&tree, cache.path(), "dep", &meta, "amd64", &mut building)
                .expect_err("a pinned-but-missing blob is a broken tree");
        assert!(err.to_string().contains("missing"), "{err}");
    }

    // output::status writes to the process stderr, and the harness's
    // capture hook intercepts eprintln! on every thread of this process —
    // fd redirection cannot see the bytes. So these tests respawn THIS
    // test binary filtered to themselves with --nocapture: the child
    // takes the real stderr path (the same child-process shape the #344
    // CLI tests use), and it also runs the behavior assertions, so a
    // green child plus the expected line proves emission and content.
    const CHILD_FLAG: &str = "NAU_TEST_FALLTHROUGH_CHILD";

    fn respawn_child(self_name: &str) -> std::process::Output {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([self_name, "--exact", "--nocapture"])
            .env(CHILD_FLAG, "1")
            .output()
            .expect("respawning the test binary must work")
    }

    #[test]
    fn missing_tree_manifest_reports_the_local_build_fallthrough() {
        if std::env::var(CHILD_FLAG).is_ok() {
            let tree = FakeTree::new(); // no release(): the member is unreleased
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
            assert_eq!(served, None, "a missing manifest is not a tree hit");
            return;
        }
        let out = respawn_child(concat!(
            "farm_prefix::tests::",
            "missing_tree_manifest_reports_the_local_build_fallthrough"
        ));
        assert!(
            out.status.success(),
            "the child must pass its behavior assertions: {out:?}"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("no tree manifest for dep 1.0"),
            "the fallthrough must name the member and its version: {stderr}"
        );
        assert!(
            stderr.contains("building it locally"),
            "the fallthrough must say the member builds locally: {stderr}"
        );
    }

    #[test]
    fn tree_hit_emits_no_local_build_fallthrough_line() {
        if std::env::var(CHILD_FLAG).is_ok() {
            let mut tree = FakeTree::new();
            tree.release("dep", "1.0", 1, b"tool v1 bytes");
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
            assert_eq!(served.as_deref(), Some("1.0"));
            return;
        }
        let out = respawn_child(concat!(
            "farm_prefix::tests::",
            "tree_hit_emits_no_local_build_fallthrough_line"
        ));
        assert!(
            out.status.success(),
            "the child must pass its behavior assertions: {out:?}"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        // The channel check: the materialize line DID reach this stderr,
        // so its silence about the fallthrough is meaningful.
        assert!(
            stderr.contains("tree payload for dep 1.0 materialized"),
            "the tree-hit status line must flow to stderr: {stderr}"
        );
        assert!(
            !stderr.contains("no tree manifest"),
            "a tree hit must not report a missing manifest: {stderr}"
        );
        assert!(
            !stderr.contains("building it locally"),
            "a tree hit must not report a local-build fallthrough: {stderr}"
        );
    }
}
