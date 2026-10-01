//! The per-package install-record vocabulary + the signed shareable
//! manifest (issue #326 PR 4 down-moves). Shapes recorded at install
//! time and shared by the pod runtime, the farm emitter, the pull
//! lanes, and the shareable package manifest. Issue #326 PR 5 moved the
//! MINTING half down too (`mint_manifest`, `load_signing_key`,
//! `inbox_manifests`, `union_inbox`): once the install records landed
//! here the mint is core vocabulary — one mint, one truth, wherever the
//! serving lane lives. The root crate's `pkg_manifest` module is a pure
//! re-export shim over everything here.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use miette::{bail, IntoDiagnostic, WrapErr};
use serde::{Deserialize, Serialize};

use crate::sign::KeyPair;
use crate::snap_types::{Confinement, ServiceDecl};

// ── Install-time records ──

/// The precedence layer a claim on a shared ID (a desktop application ID
/// or a binary name) comes from. Derived from the pod composition chain
/// (CONTEXT.md: Pod, Overlay — issue #8): a package provided by a loaded
/// pod is `Loaded` (lowest); the loading pod's own declaration is `Own`;
/// a package patched by this pod's inline overlay is `Overlay`, which
/// strictly dominates. A pod never sits below what it loads: the loading
/// pod wins cross-layer binary conflicts.
///
/// Moved DOWN into `nau_core::pkg_manifest` (issue #326 PR 5: records
/// follow their consumers — `InstalledPackage` carries a layer); the
/// root `farm` module re-exports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimLayer {
    /// Provided by a loaded pod (issue #8) — the composition floor.
    Loaded,
    /// This pod's own declared packages.
    #[default]
    Own,
    /// This pod's inline overlay — the top layer.
    Overlay,
}

/// One installed package as pinned in a generation manifest.
///
/// Moved DOWN into `nau_core::pkg_manifest` (issue #326 PR 5: the
/// record follows its consumers — the shareable-manifest minting half
/// lives here, and the peer lanes consume the record). The root
/// `runtime` module re-exports it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub revision: u32,
    /// sha3-384 of the payload — the snap-level content address, carried
    /// through from the store resolve.
    pub sha3_384: String,
    /// sha256 content hashes of every file the package contributes to
    /// the store — the GC mark set for this package.
    pub files: Vec<String>,
    /// Daemon unit names this package contributed (empty for plain
    /// apps) — the unit reconciliation set difference works over these.
    pub units: Vec<String>,
    /// The composition precedence layer this package was installed at
    /// (issue #8): what a loaded pod provided (`Loaded`), the pod's own
    /// declaration (`Own`), or the pod's overlay (`Overlay`). The farm
    /// and launcher emitters iterate in this order so the higher layer
    /// wins a shared binary or desktop-entry name. Manifests from
    /// before the field default to `Own`.
    #[serde(default)]
    pub layer: ClaimLayer,
    /// App name → sha256 of the app's command binary in the store.
    /// The farm emitter's source of truth (pod farm, `farm.rs`): each
    /// entry becomes a direct symlink from the farm into the content
    /// store. Empty for packages without apps and store-recorded snaps.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub apps: BTreeMap<String, String>,
    /// The package's declared runtime requires (ADR-0018), recorded so
    /// the farm emitter can tell libs-carrying packages (requires
    /// beyond the glibc family → their apps get the emit-time LD
    /// wrapper, issue #110/ADR-0034) from self-contained ones without
    /// re-reading the pool. Manifests from before the field default to
    /// empty (unwrapped — the conservative old behavior).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
    /// App name → sha256 of the app's confined-launcher wrapper blob in
    /// the store (ticket #11). Only present for confined apps. The farm
    /// emitter prefers this over `apps` for a confined app so the farm's
    /// symlink points at a wrapper that invokes `nau run`, while
    /// `apps` still records the real command binary `nau run` execs.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub launchers: BTreeMap<String, String>,
    /// Multi-file app payloads (issue #37): app name → the app's
    /// in-payload binary path plus the sibling content recorded beside
    /// it at install time. The pod farm builds multi-file packages a
    /// per-package assembly subtree from this (`crate::farm`), so
    /// relative-to-executable sibling reads (`pi`'s package.json,
    /// git-credential-manager's libSkiaSharp.so) resolve beside the
    /// executed binary; single-binary packages record nothing here and
    /// keep the bare direct farm link.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub assembly: BTreeMap<String, AppAssembly>,
    /// Runtime confinement grants (ADR-0016, ticket #11): the package-level
    /// `confined` declaration. `Some` = the package is confined (its
    /// apps default to confined), `None` = unconfined. Recorded from the
    /// payload's snap.yaml at install time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confined: Option<Confinement>,
    /// Per-app confinement overrides (ticket #11): app name → grants, only
    /// for apps whose `confined` differs from the package default. The
    /// farm emitter and `nau run` resolve effective confinement as
    /// `app_confined.get(app).or(confined.as_ref())`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub app_confined: BTreeMap<String, Confinement>,
    /// Desktop-launcher metadata per GUI app (issue #7), parsed from the
    /// package's `.desktop` file at install time and recorded in the
    /// manifest so the launcher emitter rebuilds entries from the
    /// manifest alone — rollback re-emits without re-unpacking. Empty
    /// for packages without GUI apps.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub desktops: BTreeMap<String, DesktopLauncher>,
    /// Payload font files (issue #29 cutover): path under the payload's
    /// `usr/share/fonts` → sha256, recorded at install time so the font
    /// emitter rebuilds the user-level surface from the manifest alone —
    /// rollback re-emits without re-unpacking. Empty for packages that
    /// ship no fonts (the common case; the hashes also appear in `files`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fonts: BTreeMap<String, String>,
    /// Service declarations (ADR-0032, issue #106), recorded verbatim from
    /// the payload's snap.yaml at install time: service name → decl. This
    /// is the declaration record the service emitter re-renders into the
    /// generation's `units.json` (pod-level overrides are applied at
    /// record time, not stored here). Empty for packages without services.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub services: BTreeMap<String, ServiceDecl>,
    /// Service name → sha256 of the service's command binary blob in the
    /// store — the farm-link source, the `apps` precedent: each entry
    /// becomes a flat farm link `current/<svc>` exactly like an app
    /// binary. Empty for packages without services.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub service_bins: BTreeMap<String, String>,
    /// Canonical build-input digest (sha3-384) of the resolved recipe
    /// meta recorded at install time (issue #113). `None` for manifests
    /// recorded before the field existed — those never hold, so the
    /// first sync after upgrade rebuilds once and records it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta_digest: Option<String>,
}

/// One bootable selection: base version + package set + content hashes.
///
/// Moved DOWN into `nau_core::pkg_manifest` (issue #326 PR 5, beside
/// `InstalledPackage`); the root `runtime` module re-exports it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Generation {
    pub n: u64,
    /// Base OS version this generation was created on (from the host
    /// os-release; the base axis itself updates via sysupdate, never
    /// through these commands).
    pub base_version: String,
    /// The full installed package set, keyed by snap name.
    pub packages: BTreeMap<String, InstalledPackage>,
    pub created_epoch: u64,
    /// The boot entry id this generation corresponds to, when known
    /// (sysupdate integration); None for package-axis-only generations.
    pub boot_entry: Option<String>,
}

// ── The minting half (issue #326 PR 5 down-move) ──

/// Load the operator's signing key for manifest minting. Unlike
/// [`crate::sign::load_secret_key`] — whose `Ok(None)` means signing is
/// opt-out — minting REQUIRES a key: unsigned store entries are never
/// served (ADR-0033 Decision 2). Absence is a named error pointing at
/// the `nau key` ceremony.
pub fn load_signing_key(home: &Path) -> miette::Result<KeyPair> {
    crate::sign::load_secret_key(home)?.ok_or_else(|| {
        miette::miette!(
            "no signing key at {} — shareable package manifests are always signed; \
             run `nau key keygen` first (see `nau key list` for the ceremony ledger)",
            crate::sign::secret_key_path(home).display()
        )
    })
}

// ── One mint, one truth (ADR-0033 Decision 2) ──
//
// Every minting lane (serve, export — build/ingest when they land)
// calls [`mint_manifest`]; there is exactly one implementation so the
// body a peer fetches over `/manifests/<pkg>` and the file a mirror
// freezes are the same bytes by construction, not by discipline.

/// Mint a [`PackageManifest`] from a generation record (ADR-0033
/// Decision 2). The record keeps per-file CONTENT ADDRESSES only — no
/// payload paths and no executable bits — so `files[].path` carries the
/// store identity (the sha256 itself) and `executable` is true for the
/// recorded command binaries (apps, confined launchers, service
/// binaries — the farm links those for direct execution). `install`
/// mirrors the snap.yaml-derived records verbatim: metadata travels,
/// never re-derived. `signer`/`signature` are stamped by [`sign`].
pub fn mint_manifest(record: &InstalledPackage) -> PackageManifest {
    let binaries: BTreeSet<&str> = record
        .apps
        .values()
        .chain(record.launchers.values())
        .chain(record.service_bins.values())
        .map(String::as_str)
        .collect();
    let files: Vec<ManifestFile> = record
        .files
        .iter()
        .map(|sha256| ManifestFile {
            path: sha256.clone(),
            sha256: sha256.clone(),
            executable: binaries.contains(sha256.as_str()),
        })
        .collect();
    PackageManifest {
        name: record.name.clone(),
        version: record.version.clone(),
        revision: record.revision,
        target: host_target(),
        files,
        install: InstallMeta {
            units: record.units.clone(),
            apps: record.apps.clone(),
            launchers: record.launchers.clone(),
            assembly: record.assembly.clone(),
            confined: record.confined.clone(),
            app_confined: record.app_confined.clone(),
            desktops: record.desktops.clone(),
            fonts: record.fonts.clone(),
            services: record.services.clone(),
            service_bins: record.service_bins.clone(),
            requires: record.requires.clone(),
        },
        signer: String::new(),
        signature: String::new(),
    }
}

// ── The union rule (ADR-0033 Decision 5 invariant) ──

/// The pull-staging inbox: staged peer manifests under
/// `<root>/store/manifests/` (see [`manifest_path`] for the layout
/// invariant), sorted by package name. A missing directory is an empty
/// inbox — an installed-only store is still publishable.
pub fn inbox_manifests(store_root: &Path) -> miette::Result<Vec<(String, PathBuf)>> {
    let dir = store_root.join("store").join("manifests");
    let Ok(read) = std::fs::read_dir(&dir) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for entry in read {
        let entry = entry
            .into_diagnostic()
            .wrap_err_with(|| format!("reading {}", dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        out.push((stem.to_string(), path));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// The union's inbox half: staged manifests whose package is NOT in the
/// current generation — the ones published verbatim instead of minted
/// fresh. Both `serve /info` and `export index.json` walk this, so the
/// dynamic view and the frozen tree never disagree on visibility.
pub fn union_inbox<'a>(
    generation: &Option<Generation>,
    inbox: &'a [(String, PathBuf)],
) -> Vec<&'a (String, PathBuf)> {
    let gen_names: BTreeSet<&str> = generation
        .as_ref()
        .map(|g| g.packages.keys().map(String::as_str).collect())
        .unwrap_or_default();
    inbox
        .iter()
        .filter(|(name, _)| !gen_names.contains(name.as_str()))
        .collect()
}

/// One app's multi-file payload assembly (issue #37): the app binary's
/// in-payload path plus the content that ships beside it (same payload
/// directory, recursively), recorded at install time from the walked
/// payload tree. Paths under `files`/`links` are relative to the
/// binary's directory and reproduce the payload layout the binary
/// resolves against. Empty maps mean the payload ships the binary
/// alone — nothing recorded, the farm keeps the bare direct link.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AppAssembly {
    /// In-payload path of the app's command binary (e.g.
    /// `usr/bin/git-credential-manager`).
    pub binary: String,
    /// Files beside the binary: path relative to the binary's payload
    /// directory → sha256 of the content blob in the store.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, String>,
    /// Symlinks beside the binary, recreated verbatim: relative path →
    /// link target (never followed — payload links stay payload-scoped).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub links: BTreeMap<String, String>,
}

impl AppAssembly {
    /// Whether the payload ships this app's binary alone.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty() && self.links.is_empty()
    }
}

/// One GUI app's desktop-launcher metadata (issue #7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopLauncher {
    /// `Name=` of the source `.desktop` file (falls back to the app id
    /// in the generated entry when absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `GenericName=` of the source file, passed through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generic_name: Option<String>,
    /// `Comment=` of the source file, passed through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Menu categories, split from the source file's `Categories=`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    /// `Icon=` of the source file, passed through ONLY when the package
    /// ships no icon blob (a theme icon name); when the package ships
    /// one, the emitter substitutes the pod-namespaced link name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon_ref: Option<String>,
    /// The package's shipped icon, ingested into the store at install
    /// time and linked by the launcher emitter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<DesktopIcon>,
}

/// An icon blob in the content store plus its file extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopIcon {
    pub sha256: String,
    pub ext: String,
}

/// The install-side metadata half of a [`PackageManifest`] — the
/// snap.yaml-derived claims a receiving peer needs to reconstruct the
/// install-time records without the payload's yaml (mirrored field by
/// field from the runtime's `InstalledPackage`, so manifests minted
/// before a field existed — and minimal ones — keep parsing).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct InstallMeta {
    /// Daemon unit names this package contributed (empty for plain
    /// apps) — mirrored from `InstalledPackage::units`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub units: Vec<String>,
    /// App name → sha256 of the app's command binary in the store.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub apps: BTreeMap<String, String>,
    /// App name → sha256 of the app's confined-launcher wrapper blob.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub launchers: BTreeMap<String, String>,
    /// Multi-file app payloads: app name → the app's in-payload binary
    /// path plus sibling content recorded beside it at install time.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub assembly: BTreeMap<String, AppAssembly>,
    /// Package-level confinement declaration (ADR-0016): `Some` =
    /// confined, `None` = unconfined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confined: Option<Confinement>,
    /// Per-app confinement overrides: app name → grants, only for apps
    /// whose `confined` differs from the package default.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub app_confined: BTreeMap<String, Confinement>,
    /// Desktop-launcher metadata per GUI app (issue #7), parsed from
    /// the package's `.desktop` file at install time.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub desktops: BTreeMap<String, DesktopLauncher>,
    /// Payload font files: path under the payload's `usr/share/fonts`
    /// → sha256 (issue #29 cutover).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fonts: BTreeMap<String, String>,
    /// Service declarations (ADR-0032) recorded verbatim from the
    /// payload's snap.yaml: service name → decl.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub services: BTreeMap<String, ServiceDecl>,
    /// Service name → sha256 of the service's command binary blob.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub service_bins: BTreeMap<String, String>,
    /// The package's declared runtime requires (ADR-0018), recorded so
    /// a receiving peer knows the package needs the emit-time LD
    /// wrapper without re-reading a pool it does not have.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
}

// ── The signed wire schema (issue #326 PR 4 down-move) ──

/// One store file of a shared package: the payload path it occupied at
/// install time, the sha256 of its content-addressed blob in the store
/// (the ADR-0012 blob set — `store/<aa>/<sha256>`), and whether the
/// installed file carried the executable bit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFile {
    /// The file's path within the installed payload tree.
    pub path: String,
    /// sha256 of the store blob — the pull lane hash-checks every
    /// fetched blob against this.
    pub sha256: String,
    /// Whether the installed file was executable.
    pub executable: bool,
}

/// A signed, per-package, shareable manifest (ADR-0033 Decision 2):
/// what travels between peers, beside the store blobs it references.
/// The store's first per-package signed artifact — canonicalized and
/// signed with the same machinery as the image manifest
/// ([`crate::sign`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PackageManifest {
    /// Snap/package name (the store key; `[a-z0-9-]` per the ADR-0032
    /// collision-classifier charset the wire grammar reuses).
    pub name: String,
    pub version: String,
    /// Monotonic per name — the freshness rule (ADR-0033 Decision 7)
    /// refuses older revisions unless `--allow-downgrade` is explicit.
    pub revision: u32,
    /// GNU target triplet the payload was built for.
    pub target: String,
    /// The store blob set: every file the package contributes, with
    /// its sha256 and executable bit.
    pub files: Vec<ManifestFile>,
    /// The snap.yaml-derived install metadata (see [`InstallMeta`]).
    #[serde(default)]
    pub install: InstallMeta,
    /// The signing key id (first 16 hex chars of the public key) —
    /// verifiers match it against their trusted-key set (the peer lane
    /// enforces fail-closed `verify_trust_set` semantics).
    #[serde(default)]
    pub signer: String,
    /// The ed25519 signature over [`canonical_bytes`], as
    /// [`crate::sign::sign_bytes`] emits it (standard base64 — the
    /// encoding `crate::sign::verify` decodes).
    #[serde(default)]
    pub signature: String,
}

/// Canonical signature input: the manifest serialized with `signature`
/// emptied (a signature never covers itself; the emptied field keeps
/// the bytes byte-stable — the same rule
/// [`crate::sign::eval_manifest_canonical_bytes`] applies to the eval
/// manifest and the image one to theirs).
pub fn canonical_bytes(pkg: &PackageManifest) -> miette::Result<Vec<u8>> {
    let mut clean = pkg.clone();
    clean.signature = String::new();
    serde_json::to_vec(&clean).map_err(|e| miette::miette!("canonical serialization: {e}"))
}

/// Sign `pkg` in place under `kp`: the ed25519 signature over the
/// canonical bytes, with the signer key id recorded beside it. Re-signing
/// replaces any previous signature — a manifest carries one author's
/// signature; multi-key trust is the verifier-side keychain's job.
pub fn sign(pkg: &mut PackageManifest, kp: &KeyPair) -> miette::Result<()> {
    // The signer id is part of the canonical body (only `signature`
    // empties out), so it is stamped BEFORE the signed bytes exist —
    // the signature binds who signed, not just what.
    pkg.signer = kp.key_id();
    let bytes = canonical_bytes(pkg)?;
    pkg.signature = crate::sign::sign_bytes(&bytes, kp);
    Ok(())
}

/// Verify `pkg`'s signature against the full public key `public_hex`
/// (64 hex chars — the manifest carries only the 16-hex key id). A
/// tampered field (canonical bytes changed), a signature that does not
/// decode, or a key whose id is not the recorded `signer` fails closed.
/// Trust (is this key BELIEVED?) is the caller's keychain decision —
/// this checks self-consistency only, wrapping [`crate::sign::verify`].
pub fn verify(pkg: &PackageManifest, public_hex: &str) -> miette::Result<()> {
    let mut signatures = BTreeMap::new();
    signatures.insert(
        pkg.signer.clone(),
        serde_json::Value::String(pkg.signature.clone()),
    );
    crate::sign::verify(&canonical_bytes(pkg)?, &signatures, public_hex)
}

/// The pull-staging inbox path for one package's signed manifest:
/// `<root>/store/manifests/<pkg>.json`, where `root` is the state root
/// whose `store/` holds the content blobs.
///
/// Invariant (ADR-0033 Decision 5): `serve` and `export` publish the
/// UNION of the generation-derived manifests and this inbox — an inbox
/// entry whose name is not in the current generation is still visible.
/// This is how `pull` stages verified peer content without installing:
/// the manifest lands here, the blobs in the store, and installation
/// stays the pod workflow.
pub fn manifest_path(store_root: &Path, pkg: &str) -> PathBuf {
    store_root
        .join("store")
        .join("manifests")
        .join(format!("{pkg}.json"))
}

/// Host GNU triplet for minted `target` fields — the best target record
/// available at mint time (the pod store keeps no per-package build
/// triplet; payloads are host-arch glibc binaries).
pub fn host_target() -> String {
    format!("{}-unknown-linux-gnu", std::env::consts::ARCH)
}

/// The publishing-host identity `/info` and `index.json` carry: the
/// kernel hostname, read at `/proc/sys/kernel/hostname` (std fs, no new
/// deps). `unknown` when unreadable or empty — a label, never trust
/// state. `serve` prefers the configured `node.name` over this.
pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

// ── Trust-boundary validation of manifest contents ──

/// The sha256 discipline: exactly 64 lowercase hex chars — the same
/// content-address rule the store and the wire grammar use; anything
/// else is refused before it can reach a path.
pub fn validate_sha256(file: &ManifestFile) -> miette::Result<()> {
    let malformed = file.sha256.len() != 64
        || !file.sha256.bytes().all(|b| b.is_ascii_hexdigit())
        || file.sha256.bytes().any(|b| b.is_ascii_uppercase());
    if malformed {
        bail!(
            "manifest file '{}' carries malformed sha256 {:?} — expected 64 lowercase hex chars",
            file.path,
            file.sha256
        );
    }
    Ok(())
}

/// Boundary validation of a manifest's declared payload path: no
/// absolute paths, no `..` segments — a manifest is untrusted wire
/// input and its paths are only ever joined under the payload root by
/// the (future) install-from-inbox consumer.
pub fn validate_payload_path(file: &ManifestFile) -> miette::Result<()> {
    use std::path::Component;
    let unsafe_path = file.path.starts_with('/')
        || Path::new(&file.path)
            .components()
            .any(|c| c == Component::ParentDir);
    if unsafe_path {
        bail!(
            "manifest file carries an unsafe path {:?} — absolute paths and '..' \
             segments are refused",
            file.path
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic keypair from a single seed byte (test-only).
    fn test_kp(seed_byte: u8) -> KeyPair {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed_byte; 32]);
        KeyPair {
            seed: sk.to_bytes(),
            public: sk.verifying_key().to_bytes(),
        }
    }

    fn sample() -> PackageManifest {
        let mut apps = BTreeMap::new();
        apps.insert("hello".to_string(), "ab".repeat(32));
        let services: BTreeMap<String, ServiceDecl> = serde_json::from_value(
            serde_json::json!({ "srv": { "command": "bin/srv", "daemon": "simple" } }),
        )
        .unwrap();
        let confined: Confinement = serde_json::from_value(serde_json::json!({})).unwrap();
        PackageManifest {
            name: "hello".to_string(),
            version: "2.10".to_string(),
            revision: 7,
            target: "x86_64-linux-gnu".to_string(),
            files: vec![ManifestFile {
                path: "usr/bin/hello".to_string(),
                sha256: "cd".repeat(32),
                executable: true,
            }],
            install: InstallMeta {
                apps,
                services,
                confined: Some(confined),
                requires: vec!["libc6".to_string()],
                ..Default::default()
            },
            signer: String::new(),
            signature: String::new(),
        }
    }

    #[test]
    fn roundtrip_preserves_manifest() {
        let pkg = sample();
        let json = serde_json::to_string(&pkg).unwrap();
        let parsed: PackageManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, pkg);
    }

    #[test]
    fn canonical_bytes_are_stable_and_exclude_the_signature() {
        let mut pkg = sample();
        sign(&mut pkg, &test_kp(1)).unwrap();
        let canonical = canonical_bytes(&pkg).unwrap();

        // Byte-stable across calls…
        assert_eq!(canonical_bytes(&pkg).unwrap(), canonical);
        // …and identical to the unsigned shape: the signature field is
        // emptied, not removed, so re-serializing the unsigned manifest
        // matches.
        let mut unsigned = pkg.clone();
        unsigned.signature = String::new();
        assert_eq!(serde_json::to_vec(&unsigned).unwrap(), canonical);
        assert_ne!(serde_json::to_vec(&pkg).unwrap(), canonical);
    }

    #[test]
    fn verify_accepts_signed_manifest_and_refuses_tampered_signature() {
        let mut pkg = sample();
        sign(&mut pkg, &test_kp(1)).unwrap();
        let public = test_kp(1).public_hex();
        verify(&pkg, &public).expect("a freshly signed manifest must verify");

        let mut tampered = pkg.clone();
        tampered.signature.push('x');
        assert!(
            verify(&tampered, &public).is_err(),
            "a flipped signature must be refused"
        );

        // Content tampering changes the canonical bytes → refused too.
        let mut tampered = pkg.clone();
        tampered.files[0].sha256 = "ff".repeat(32);
        assert!(verify(&tampered, &public).is_err());
    }

    #[test]
    fn verify_refuses_a_different_key() {
        let mut pkg = sample();
        sign(&mut pkg, &test_kp(1)).unwrap();
        let other = test_kp(2).public_hex();
        assert!(
            verify(&pkg, &other).is_err(),
            "verifying under the wrong public key must fail closed"
        );
    }

    #[test]
    fn inbox_path_is_store_scoped_per_package() {
        let root = Path::new("/srv/nau-state");
        assert_eq!(
            manifest_path(root, "hello"),
            PathBuf::from("/srv/nau-state/store/manifests/hello.json")
        );
    }

    #[test]
    fn sha_validation_demands_64_lowercase_hex() {
        let ok = ManifestFile {
            path: "ab".repeat(32),
            sha256: "ab".repeat(32),
            executable: false,
        };
        validate_sha256(&ok).unwrap();
        for bad in ["AB".repeat(32), "ab".repeat(31), "zz".repeat(32)] {
            let file = ManifestFile {
                path: bad.clone(),
                sha256: bad,
                executable: false,
            };
            assert!(validate_sha256(&file).is_err(), "{:?}", file.sha256);
        }
    }

    #[test]
    fn payload_path_validation_refuses_absolute_and_parent_segments() {
        let file = |path: &str| ManifestFile {
            path: path.to_string(),
            sha256: "ab".repeat(32),
            executable: false,
        };
        validate_payload_path(&file("usr/bin/hello")).unwrap();
        validate_payload_path(&file("ab".repeat(32).as_str())).unwrap();
        for bad in [
            "/etc/passwd",
            "../../etc/passwd",
            "usr/../../etc/passwd",
            "..",
        ] {
            let err = validate_payload_path(&file(bad)).expect_err(bad);
            assert!(err.to_string().contains(bad), "{err}");
        }
    }

    // ── Minting half (moved beside `mint_manifest`, issue #326 PR 5) ──

    /// A generation record with one app, one launcher and one service
    /// binary (the executable bits' sources) plus two plain blobs.
    fn record() -> InstalledPackage {
        let mut apps = BTreeMap::new();
        apps.insert("hello".to_string(), "aa".repeat(32));
        let mut launchers = BTreeMap::new();
        launchers.insert("hello".to_string(), "bb".repeat(32));
        let mut service_bins = BTreeMap::new();
        service_bins.insert("srv".to_string(), "cc".repeat(32));
        InstalledPackage {
            name: "hello".into(),
            version: "2.10".into(),
            revision: 7,
            sha3_384: "a3".repeat(48),
            files: vec![
                "aa".repeat(32),
                "bb".repeat(32),
                "cc".repeat(32),
                "dd".repeat(32),
            ],
            units: vec![],
            layer: ClaimLayer::Own,
            apps,
            requires: vec!["libc6".into()],
            launchers,
            assembly: BTreeMap::new(),
            confined: None,
            app_confined: BTreeMap::new(),
            desktops: BTreeMap::new(),
            fonts: BTreeMap::new(),
            services: BTreeMap::new(),
            service_bins,
            meta_digest: None,
        }
    }

    /// The regression guard the council demanded: serve and export mint
    /// through this one function, so the same record serializes to the
    /// SAME bytes (ed25519 signatures are deterministic) — the `/info`-
    /// adjacent `manifests/<pkg>.json` a mirror freezes can never drift
    /// from the body `/manifests/<pkg>` serves.
    #[test]
    fn one_mint_serve_and_export_serialize_byte_identically() {
        let kp = test_kp(1);
        let mut served = mint_manifest(&record());
        sign(&mut served, &kp).unwrap();
        let mut exported = mint_manifest(&record());
        sign(&mut exported, &kp).unwrap();

        // The exact serializations the two lanes emit.
        let serve_body = serde_json::to_vec_pretty(&served).unwrap();
        let export_file = serde_json::to_vec_pretty(&exported).unwrap();
        assert_eq!(serve_body, export_file);
    }

    /// The minted manifest's documented semantics (export semantics won
    /// when the mints were consolidated): `files[].path` is the sha256
    /// store identity and `executable` is the recorded-command union.
    #[test]
    fn minted_files_carry_store_identity_and_command_executable_bits() {
        let manifest = mint_manifest(&record());
        assert_eq!(manifest.target, host_target());
        assert_eq!(manifest.files.len(), 4);
        for file in &manifest.files {
            assert_eq!(file.path, file.sha256, "path = store identity");
        }
        let exe: Vec<&str> = manifest
            .files
            .iter()
            .filter(|f| f.executable)
            .map(|f| f.sha256.as_str())
            .collect();
        // The app binary, the launcher wrapper and the service binary —
        // in `files` order; the plain blob stays non-executable.
        let (aa, bb, cc) = ("aa".repeat(32), "bb".repeat(32), "cc".repeat(32));
        assert_eq!(exe, vec![aa.as_str(), bb.as_str(), cc.as_str()]);
        assert_eq!(manifest.install.apps.len(), 1);
        assert_eq!(manifest.install.requires, vec!["libc6".to_string()]);
    }

    // ── Union helpers ──

    #[test]
    fn union_inbox_keeps_only_packages_outside_the_generation() {
        let mut packages = BTreeMap::new();
        packages.insert(
            "alpha".to_string(),
            InstalledPackage {
                name: "alpha".into(),
                revision: 1,
                ..record()
            },
        );
        let gen = Generation {
            n: 1,
            base_version: "test".into(),
            packages,
            created_epoch: 0,
            boot_entry: None,
        };
        let inbox = vec![
            ("alpha".to_string(), PathBuf::from("/x/alpha.json")),
            ("gamma".to_string(), PathBuf::from("/x/gamma.json")),
        ];
        let inbox_only: Vec<&(String, PathBuf)> = union_inbox(&Some(gen), &inbox);
        assert_eq!(inbox_only.len(), 1);
        assert_eq!(inbox_only[0].0, "gamma");
        assert!(
            union_inbox(&None, &inbox).len() == 2,
            "no generation → all inbox"
        );
    }
}

// ── The .desktop source-metadata parser (moved from the pod emit family,
// issue #326 PR 7: the on-device install records the parsed launcher
// metadata — pure text parsing, no store) ──

/// The metadata subset the launcher takes from a package's `.desktop`
/// file, parsed at install time and recorded in the generation manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DesktopSource {
    /// `Name=` (required for a valid entry).
    pub name: Option<String>,
    /// `GenericName=`, passed through.
    pub generic_name: Option<String>,
    /// `Comment=`, passed through.
    pub comment: Option<String>,
    /// `Categories=`, split on `;` (empties dropped).
    pub categories: Vec<String>,
    /// `Icon=` — a theme icon name passed through ONLY when the package
    /// ships no icon of its own (the emitter then substitutes the
    /// pod-namespaced link name).
    pub icon_ref: Option<String>,
}

/// Parse a package's `.desktop` file. Strict about what the launcher
/// NEEDS: the file must carry a `[Desktop Entry]` group with
/// `Type=Application` and a non-empty `Name=`; everything else the
/// launcher uses is optional. Unknown keys and locale variants
/// (`Name[de]=`) are ignored — the source file is the package's own.
pub fn parse_source(text: &str, label: &str) -> miette::Result<DesktopSource> {
    let mut source = DesktopSource::default();
    let mut in_entry = false;
    let mut saw_entry_group = false;
    let mut type_is_application = false;
    for line in text.lines() {
        if line.starts_with('[') {
            // A new group ends the Desktop Entry group.
            if in_entry {
                break;
            }
            in_entry = line == "[Desktop Entry]";
            saw_entry_group |= in_entry;
            continue;
        }
        if !in_entry || line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        // Locale variants (`Name[de]=`) are distinct keys — the
        // launcher uses the un-localized base key only.
        if key.contains('[') {
            continue;
        }
        match key {
            "Type" => type_is_application = value == "Application",
            "Name" => source.name = Some(unescape_value(value)),
            "GenericName" => source.generic_name = Some(unescape_value(value)),
            "Comment" => source.comment = Some(unescape_value(value)),
            "Categories" => {
                source.categories = value
                    .split(';')
                    .filter(|c| !c.is_empty())
                    .map(str::to_string)
                    .collect();
            }
            "Icon" => source.icon_ref = Some(unescape_value(value)),
            _ => {}
        }
    }
    if !saw_entry_group {
        miette::bail!("{label}: .desktop file has no [Desktop Entry] group");
    }
    if !type_is_application {
        miette::bail!("{label}: .desktop file must have Type=Application");
    }
    match &source.name {
        Some(n) if !n.trim().is_empty() => {}
        _ => miette::bail!("{label}: .desktop file must have a non-empty Name="),
    }
    Ok(source)
}

/// Unescape a `.desktop` string value: `\n`, `\t`, `\r`, `\s`, `\\`.
fn unescape_value(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let mut out = String::with_capacity(value.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        i += 1;
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.get(i) {
            Some('n') => {
                out.push('\n');
                i += 1;
            }
            Some('t') => {
                out.push('\t');
                i += 1;
            }
            Some('r') => {
                out.push('\r');
                i += 1;
            }
            Some('s') => {
                out.push(' ');
                i += 1;
            }
            Some('\\') => {
                out.push('\\');
                i += 1;
            }
            Some(&other) => {
                out.push('\\');
                out.push(other);
                i += 1;
            }
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod desktop_parse_tests {
    use super::*;

    #[test]
    fn parse_source_reads_the_metadata_subset() {
        let text = "[Desktop Entry]\nType=Application\nName=My App\nGenericName=Editor\n\
                    Comment=Does things\nCategories=Graphics;Viewer;\nIcon=theme-icon\n\
                    Exec=/somewhere/original\nName[de]=Meine App\nX-Custom=1\n";
        let src = parse_source(text, "test").unwrap();
        assert_eq!(src.name.as_deref(), Some("My App"));
        assert_eq!(src.generic_name.as_deref(), Some("Editor"));
        assert_eq!(src.comment.as_deref(), Some("Does things"));
        assert_eq!(src.categories, vec!["Graphics", "Viewer"]);
        assert_eq!(src.icon_ref.as_deref(), Some("theme-icon"));
    }

    #[test]
    fn parse_source_unescapes_values() {
        let src = parse_source("[Desktop Entry]\nType=Application\nName=a\\sb\n", "t").unwrap();
        assert_eq!(src.name.as_deref(), Some("a b"));
    }

    #[test]
    fn parse_source_requires_entry_group_type_and_name() {
        for (what, text) in [
            ("no group", "Type=Application\nName=x\n"),
            ("wrong type", "[Desktop Entry]\nType=Link\nName=x\n"),
            ("no type", "[Desktop Entry]\nName=x\n"),
            ("no name", "[Desktop Entry]\nType=Application\n"),
            ("empty name", "[Desktop Entry]\nType=Application\nName=  \n"),
        ] {
            let err = parse_source(text, "t").unwrap_err().to_string();
            assert!(!err.is_empty(), "{what} must fail");
        }
    }
}
