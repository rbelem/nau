//! Floor-tool self-provisioning (issue #101 disposition (c)).
//!
//! The pod surface (`mksquashfs`, `unsquashfs`, `bwrap`, `tar`, `curl`) is
//! absent from a fresh post-cutover login PATH, and pod-provided tools
//! cannot cold-start (the squashfs unpacker cannot ride inside the thing
//! it unpacks). This module is the rustup pattern: shuttle fetches pinned,
//! statically-linked tool binaries into a versioned tools root and
//! resolves them ahead of PATH.
//!
//! # Layout
//!
//! ```text
//! <root>/<tools_version>/bin/<tool>   one immutable set per manifest version
//! <root>/current                      pointer file: the active tools_version
//! ```
//!
//! A provision set is atomic: binaries are exec-tested in staging, the
//! versioned directory is renamed into place as a unit, and activation is
//! a pointer flip. Concurrent provisions cannot tear state — the loser of
//! a rename race validates the winner's stamps and short-circuits.
//!
//! # Resolution policy
//!
//! Per-tool, explicit: everything resolves provisioned-dir-first with PATH
//! fallback, except `curl`, which resolves PATH-first (host network
//! fidelity beats version fidelity for the one tool that lives behind
//! corporate NSS/LDAP directories and custom CA bundles). `SHUTTLE_TOOLS_DIR`
//! relocates the root; `SHUTTLE_TOOL_<UPPERNAME>` pins one tool to an exact
//! path.
//!
//! Resolution stats only — it never executes anything, so it is safe
//! mid-build. Version strings on [`ResolvedTool::Path`] are filled by the
//! separate, best-effort [`discover_version`] (used by doctor reporting,
//! never by resolution).
//!
//! # No silent fallback mid-build
//!
//! [`ensure`] is the build-path entry: for provisioned-first tools it
//! accepts ONLY the provisioned set and points at `shuttle doctor --fix`
//! otherwise. Provisioning is never invoked implicitly during resolution;
//! the two operations stay separate.
//!
//! # Integrity and exec-test
//!
//! Every fetched artifact is verified against the in-tree sha256 manifest
//! (fail closed, expected vs actual named) and then exec-tested
//! (`--version`) BEFORE it moves into place. An EACCES/EPERM at the probe
//! means the tools directory is likely mounted noexec — the diagnostic
//! names it and prints the `SHUTTLE_TOOLS_DIR` workaround, failing closed
//! at provision time rather than at first build (Yocto's checksum-ok-≠-runs
//! landmine).
//!
//! # Root of trust
//!
//! The manifest is compiled into this binary from `tools-manifest.toml`
//! (`include_str!`) — the git repo is the root of trust, same as the
//! shuttle binary itself. sha256 pins bytes, not provenance; per-tool
//! `source_url` carries the license/source offer (mere aggregation — no
//! embedding).

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use ureq::Agent;

/// Subdirectory holding the tool binaries inside a versioned set.
const BIN: &str = "bin";
/// Pointer file naming the active tools_version (`<root>/current`).
const CURRENT: &str = "current";
/// Stamp file inside a versioned set: proves the directory is the complete,
/// verified set for one manifest, not a partial leftover of a crashed run.
const STAMP: &str = ".stamp";
/// Tools-root default under `$HOME` (Linux-only project; matches the XDG
/// data location precedent of shuttle's own config handling).
const DEFAULT_ROOT_SUFFIX: &str = ".local/share/shuttle/tools";
const ENV_TOOLS_DIR: &str = "SHUTTLE_TOOLS_DIR";
/// Provisioning moves a few MB total; generous body ceiling, short
/// connect fail-fast.
pub(crate) const FETCH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Crate-visible so the vault source (src/secrets.rs) rides the SAME
/// timeout contract as the fetch stack instead of duplicating numbers.
pub(crate) const FETCH_TOTAL_TIMEOUT: Duration = Duration::from_secs(600);
/// Exec-probe budget: three tries with a short gap covers the flaky
/// ETXTBSY a heavily forking host can return for a just-closed file.
const PROBE_ATTEMPTS: u32 = 3;
const PROBE_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Result alias for the tools module.
pub type ToolsResult<T> = std::result::Result<T, ToolsError>;

/// The five floor tools (issue #101): everything else (`make`/`cc`/`c++`)
/// belongs to pods via `build_deps`; `sh` stays host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolName {
    Mksquashfs,
    Unsquashfs,
    Bwrap,
    Tar,
    Curl,
}

impl ToolName {
    /// All floor tools, stable order for reports and provision loops.
    pub const ALL: [ToolName; 5] = [
        ToolName::Mksquashfs,
        ToolName::Unsquashfs,
        ToolName::Bwrap,
        ToolName::Tar,
        ToolName::Curl,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            ToolName::Mksquashfs => "mksquashfs",
            ToolName::Unsquashfs => "unsquashfs",
            ToolName::Bwrap => "bwrap",
            ToolName::Tar => "tar",
            ToolName::Curl => "curl",
        }
    }

    /// Per-tool resolution override: `SHUTTLE_TOOL_<UPPERNAME>`.
    pub fn env_var(&self) -> String {
        format!("SHUTTLE_TOOL_{}", self.as_str().to_uppercase())
    }

    /// Policy default when the manifest carries no spec for the tool:
    /// provisioned-first everywhere except curl (PATH-first — host network
    /// fidelity beats version fidelity; musl-static ignores nsswitch.conf
    /// and ships no CA-bundle story).
    pub fn default_precedence(&self) -> Precedence {
        match self {
            ToolName::Curl => Precedence::PathFirst,
            _ => Precedence::ProvisionedFirst,
        }
    }
}

impl fmt::Display for ToolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which side of the resolution wins first, per tool, explicit in the
/// manifest. Default is provisioned-first; curl is the lone PATH-first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Precedence {
    #[default]
    ProvisionedFirst,
    PathFirst,
}

/// One pinned tool artifact. `url`/`sha256_hex` pin the exact bytes;
/// `source_url` carries the license/source offer (mere aggregation — the
/// release ships the build recipe; provenance without the recipe is
/// theater).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: ToolName,
    pub version: String,
    pub triple: String,
    pub url: String,
    pub sha256_hex: String,
    pub source_url: String,
    pub license: String,
    #[serde(default)]
    pub precedence: Precedence,
}

/// The in-tree manifest, compiled into the binary. `tools_version` is
/// monotonic; `min_kernel` is advisory (doctor warns, never hard-fails);
/// `signature` is reserved for future signing (a CI-held key would share
/// the manifest's compromise boundary — signing before an out-of-band key
/// exists is theater).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolsManifest {
    pub tools_version: u64,
    #[serde(default)]
    pub min_kernel: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub tools: Vec<ToolSpec>,
}

impl ToolsManifest {
    pub fn spec(&self, name: ToolName) -> Option<&ToolSpec> {
        self.tools.iter().find(|s| s.name == name)
    }
}

/// A tool resolved to a concrete path. `Provisioned.version` is the
/// installed set's `tools_version` (read from the pointer) — no execution,
/// and it is the number stale detection compares; the tool's upstream
/// version comes from the manifest [`ToolSpec`]. `Path.version` is `None`
/// at resolution time (resolution never executes); doctor reporting fills
/// it via [`discover_version`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedTool {
    Provisioned {
        path: PathBuf,
        version: String,
    },
    Path {
        path: PathBuf,
        version: Option<String>,
    },
}

/// Where provisioned bytes come from: the pinned release URLs (Fetch) or a
/// local directory of pre-fetched artifacts (offline, identical verify
/// path — `--from <dir>`).
#[derive(Debug, Clone)]
pub enum ProvisionSource {
    Fetch,
    FromDir(PathBuf),
}

/// The installed provision set after a successful [`provision`].
#[derive(Debug, Clone)]
pub struct ToolsRoot {
    pub root: PathBuf,
    pub tools_version: u64,
    pub bin_dir: PathBuf,
}

/// Manifest/installed-set divergence (issue #101 stale-shadow policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stale {
    pub installed: u64,
    pub manifest: u64,
}

#[derive(Debug)]
pub enum ToolsError {
    Io {
        context: String,
        source: io::Error,
    },
    Manifest(String),
    Fetch {
        tool: String,
        url: String,
        source: Box<ureq::Error>,
    },
    HashMismatch {
        tool: String,
        expected: String,
        actual: String,
    },
    /// EACCES/EPERM running the exec probe: the tools root is likely on a
    /// noexec mount. Names the cause and the `SHUTTLE_TOOLS_DIR` workaround.
    Noexec {
        tool: String,
        path: PathBuf,
        source: io::Error,
    },
    ProbeFailed {
        tool: String,
        detail: String,
    },
    NotResolved {
        tool: String,
        detail: String,
    },
}

impl fmt::Display for ToolsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ToolsError::Io { context, source } => write!(f, "{context}: {source}"),
            ToolsError::Manifest(msg) => write!(f, "tools manifest is invalid: {msg}"),
            ToolsError::Fetch { tool, url, source } => {
                write!(f, "fetch of '{tool}' from {url} failed: {source}")
            }
            ToolsError::HashMismatch { tool, expected, actual } => write!(
                f,
                "sha256 mismatch for '{tool}': expected {expected}, got {actual} — refusing to install"
            ),
            ToolsError::Noexec { tool, path, source } => write!(
                f,
                "cannot execute staged '{tool}' at {}: {source} — the tools directory is likely \
                 mounted noexec; relocate it by setting SHUTTLE_TOOLS_DIR to an exec-mounted \
                 path (e.g. SHUTTLE_TOOLS_DIR=/var/tmp/shuttle-tools) and re-run \
                 `shuttle doctor --fix`",
                path.display()
            ),
            ToolsError::ProbeFailed { tool, detail } => {
                write!(f, "exec probe failed for '{tool}': {detail}")
            }
            ToolsError::NotResolved { tool, detail } => {
                write!(f, "tool '{tool}' could not be resolved: {detail}")
            }
        }
    }
}

impl std::error::Error for ToolsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ToolsError::Io { source, .. } | ToolsError::Noexec { source, .. } => Some(source),
            ToolsError::Fetch { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/// The in-tree manifest bytes, compiled into the binary: the git repo is
/// the root of trust, same as the shuttle binary itself.
pub const MANIFEST_TOML: &str = include_str!("../tools-manifest.toml");

/// Parse manifest bytes. Tolerates an empty tools list (the shipped state
/// until the CI lane attaches artifacts).
pub fn parse_manifest(toml_str: &str) -> ToolsResult<ToolsManifest> {
    toml::from_str(toml_str).map_err(|e| ToolsError::Manifest(e.to_string()))
}

/// The compiled-in manifest.
pub fn manifest() -> ToolsManifest {
    // Unwrap is sound: MANIFEST_TOML is repo-controlled and unit-tested.
    parse_manifest(MANIFEST_TOML).expect("embedded tools-manifest.toml must parse")
}

// ---------------------------------------------------------------------------
// Resolution (stats only — never executes)
// ---------------------------------------------------------------------------

/// Effective precedence for `name`: the manifest spec's field when present,
/// otherwise the per-tool default. A free function over an explicit
/// manifest so tests can inject one.
fn precedence_in(m: &ToolsManifest, name: ToolName) -> Precedence {
    m.spec(name)
        .map(|s| s.precedence)
        .unwrap_or_else(|| name.default_precedence())
}

/// The tools root: `SHUTTLE_TOOLS_DIR` override, else
/// `$HOME/.local/share/shuttle/tools`.
fn tools_root_opt() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os(ENV_TOOLS_DIR) {
        return Some(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(DEFAULT_ROOT_SUFFIX))
}

fn tools_root() -> ToolsResult<PathBuf> {
    tools_root_opt().ok_or_else(|| ToolsError::Io {
        context: "cannot locate the tools root (HOME not set; set SHUTTLE_TOOLS_DIR)".into(),
        source: io::Error::new(io::ErrorKind::NotFound, "HOME not set"),
    })
}

/// Resolve `name` following its manifest precedence, honouring
/// `SHUTTLE_TOOL_<UPPERNAME>` (which pins the tool to an exact path and
/// beats every other rule — a missing or non-executable override fails
/// loud rather than silently falling back). Stats only.
pub fn resolve(name: ToolName) -> ToolsResult<ResolvedTool> {
    let override_path = std::env::var_os(name.env_var()).map(PathBuf::from);
    let root = tools_root()?;
    resolve_explicit(&root, &path_dirs(), override_path.as_deref(), name)
}

/// [`resolve`] with every input explicit — the test seam and the shape
/// doctor reporting uses for per-source diagnostics.
fn resolve_explicit(
    root: &Path,
    path_dirs: &[PathBuf],
    override_path: Option<&Path>,
    name: ToolName,
) -> ToolsResult<ResolvedTool> {
    if let Some(p) = override_path {
        if !is_executable(p) {
            return Err(ToolsError::NotResolved {
                tool: name.as_str().into(),
                detail: format!(
                    "the {} override points at {}, which is not an executable file",
                    name.env_var(),
                    p.display()
                ),
            });
        }
        return Ok(ResolvedTool::Path {
            path: p.to_path_buf(),
            version: None,
        });
    }
    let provisioned = provisioned_lookup(root, name)
        .map(|(path, version)| ResolvedTool::Provisioned { path, version });
    let on_path =
        path_lookup(path_dirs, name).map(|(path, version)| ResolvedTool::Path { path, version });
    let (first, second) = match precedence_in(&manifest(), name) {
        Precedence::ProvisionedFirst => (provisioned, on_path),
        Precedence::PathFirst => (on_path, provisioned),
    };
    first.or(second).ok_or_else(|| ToolsError::NotResolved {
        tool: name.as_str().into(),
        detail: "no provisioned set and no executable on PATH; run `shuttle doctor --fix` \
                     to provision the floor tools"
            .into(),
    })
}

/// The build-path entry point: like [`resolve`] but with the mid-build
/// failure policy (issue #101 AC-7). For provisioned-first tools it
/// accepts ONLY the provisioned set — a missing set is a hard error naming
/// `shuttle doctor --fix`, never a silent PATH fallback. curl (PATH-first)
/// keeps its precedence: PATH, then the provisioned fallback.
///
/// This never invokes the provisioner; resolution and provisioning stay
/// separate operations.
pub fn ensure(name: ToolName) -> ToolsResult<ResolvedTool> {
    let override_path = std::env::var_os(name.env_var()).map(PathBuf::from);
    let root = tools_root()?;
    ensure_explicit(&root, &path_dirs(), override_path.as_deref(), name)
}

/// [`ensure`] with every input explicit — the test seam.
fn ensure_explicit(
    root: &Path,
    path_dirs: &[PathBuf],
    override_path: Option<&Path>,
    name: ToolName,
) -> ToolsResult<ResolvedTool> {
    if precedence_in(&manifest(), name) == Precedence::PathFirst {
        return resolve_explicit(root, path_dirs, override_path, name);
    }
    provisioned_lookup(root, name)
        .map(|(path, version)| ResolvedTool::Provisioned { path, version })
        .ok_or_else(|| ToolsError::NotResolved {
            tool: name.as_str().into(),
            detail: "not provisioned; shuttle never falls back to PATH mid-build for \
                     provisioned-first tools — run `shuttle doctor --fix`"
                .into(),
        })
}

/// The active provisioned binary for `name`, if the pointer names an
/// existing set that still contains it: `(<path>, <tools_version string>)`.
fn provisioned_lookup(root: &Path, name: ToolName) -> Option<(PathBuf, String)> {
    let version = fs::read_to_string(root.join(CURRENT)).ok()?;
    let version = version.trim();
    let path = root.join(version).join(BIN).join(name.as_str());
    is_executable(&path).then(|| (path, version.to_string()))
}

fn path_dirs() -> Vec<PathBuf> {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default()
}

fn path_lookup(path_dirs: &[PathBuf], name: ToolName) -> Option<(PathBuf, Option<String>)> {
    path_dirs
        .iter()
        .map(|dir| dir.join(name.as_str()))
        .find(|p| is_executable(p))
        .map(|p| (p, None))
}

fn is_executable(path: &Path) -> bool {
    fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Best-effort version discovery for a resolved binary: run a
/// `--version`/`-version` probe and pull the first whitespace token that
/// contains a digit ("curl 8.5.0 (...)" → "8.5.0"; "tar (GNU tar) 1.35" →
/// "1.35"). `None` is acceptable — callers treat versions as advisory.
/// Never called by resolution itself.
pub fn discover_version(path: &Path) -> Option<String> {
    ["--version", "-version"]
        .into_iter()
        .find_map(|flag| version_from_probe(path, flag))
}

fn version_from_probe(path: &Path, flag: &str) -> Option<String> {
    let out = Command::new(path).arg(flag).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    parse_version_token(stdout.lines().next()?)
}

fn parse_version_token(line: &str) -> Option<String> {
    line.split_whitespace()
        .find(|token| token.chars().any(|c| c.is_ascii_digit()))
        .map(str::to_string)
}

/// Doctor's origin+version report: every resolvable floor tool with PATH
/// versions enriched (provisioned sets already carry their set version).
/// Tools that fail resolution are omitted — doctor surfaces those per-tool
/// via [`resolve`] directly when it needs the error.
pub fn installed_report() -> Vec<(ToolName, ResolvedTool)> {
    ToolName::ALL
        .into_iter()
        .filter_map(|name| {
            let resolved = resolve(name).ok()?;
            let enriched = match resolved {
                ResolvedTool::Path {
                    path,
                    version: None,
                } => ResolvedTool::Path {
                    version: discover_version(&path),
                    path,
                },
                other => other,
            };
            Some((name, enriched))
        })
        .collect()
}

/// Manifest/installed-set divergence against the live tools root.
/// Nothing installed (missing or unparseable pointer) is not stale — the
/// next provision defines the state.
pub fn detect_stale() -> Option<Stale> {
    let root = tools_root_opt()?;
    detect_stale_in(&root, &manifest())
}

fn detect_stale_in(root: &Path, m: &ToolsManifest) -> Option<Stale> {
    let installed = fs::read_to_string(root.join(CURRENT)).ok()?;
    let installed = installed.trim().parse::<u64>().ok()?;
    (installed != m.tools_version).then_some(Stale {
        installed,
        manifest: m.tools_version,
    })
}

// ---------------------------------------------------------------------------
// Provisioning
// ---------------------------------------------------------------------------

/// Provision the compiled-in manifest into the tools root.
///
/// Fetch: each artifact streams from its pinned URL (redirects followed)
/// into a temp file on the target filesystem, verifies sha256 (fail
/// closed), passes the exec probe, then moves into the versioned set —
/// and only a fully verified set is published (atomic directory rename)
/// and activated (atomic pointer flip). A versioned directory whose stamps
/// already verify short-circuits the whole run, which is what makes
/// concurrent provisions safe.
pub fn provision(source: ProvisionSource) -> ToolsResult<ToolsRoot> {
    provision_with(&manifest(), source)
}

fn provision_with(m: &ToolsManifest, source: ProvisionSource) -> ToolsResult<ToolsRoot> {
    let root = tools_root()?;
    let version_dir = root.join(m.tools_version.to_string());
    if installed_set_valid(&version_dir, m) {
        flip_pointer(&root, m.tools_version)?;
        return Ok(ToolsRoot {
            bin_dir: version_dir.join(BIN),
            root,
            tools_version: m.tools_version,
        });
    }

    fs::create_dir_all(&root).map_err(|e| io_context("create tools root", e))?;
    // Staging lives on the target filesystem, so every later rename is
    // atomic (same-device), and the exec probe exercises the mount the
    // tools will actually run from (noexec detection).
    let staging =
        tempfile::TempDir::new_in(&root).map_err(|e| io_context("create staging dir", e))?;
    let stage_version_dir = staging.path().join(m.tools_version.to_string());
    let stage_bin = stage_version_dir.join(BIN);
    fs::create_dir_all(&stage_bin).map_err(|e| io_context("create staging bin dir", e))?;

    for spec in &m.tools {
        match &source {
            ProvisionSource::Fetch => stage_fetch(spec, &stage_bin)?,
            ProvisionSource::FromDir(dir) => stage_from_dir(dir, spec, &stage_bin)?,
        }
    }
    fs::write(stage_version_dir.join(STAMP), stamp_text(m))
        .map_err(|e| io_context("write provision stamp", e))?;

    // Publish: the set appears complete or not at all. Losing a rename
    // race to a concurrent provisioner is fine when the winner's stamps
    // verify — that IS the state we wanted.
    if let Err(e) = fs::rename(&stage_version_dir, &version_dir) {
        if !installed_set_valid(&version_dir, m) {
            return Err(ToolsError::Io {
                context: format!(
                    "publish provision set {} (renaming {} into place)",
                    m.tools_version,
                    version_dir.display()
                ),
                source: e,
            });
        }
    }
    flip_pointer(&root, m.tools_version)?;

    Ok(ToolsRoot {
        bin_dir: version_dir.join(BIN),
        root,
        tools_version: m.tools_version,
    })
}

fn stage_fetch(spec: &ToolSpec, stage_bin: &Path) -> ToolsResult<()> {
    let agent = fetch_agent(FETCH_CONNECT_TIMEOUT, FETCH_TOTAL_TIMEOUT);
    let mut reader = http_get(&agent, &spec.url).map_err(|source| ToolsError::Fetch {
        tool: spec.name.as_str().into(),
        url: spec.url.clone(),
        source,
    })?;
    stage_verified(spec, reader.as_mut(), stage_bin)
}

fn stage_from_dir(dir: &Path, spec: &ToolSpec, stage_bin: &Path) -> ToolsResult<()> {
    let src = dir.join(spec.name.as_str());
    let mut file = File::open(&src).map_err(|e| {
        io_context(
            format!(
                "open offline artifact {} for '{}'",
                src.display(),
                spec.name
            ),
            e,
        )
    })?;
    stage_verified(spec, &mut file, stage_bin)
}

/// The shared verify path: stream bytes into a temp file on the target
/// filesystem, verify sha256 (fail closed), make executable, exec-probe —
/// and only then move into the staging set. Identical for fetched and
/// offline-sourced artifacts.
///
/// The stage file lives in the run's private staging `TempDir`, so its
/// name cannot collide with a concurrent provision, and any failure path
/// leaves cleanup to the TempDir. The writable handle is closed before the
/// exec probe: Linux refuses to exec a file with an open writer (ETXTBSY).
fn stage_verified(spec: &ToolSpec, src: &mut dyn Read, stage_bin: &Path) -> ToolsResult<()> {
    let staged = stage_bin.join(format!(".stage-{}", spec.name.as_str()));
    let mut file = File::create(&staged).map_err(|e| io_context("create staged temp file", e))?;
    io::copy(src, &mut file)
        .map_err(|e| io_context(format!("stream artifact bytes for '{}'", spec.name), e))?;
    file.sync_all()
        .map_err(|e| io_context("flush staged artifact", e))?;
    drop(file);

    let actual = sha256_hex_file(&staged)?;
    let expected = spec.sha256_hex.trim().to_lowercase();
    if actual != expected {
        return Err(ToolsError::HashMismatch {
            tool: spec.name.as_str().into(),
            expected,
            actual,
        });
    }

    fs::set_permissions(&staged, fs::Permissions::from_mode(0o755))
        .map_err(|e| io_context("chmod staged artifact", e))?;
    exec_probe(&staged, spec.name.as_str())?;

    fs::rename(&staged, stage_bin.join(spec.name.as_str())).map_err(|e| {
        io_context(
            format!(
                "move staged artifact for '{}' into the provision set",
                spec.name
            ),
            e,
        )
    })?;
    Ok(())
}

/// Run the `--version` probe on a staged binary BEFORE it moves into
/// place. EACCES/EPERM here is the noexec-mount signature (the artifact
/// bytes are verified — it is the mount that refuses execution): the
/// [`ToolsError::Noexec`] diagnostic names it and prints the
/// `SHUTTLE_TOOLS_DIR` workaround, so `doctor --fix` fails closed now
/// instead of the first build failing later.
///
/// ETXTBSY is retried briefly: the writable handle is long closed by then,
/// and a spuriously busy reply can come from concurrent fork/exec activity
/// on the host — never worth failing a provision over.
fn exec_probe(path: &Path, tool: &str) -> ToolsResult<()> {
    let mut attempts = 0;
    loop {
        attempts += 1;
        match Command::new(path).arg("--version").output() {
            Ok(out) if out.status.success() => return Ok(()),
            Ok(out) => {
                return Err(ToolsError::ProbeFailed {
                    tool: tool.into(),
                    detail: match out.status.code() {
                        Some(code) => format!("`--version` exited with status {code}"),
                        None => "`--version` was killed by a signal".into(),
                    },
                });
            }
            Err(e) if is_text_file_busy(&e) && attempts < PROBE_ATTEMPTS => {
                std::thread::sleep(PROBE_RETRY_DELAY);
            }
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                return Err(ToolsError::Noexec {
                    tool: tool.into(),
                    path: path.to_path_buf(),
                    source: e,
                });
            }
            Err(e) => {
                return Err(io_context(
                    format!("spawn '{tool}' for the exec probe at {}", path.display()),
                    e,
                ));
            }
        }
    }
}

fn is_text_file_busy(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::ExecutableFileBusy || e.raw_os_error() == Some(26 /* ETXTBSY */)
}

/// A versioned directory counts as installed only when every manifest tool
/// is present, executable, and the stamp matches this exact manifest — a
/// partial or stale-content directory must not short-circuit.
fn installed_set_valid(version_dir: &Path, m: &ToolsManifest) -> bool {
    version_dir.join(BIN).is_dir()
        && m.tools
            .iter()
            .all(|s| is_executable(&version_dir.join(BIN).join(s.name.as_str())))
        && fs::read_to_string(version_dir.join(STAMP)).is_ok_and(|stamp| stamp == stamp_text(m))
}

/// Deterministic set identity: tools_version plus every pinned hash.
/// Written into the published set; compared on short-circuit and rename
/// races.
fn stamp_text(m: &ToolsManifest) -> String {
    let mut text = format!("tools_version={}\n", m.tools_version);
    for spec in &m.tools {
        text.push_str(&format!(
            "{}={}\n",
            spec.name.as_str(),
            spec.sha256_hex.trim().to_lowercase()
        ));
    }
    text
}

/// Activate a provision set: pointer flip via write-temp + rename (atomic
/// replace), so a reader sees either the old or the new version, never a
/// torn file.
fn flip_pointer(root: &Path, version: u64) -> ToolsResult<()> {
    let tmp = NamedTempFile::new_in(root).map_err(|e| io_context("create pointer temp file", e))?;
    fs::write(tmp.path(), format!("{version}\n"))
        .map_err(|e| io_context("write pointer temp file", e))?;
    fs::rename(tmp.path(), root.join(CURRENT))
        .map_err(|e| io_context(format!("flip {CURRENT} -> {version} (atomic rename)"), e))?;
    Ok(())
}

fn fetch_agent(connect: Duration, total: Duration) -> Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(connect)
        .timeout(total)
        .build()
}

fn http_get(agent: &Agent, url: &str) -> Result<Box<dyn Read>, Box<ureq::Error>> {
    let response = agent.get(url).call().map_err(Box::new)?;
    let reader: Box<dyn Read> = Box::new(response.into_reader());
    Ok(reader)
}

fn sha256_hex_file(path: &Path) -> ToolsResult<String> {
    let mut file =
        File::open(path).map_err(|e| io_context("re-open staged artifact for hashing", e))?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher).map_err(|e| io_context("hash staged artifact", e))?;
    Ok(to_hex(&hasher.finalize()))
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn io_context(context: impl Into<String>, source: io::Error) -> ToolsError {
    ToolsError::Io {
        context: context.into(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Env vars are process-global; cargo runs tests in parallel threads.
    /// Every test that reads or mutates tool-related env holds this lock —
    /// the shared crate-wide one (src/test_env.rs); the per-module
    /// statics of the pre-#186 era excluded nothing across modules.
    use crate::test_env::ENV_LOCK;

    /// Points `SHUTTLE_TOOLS_DIR` at a tempdir for the test's lifetime and
    /// restores the previous value on drop — provision tests must never
    /// touch the real `$HOME/.local/share/shuttle/tools`.
    struct ToolsDirGuard {
        saved: Option<std::ffi::OsString>,
    }

    impl ToolsDirGuard {
        fn at(path: &Path) -> Self {
            let saved = std::env::var_os(ENV_TOOLS_DIR);
            std::env::set_var(ENV_TOOLS_DIR, path);
            ToolsDirGuard { saved }
        }
    }

    impl Drop for ToolsDirGuard {
        fn drop(&mut self) {
            match self.saved.take() {
                Some(v) => std::env::set_var(ENV_TOOLS_DIR, v),
                None => std::env::remove_var(ENV_TOOLS_DIR),
            }
        }
    }

    fn fake_tool_body(name: ToolName) -> String {
        format!("#!/bin/sh\necho {} 9.9.9-fake\n", name.as_str())
    }

    fn write_fake_tool(dir: &Path, name: ToolName) -> PathBuf {
        let path = dir.join(name.as_str());
        fs::write(&path, fake_tool_body(name)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn sha256_hex_bytes(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        to_hex(&h.finalize())
    }

    fn fake_spec(name: ToolName) -> ToolSpec {
        ToolSpec {
            name,
            version: "9.9.9-fake".into(),
            triple: "x86_64-linux-musl".into(),
            url: format!("http://127.0.0.1:1/{}.bin", name.as_str()),
            sha256_hex: sha256_hex_bytes(fake_tool_body(name).as_bytes()),
            source_url: "https://example.invalid/src".into(),
            license: "GPL-2.0+".into(),
            precedence: Precedence::ProvisionedFirst,
        }
    }

    fn manifest_for(version: u64, tools: &[ToolName]) -> ToolsManifest {
        ToolsManifest {
            tools_version: version,
            min_kernel: None,
            signature: None,
            tools: tools.iter().map(|n| fake_spec(*n)).collect(),
        }
    }

    #[test]
    fn embedded_manifest_parses_with_empty_tools() {
        let m = manifest();
        assert_eq!(m.tools_version, 1);
        assert!(m.tools.is_empty());
        assert_eq!(m.min_kernel, None);
        // Round-trips through the public parser, not just the const path.
        assert_eq!(parse_manifest(MANIFEST_TOML).unwrap(), m);
    }

    #[test]
    fn manifest_schema_parses_all_fields_and_defaults_precedence() {
        let toml_str = r#"
            tools_version = 3
            min_kernel = "5.10"
            signature = ""
            [[tools]]
            name = "mksquashfs"
            version = "4.7.2"
            triple = "x86_64-linux-musl"
            url = "https://example.invalid/mksquashfs"
            sha256_hex = "aa"
            source_url = "https://example.invalid/src"
            license = "GPL-2.0+"
            [[tools]]
            name = "curl"
            version = "8.5.0"
            triple = "x86_64-linux-musl"
            url = "https://example.invalid/curl"
            sha256_hex = "bb"
            source_url = "https://example.invalid/src"
            license = "curl"
            precedence = "path-first"
        "#;
        let m = parse_manifest(toml_str).unwrap();
        assert_eq!(m.tools_version, 3);
        assert_eq!(m.min_kernel.as_deref(), Some("5.10"));
        assert_eq!(m.tools.len(), 2);
        // Unspecified precedence defaults to provisioned-first.
        assert_eq!(m.tools[0].precedence, Precedence::ProvisionedFirst);
        assert_eq!(m.tools[1].precedence, Precedence::PathFirst);
        assert_eq!(m.spec(ToolName::Curl).unwrap().version, "8.5.0");
        assert!(m.spec(ToolName::Bwrap).is_none());
    }

    #[test]
    fn precedence_defaults_and_manifest_override() {
        let empty = manifest();
        assert_eq!(
            precedence_in(&empty, ToolName::Mksquashfs),
            Precedence::ProvisionedFirst
        );
        assert_eq!(precedence_in(&empty, ToolName::Curl), Precedence::PathFirst);

        // A manifest spec overrides the per-tool default.
        let mut m = manifest();
        m.tools.push(ToolSpec {
            name: ToolName::Curl,
            version: "1".into(),
            triple: "t".into(),
            url: "u".into(),
            sha256_hex: "h".into(),
            source_url: "s".into(),
            license: "l".into(),
            precedence: Precedence::ProvisionedFirst,
        });
        assert_eq!(
            precedence_in(&m, ToolName::Curl),
            Precedence::ProvisionedFirst
        );
    }

    #[test]
    fn provisioned_first_wins_over_path_and_curl_is_path_first() {
        let root = tempfile::tempdir().unwrap();
        let pathdir = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("7/bin")).unwrap();
        write_fake_tool(&root.path().join("7/bin"), ToolName::Mksquashfs);
        write_fake_tool(&root.path().join("7/bin"), ToolName::Curl);
        write_fake_tool(pathdir.path(), ToolName::Mksquashfs);
        write_fake_tool(pathdir.path(), ToolName::Curl);
        fs::write(root.path().join(CURRENT), "7\n").unwrap();
        let dirs = [pathdir.path().to_path_buf()];

        // mksquashfs: provisioned-first — the provisioned set wins even
        // though PATH also carries a binary.
        let r = resolve_explicit(root.path(), &dirs, None, ToolName::Mksquashfs).unwrap();
        assert_eq!(
            r,
            ResolvedTool::Provisioned {
                path: root.path().join("7/bin/mksquashfs"),
                version: "7".into(),
            }
        );

        // curl: PATH-first — the PATH binary wins over the provisioned set.
        let r = resolve_explicit(root.path(), &dirs, None, ToolName::Curl).unwrap();
        assert_eq!(
            r,
            ResolvedTool::Path {
                path: pathdir.path().join("curl"),
                version: None,
            }
        );

        // PATH fallback for a provisioned-first tool with no set installed.
        fs::remove_file(root.path().join(CURRENT)).unwrap();
        let r = resolve_explicit(root.path(), &dirs, None, ToolName::Mksquashfs).unwrap();
        assert!(matches!(r, ResolvedTool::Path { .. }));
    }

    #[test]
    fn env_override_pins_resolution_to_an_exact_path() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let fake = write_fake_tool(dir.path(), ToolName::Tar);

        std::env::set_var(ToolName::Tar.env_var(), &fake);
        let result = resolve(ToolName::Tar);
        std::env::remove_var(ToolName::Tar.env_var());

        assert_eq!(
            result.unwrap(),
            ResolvedTool::Path {
                path: fake,
                version: None,
            }
        );

        // A dangling override fails loud instead of silently falling back.
        std::env::set_var(ToolName::Tar.env_var(), "/nonexistent/tar-zz9x");
        let err = resolve(ToolName::Tar);
        std::env::remove_var(ToolName::Tar.env_var());
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("SHUTTLE_TOOL_TAR"), "{msg}");
    }

    #[test]
    fn fromdir_provision_installs_verifies_and_flips_pointer() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _guard = ToolsDirGuard::at(root.path());
        let src = tempfile::tempdir().unwrap();
        let tools = [ToolName::Mksquashfs, ToolName::Curl];
        for name in tools {
            write_fake_tool(src.path(), name);
        }
        let m = manifest_for(4, &tools);

        let installed = provision_with(&m, ProvisionSource::FromDir(src.path().to_path_buf()))
            .unwrap_or_else(|e| panic!("provision failed: {e}"));
        assert_eq!(installed.tools_version, 4);
        assert_eq!(installed.bin_dir, root.path().join("4/bin"));

        // Pointer, exec bit, and resolution through the public shape.
        assert_eq!(
            fs::read_to_string(root.path().join(CURRENT)).unwrap(),
            "4\n"
        );
        let bin = root.path().join("4/bin/mksquashfs");
        assert!(is_executable(&bin));
        assert!(detect_stale_in(root.path(), &m).is_none());
        assert_eq!(
            resolve_explicit(root.path(), &[], None, ToolName::Mksquashfs).unwrap(),
            ResolvedTool::Provisioned {
                path: bin,
                version: "4".into(),
            }
        );

        // Stale detection fires while the manifest is ahead of the set.
        let stale = detect_stale_in(root.path(), &manifest_for(5, &tools)).unwrap();
        assert_eq!(stale.installed, 4);
        assert_eq!(stale.manifest, 5);

        // A second version installs alongside and flips the pointer.
        provision_with(
            &manifest_for(5, &tools),
            ProvisionSource::FromDir(src.path().to_path_buf()),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(root.path().join(CURRENT)).unwrap(),
            "5\n"
        );
        assert!(root.path().join("4/bin/mksquashfs").exists());
        assert!(detect_stale_in(root.path(), &manifest_for(5, &tools)).is_none());
    }

    #[test]
    fn verified_set_short_circuits_a_rerun_even_from_corrupt_sources() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _guard = ToolsDirGuard::at(root.path());
        let src = tempfile::tempdir().unwrap();
        let tools = [ToolName::Tar];
        write_fake_tool(src.path(), ToolName::Tar);
        let m = manifest_for(2, &tools);
        provision_with(&m, ProvisionSource::FromDir(src.path().to_path_buf())).unwrap();
        let installed_bytes = fs::read(root.path().join("2/bin/tar")).unwrap();

        // Corrupt the source: a rerun must short-circuit on the stamps
        // BEFORE touching any artifact bytes.
        fs::write(src.path().join("tar"), b"corrupted").unwrap();
        provision_with(&m, ProvisionSource::FromDir(src.path().to_path_buf())).unwrap();
        assert_eq!(
            fs::read(root.path().join("2/bin/tar")).unwrap(),
            installed_bytes
        );
    }

    #[test]
    fn tampered_artifact_fails_closed_with_named_hashes() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _guard = ToolsDirGuard::at(root.path());
        let src = tempfile::tempdir().unwrap();
        write_fake_tool(src.path(), ToolName::Bwrap);
        let mut m = manifest_for(1, &[ToolName::Bwrap]);
        m.tools[0].sha256_hex = sha256_hex_bytes(b"not what is on disk");

        let err =
            provision_with(&m, ProvisionSource::FromDir(src.path().to_path_buf())).unwrap_err();
        match err {
            ToolsError::HashMismatch {
                tool,
                expected,
                actual,
            } => {
                assert_eq!(tool, "bwrap");
                assert_ne!(expected, actual);
                assert_eq!(expected.len(), 64);
            }
            other => panic!("expected HashMismatch, got {other:?}"),
        }
        // Nothing was published or activated.
        assert!(!root.path().join("1").exists());
        assert!(!root.path().join(CURRENT).exists());
    }

    #[test]
    fn probe_failure_blocks_installation() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _guard = ToolsDirGuard::at(root.path());
        let src = tempfile::tempdir().unwrap();
        // A "binary" that runs but exits non-zero: sha256 verifies, the
        // exec probe must still refuse it.
        let path = src.path().join("unsquashfs");
        fs::write(&path, "#!/bin/sh\necho boom >&2\nexit 3\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let mut m = manifest_for(1, &[ToolName::Unsquashfs]);
        m.tools[0].sha256_hex = sha256_hex_bytes(&fs::read(&path).unwrap());

        let err =
            provision_with(&m, ProvisionSource::FromDir(src.path().to_path_buf())).unwrap_err();
        assert!(matches!(err, ToolsError::ProbeFailed { ref tool, .. } if tool == "unsquashfs"));
        assert!(!root.path().join(CURRENT).exists());
    }

    #[test]
    fn ensure_hard_fails_with_doctor_hint_then_succeeds_once_provisioned() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _guard = ToolsDirGuard::at(root.path());

        // Provisioned-first tool with nothing provisioned: ensure refuses,
        // naming `shuttle doctor --fix`.
        let msg = ensure(ToolName::Mksquashfs).unwrap_err().to_string();
        assert!(msg.contains("shuttle doctor --fix"), "{msg}");

        let src = tempfile::tempdir().unwrap();
        write_fake_tool(src.path(), ToolName::Mksquashfs);
        provision_with(
            &manifest_for(6, &[ToolName::Mksquashfs]),
            ProvisionSource::FromDir(src.path().to_path_buf()),
        )
        .unwrap();
        assert!(matches!(
            ensure(ToolName::Mksquashfs).unwrap(),
            ResolvedTool::Provisioned { .. }
        ));
    }

    #[test]
    fn ensure_keeps_path_first_precedence_for_curl() {
        // Explicit-input seam: no global PATH mutation (parallel tests in
        // this process spawn tools off the real PATH).
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let pathdir = tempfile::tempdir().unwrap();
        write_fake_tool(pathdir.path(), ToolName::Curl);

        // curl keeps PATH-first precedence inside ensure.
        let r = ensure_explicit(
            root.path(),
            &[pathdir.path().to_path_buf()],
            None,
            ToolName::Curl,
        )
        .unwrap();
        assert!(matches!(r, ResolvedTool::Path { .. }));

        // ...and the provisioned set is the fallback, not the first choice.
        let src = tempfile::tempdir().unwrap();
        write_fake_tool(src.path(), ToolName::Curl);
        provision_rooted_fixture(root.path(), 8, &[ToolName::Curl], src.path());
        let r = ensure_explicit(
            root.path(),
            &[pathdir.path().to_path_buf()],
            None,
            ToolName::Curl,
        )
        .unwrap();
        assert!(matches!(r, ResolvedTool::Path { .. }));
        // With PATH exhausted, the provisioned fallback answers.
        let r = ensure_explicit(root.path(), &[], None, ToolName::Curl).unwrap();
        assert!(matches!(r, ResolvedTool::Provisioned { version, .. } if version == "8"));
    }

    /// Provisions `tools` from `src` into an explicit root — the shared
    /// arrange step for tests that must not touch the live env. Requires
    /// the caller to hold ENV_LOCK (provision reads SHUTTLE_TOOLS_DIR).
    fn provision_rooted_fixture(root: &Path, version: u64, tools: &[ToolName], src: &Path) {
        let _guard = ToolsDirGuard::at(root);
        provision_with(
            &manifest_for(version, tools),
            ProvisionSource::FromDir(src.to_path_buf()),
        )
        .unwrap_or_else(|e| panic!("fixture provision failed: {e}"));
    }

    #[test]
    fn installed_report_carries_origin_and_versions() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _guard = ToolsDirGuard::at(root.path());
        let src = tempfile::tempdir().unwrap();
        write_fake_tool(src.path(), ToolName::Mksquashfs);
        provision_rooted_fixture(root.path(), 9, &[ToolName::Mksquashfs], src.path());

        // curl comes from a SHUTTLE_TOOL_* override — module-local env, no
        // global PATH mutation.
        let pathdir = tempfile::tempdir().unwrap();
        let fake_curl = write_fake_tool(pathdir.path(), ToolName::Curl);
        std::env::set_var(ToolName::Curl.env_var(), &fake_curl);
        let report = installed_report();
        std::env::remove_var(ToolName::Curl.env_var());

        // The real PATH may resolve additional tools on the dev host;
        // assert the two controlled origins, not the total count.
        assert!(report.iter().any(|(name, r)| match r {
            ResolvedTool::Provisioned { version, .. } => {
                *name == ToolName::Mksquashfs && version == "9"
            }
            _ => false,
        }));
        assert!(report.iter().any(|(name, r)| match r {
            ResolvedTool::Path { version, .. } => {
                *name == ToolName::Curl && version.as_deref() == Some("9.9.9-fake")
            }
            _ => false,
        }));
    }

    #[test]
    fn fetch_errors_on_an_unreachable_host() {
        // Hermetic smoke of the fetch path: port 1 on loopback is refused
        // immediately — no network egress, short timeout.
        let agent = fetch_agent(Duration::from_secs(1), Duration::from_secs(2));
        let err = match http_get(&agent, "http://127.0.0.1:1/shuttle-tools-fake.bin") {
            Err(e) => e,
            Ok(_) => panic!("fetch from a refused port must fail"),
        };
        assert!(matches!(*err, ureq::Error::Transport(_)), "{err}");
    }

    #[test]
    fn version_discovery_parses_known_probe_shapes() {
        assert_eq!(
            parse_version_token("curl 8.5.0 (x86_64-pc-linux-gnu) libcurl/8.5.0"),
            Some("8.5.0".into())
        );
        assert_eq!(
            parse_version_token("tar (GNU tar) 1.35"),
            Some("1.35".into())
        );
        assert_eq!(
            parse_version_token("mksquashfs version 4.6.1 (2023-08-31)"),
            Some("4.6.1".into())
        );
        assert_eq!(
            parse_version_token("bubblewrap 0.8.0"),
            Some("0.8.0".into())
        );
        assert_eq!(parse_version_token("no version tokens here"), None);
        assert_eq!(parse_version_token(""), None);

        // A shell script answering the probe end-to-end.
        let dir = tempfile::tempdir().unwrap();
        let fake = write_fake_tool(dir.path(), ToolName::Tar);
        assert_eq!(discover_version(&fake), Some("9.9.9-fake".into()));
        // Non-zero exit or digit-less output → None, not an error.
        let silent = dir.path().join("silent");
        fs::write(&silent, "#!/bin/sh\necho ok\n").unwrap();
        fs::set_permissions(&silent, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(discover_version(&silent), None);
    }
}
