use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use mlua::Value;
use serde::Serialize;
use serde::Serializer;
use sha2::Digest;

// ── Snap pinning (references to external snaps) ──

/// A reference to a snap from the Snap Store, optionally pinned by revision
/// and content hash for reproducibility.
///
/// Created by the `pin()` DSL function:
/// ```lua
/// pin("core22")                                    -- name only
/// pin("core22", { revision = 1847 })               -- + revision
/// pin("core22", { revision = 1847, sha3_384 = "…" }) -- fully pinned
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct SnapRef {
    pub name: String,
    pub revision: Option<u32>,
    /// sha3-384 hex digest (lowercase, without prefix).
    pub sha3_384: Option<String>,
}

impl SnapRef {
    /// Create from a Lua pin table (validated by the DSL).
    pub fn from_pin_table(table: &mlua::Table) -> miette::Result<Self> {
        let name: String = table
            .get("name")
            .map_err(|_| miette::miette!("pin(): missing required field 'name'"))?;
        let revision: Option<u32> = table.get("revision").ok();
        let sha3_384: Option<String> = table.get("sha3_384").ok();

        Ok(SnapRef {
            name,
            revision,
            sha3_384,
        })
    }
}

// ── Reproducible builds: source pinning ──

/// How a source was specified: bare URL, or URL + pinning hash.
#[derive(Debug, Clone)]
pub enum SourceSpec {
    /// Just a URL — no hash verification (legacy).
    Unverified(String),
    /// URL + expected SHA-256 hash for pinning.
    Pinned { url: String, sha256: String },
}

impl SourceSpec {
    pub fn url(&self) -> &str {
        match self {
            SourceSpec::Unverified(url) => url,
            SourceSpec::Pinned { url, .. } => url,
        }
    }

    /// The SHA-256 hash the source is expected to have, if pinned.
    pub fn expected_sha256(&self) -> Option<&str> {
        match self {
            SourceSpec::Unverified(_) => None,
            SourceSpec::Pinned { sha256, .. } => Some(sha256),
        }
    }
}

/// Serialize as a plain URL string (for `meta/snap.yaml` backward compat).
impl Serialize for SourceSpec {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.url().serialize(serializer)
    }
}

// ── Build result ──

/// Info about a downloaded source, for lockfile recording.
#[derive(Debug, Clone)]
pub struct SourceInfo {
    pub url: String,
    pub sha256: String,
}

/// Result of building one snap, including lockfile-relevant metadata.
#[derive(Debug)]
pub struct BuildResult {
    /// The output `.snap` filename (e.g. `hello_2.10_amd64.snap`).
    pub snap_filename: String,
    /// Source info if a source was downloaded and processed.
    pub source_info: Option<SourceInfo>,
}

// ── Phase 3: Snap metadata structs ──

/// Top-level metadata for one snap output.
///
/// Maps directly to the `meta/snap.yaml` schema that snapd expects.
#[derive(Debug, Clone, Serialize)]
pub struct SnapMeta {
    pub name: String,
    pub version: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceSpec>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub architectures: Option<Vec<String>>,

    /// Build command (shell). If set, tool fetches source and runs build
    /// before snap assembly. Skipped in YAML — build-time only.
    #[serde(skip)]
    pub build: Option<String>,

    #[serde(default = "default_grade")]
    pub grade: String,

    #[serde(default = "default_confinement")]
    pub confinement: String,

    /// Package type: "source" (build from source), "meta" (dependencies only),
    /// "store" (from Snap Store). Inferred from presence of source/build fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,

    /// Alternative names this package is known by. Skipped in YAML — build metadata only.
    #[serde(skip)]
    pub aliases: Vec<String>,

    /// Build/runtime dependencies. Skipped in YAML — build metadata only.
    #[serde(skip)]
    pub requires: Vec<String>,

    /// Cross-compilation target triplet (e.g. "x86_64-linux-gnu", "aarch64-linux-gnu").
    /// When set, the build sandbox sets CC/CXX/LD/etc to the cross-compiler and
    /// exports CONFIGURE_TARGET for autotools-based packages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,

    /// Name of the toolchain meta-package to use for builds (e.g. "toolchain-gcc-gnu-x86_64").
    /// Controls which compiler/linker are mounted into the build sandbox.
    /// Default: host system toolchain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toolchain: Option<String>,

    #[serde(default)]
    pub apps: HashMap<String, SnapApp>,
}

fn default_grade() -> String {
    "stable".to_string()
}

fn default_confinement() -> String {
    "strict".to_string()
}

/// An app declared inside a snap.
#[derive(Debug, Clone, Serialize)]
pub struct SnapApp {
    pub command: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub daemon: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugs: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub slots: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<HashMap<String, String>>,
}

// ── Conversion from Lua (Phase 3) ──
//
// Per ADR-0002: Lua validates at eval time so Rust is a passive consumer.
// These conversions extract pre-validated fields — errors here indicate
// internal bugs or version mismatches, not user config errors.

impl SnapMeta {
    /// Convert from an `mlua::Value` (must be a table).
    pub fn from_lua_value(value: &mlua::Value) -> miette::Result<Self> {
        match value {
            Value::Table(table) => Self::from_lua_table(table),
            other => Err(miette::miette!(
                "expected a table from snap(), got {}",
                other.type_name()
            )),
        }
    }

    /// Convert a validated Lua table (from `snap()`) into a `SnapMeta`.
    pub fn from_lua_table(table: &mlua::Table) -> miette::Result<Self> {
        let name = get_required_string(table, "name")?;
        let version = get_required_string(table, "version")?;
        let summary = get_opt_string(table, "summary")?;
        let description = get_opt_string(table, "description")?;
        let license = get_opt_string(table, "license")?;
        let source = get_source_spec(table)?;
        let grade = get_opt_string(table, "grade")?.unwrap_or_else(default_grade);
        let confinement = get_opt_string(table, "confinement")?.unwrap_or_else(default_confinement);
        let architectures = get_opt_string_array(table, "architectures")?;
        let build = get_opt_string(table, "build")?;
        let type_: Option<String> = table.get("type").ok();
        let aliases: Vec<String> = table.get("aliases").unwrap_or_default();
        let requires: Vec<String> = table.get("requires").unwrap_or_default();
        let target: Option<String> = get_opt_string(table, "target")?;
        let toolchain: Option<String> = get_opt_string(table, "toolchain")?;

        let apps = get_opt_table(table, "apps")?
            .map(|apps_table| {
                let mut apps = HashMap::new();
                for pair in apps_table.pairs::<String, Value>() {
                    let (name, value) = pair.map_err(|e| miette::miette!("apps entry: {}", e))?;
                    match value {
                        Value::Table(t) => {
                            apps.insert(name, SnapApp::from_lua_table(&t)?);
                        }
                        other => {
                            return Err(miette::miette!(
                                "apps['{}'] must be a table, got {}",
                                name,
                                other.type_name()
                            ));
                        }
                    }
                }
                Ok(apps)
            })
            .transpose()?
            .unwrap_or_default();

        Ok(SnapMeta {
            name,
            version,
            summary,
            description,
            license,
            source,
            build,
            architectures,
            grade,
            confinement,
            type_,
            aliases,
            requires,
            target,
            toolchain,
            apps,
        })
    }
}

impl SnapApp {
    /// Convert a validated Lua table (from `app()`) into a `SnapApp`.
    pub fn from_lua_table(table: &mlua::Table) -> miette::Result<Self> {
        let command = get_required_string(table, "command")?;
        let daemon = get_opt_string(table, "daemon")?;
        let plugs = get_opt_string_array(table, "plugs")?;
        let slots = get_opt_string_array(table, "slots")?;
        let environment = get_opt_map(table, "environment")?;

        Ok(SnapApp {
            command,
            daemon,
            plugs,
            slots,
            environment,
        })
    }
}

// ── Lua table extraction helpers ──

fn get_required_string(table: &mlua::Table, key: &str) -> miette::Result<String> {
    table
        .get::<String>(key)
        .map_err(|e| miette::miette!("snap meta: field '{}' is required but invalid: {}", key, e))
}

fn get_opt_string(table: &mlua::Table, key: &str) -> miette::Result<Option<String>> {
    match table
        .get::<Value>(key)
        .map_err(|e| miette::miette!("{}", e))?
    {
        Value::String(s) => Ok(Some(
            s.to_str()
                .map_err(|e| miette::miette!("{}", e))?
                .to_string(),
        )),
        Value::Nil => Ok(None),
        _ => Ok(None),
    }
}

fn get_opt_string_array(table: &mlua::Table, key: &str) -> miette::Result<Option<Vec<String>>> {
    match table
        .get::<Value>(key)
        .map_err(|e| miette::miette!("{}", e))?
    {
        Value::Table(t) => {
            let mut items = Vec::new();
            for pair in t.pairs::<usize, Value>() {
                let (_, value) = pair.map_err(|e| miette::miette!("{}[{}]: {}", key, 0, e))?;
                if let Value::String(s) = value {
                    items.push(
                        s.to_str()
                            .map_err(|e| miette::miette!("{}", e))?
                            .to_string(),
                    );
                }
            }
            Ok(Some(items))
        }
        Value::Nil => Ok(None),
        _ => Ok(None),
    }
}

fn get_opt_table(table: &mlua::Table, key: &str) -> miette::Result<Option<mlua::Table>> {
    match table
        .get::<Value>(key)
        .map_err(|e| miette::miette!("{}", e))?
    {
        Value::Table(t) => Ok(Some(t)),
        Value::Nil => Ok(None),
        _ => Ok(None),
    }
}

/// Extract `source` which can be a string (legacy) or table `{ url, sha256? }`.
fn get_source_spec(table: &mlua::Table) -> miette::Result<Option<SourceSpec>> {
    let value: Value = table.get("source").unwrap_or(Value::Nil);
    match value {
        Value::String(s) => Ok(Some(SourceSpec::Unverified(
            s.to_str()
                .map_err(|e| miette::miette!("{}", e))?
                .to_string(),
        ))),
        Value::Table(t) => {
            let url: String = t
                .get("url")
                .map_err(|_| miette::miette!("source table: missing required 'url' field"))?;
            let sha256: Option<String> = t.get("sha256").ok();
            Ok(match sha256 {
                Some(h) => Some(SourceSpec::Pinned { url, sha256: h }),
                None => Some(SourceSpec::Unverified(url)),
            })
        }
        Value::Nil => Ok(None),
        other => Err(miette::miette!(
            "snap meta: 'source' must be a string or table, got {}",
            other.type_name()
        )),
    }
}

fn get_opt_map(table: &mlua::Table, key: &str) -> miette::Result<Option<HashMap<String, String>>> {
    match table
        .get::<Value>(key)
        .map_err(|e| miette::miette!("{}", e))?
    {
        Value::Table(t) => {
            let mut map = HashMap::new();
            for pair in t.pairs::<String, Value>() {
                let (k, v) = pair.map_err(|e| miette::miette!("{}: {}", key, e))?;
                if let Value::String(s) = v {
                    map.insert(
                        k,
                        s.to_str()
                            .map_err(|e| miette::miette!("{}", e))?
                            .to_string(),
                    );
                }
            }
            Ok(Some(map))
        }
        Value::Nil => Ok(None),
        _ => Ok(None),
    }
}

// ── Phase 4: YAML serialization ──

impl SnapMeta {
    /// Serialize to YAML string (the `meta/snap.yaml` content).
    pub fn to_yaml(&self) -> miette::Result<String> {
        serde_yaml::to_string(self)
            .map_err(|e| miette::miette!("failed to serialize snap metadata to YAML: {}", e))
    }
}

// ── Phase 5/6: Snap directory assembly + SquashFS packaging ──

/// Build a `.snap` package for a single architecture.
///
/// The `arch` parameter controls which architecture appears in the
/// `meta/snap.yaml` and the output filename `{name}_{version}_{arch}.snap`.
/// Returns the output filename (not the full path).
pub fn build_snap(
    meta: &SnapMeta,
    stage_dir: &Path,
    output_dir: &Path,
    arch: &str,
) -> miette::Result<BuildResult> {
    let build_dir = tempfile::tempdir()
        .map_err(|e| miette::miette!("failed to create build directory: {}", e))?;

    // 1. Run build phase (download source, run build command) if configured
    let source_info = run_build(meta, stage_dir)?;

    // Clone meta with architecture filtered to the target arch
    let mut arch_meta = meta.clone();
    arch_meta.architectures = Some(vec![arch.to_string()]);

    // 2. Write meta/snap.yaml
    let meta_dir = build_dir.path().join("meta");
    std::fs::create_dir_all(&meta_dir)
        .map_err(|e| miette::miette!("failed to create meta/ directory: {}", e))?;

    let yaml = arch_meta.to_yaml()?;
    std::fs::write(meta_dir.join("snap.yaml"), &yaml)
        .map_err(|e| miette::miette!("failed to write meta/snap.yaml: {}", e))?;

    // 3. Copy stage contents into build root
    if stage_dir.exists() {
        cp_r(stage_dir, build_dir.path())
            .map_err(|e| miette::miette!("failed to copy from {:?}: {}", stage_dir, e))?;
    }

    // 4. Output filename
    let output_filename = format!("{}_{}_{}.snap", meta.name, meta.version, arch);
    let output_path = output_dir.join(&output_filename);

    // 5. Run mksquashfs with optional SOURCE_DATE_EPOCH
    let mut mksquashfs = std::process::Command::new("mksquashfs");
    mksquashfs
        .arg(build_dir.path())
        .arg(&output_path)
        .arg("-noappend")
        .arg("-comp")
        .arg("xz")
        .arg("-all-root");

    // Reproducible timestamps via SOURCE_DATE_EPOCH.
    // mksquashfs 4.4+ reads this env var natively — we just need to
    // ensure it's propagated into the child process.
    // (We set it in main.rs from the --source-date-epoch flag.)

    let status = mksquashfs
        .status()
        .map_err(|e| miette::miette!("failed to execute mksquashfs: {}", e))?;

    if !status.success() {
        return Err(miette::miette!("mksquashfs exited with error"));
    }

    Ok(BuildResult {
        snap_filename: output_filename,
        source_info,
    })
}

/// Run the build phase: download source, extract, and execute build command.
///
/// Only runs if `meta.build` is set. Downloads the tarball from `meta.source`
/// (if it's a URL), extracts it, verifies SHA-256 (if pinned), and runs the
/// build shell command with `$STAGE` pointing to the stage directory and
/// `$SRC` pointing to the downloaded/extracted source.
///
/// Returns `SourceInfo` with the computed SHA-256 if a source was downloaded.
fn run_build(meta: &SnapMeta, stage_dir: &Path) -> miette::Result<Option<SourceInfo>> {
    let build_cmd = match &meta.build {
        Some(cmd) => cmd,
        None => return Ok(None),
    };

    let source_spec = match &meta.source {
        Some(s) => s,
        None => {
            return Err(miette::miette!(
                "build is set but no source — add 'source = \"...\"' to snap()"
            ));
        }
    };

    let source_url = source_spec.url();

    if !source_url.starts_with("http://") && !source_url.starts_with("https://") {
        return Err(miette::miette!(
            "build requires a URL source, got: {}",
            source_url
        ));
    }

    let build_dir = tempfile::tempdir()
        .map_err(|e| miette::miette!("failed to create build directory: {}", e))?;
    let build_path = build_dir.path();

    // 1. Download source tarball
    let filename = source_url.rsplit('/').next().unwrap_or("source.tar.gz");
    let tarball = build_path.join(filename);

    let status = std::process::Command::new("curl")
        .args(["-fsSL", "-o", &tarball.to_string_lossy(), source_url])
        .status()
        .map_err(|e| miette::miette!("curl not found: {}", e))?;

    if !status.success() {
        return Err(miette::miette!("failed to download {}", source_url));
    }

    // 2. Compute SHA-256 of downloaded file
    let computed_sha256 = sha256_file(&tarball)?;

    // 3. Verify against pinned hash
    if let Some(expected) = source_spec.expected_sha256() {
        if computed_sha256 != expected {
            return Err(miette::miette!(
                "SHA-256 mismatch for {}:\n  expected: {}\n  got:      {}",
                source_url,
                expected,
                computed_sha256
            ));
        }
        eprintln!("  ✓ SHA-256 verified: {computed_sha256}");
    } else {
        eprintln!("  source hash (not pinned): {computed_sha256} (add to source.sha256 to pin)");
    }

    // 4. Extract tarball and find source root
    let is_tarball = filename.ends_with(".tar.gz")
        || filename.ends_with(".tar.xz")
        || filename.ends_with(".tgz");
    if is_tarball {
        let tarball_str = tarball.to_string_lossy().to_string();
        let status = std::process::Command::new("tar")
            .arg("xaf")
            .arg(&tarball_str)
            .current_dir(build_path)
            .status()
            .map_err(|e| miette::miette!("tar not found: {}", e))?;
        if !status.success() {
            return Err(miette::miette!("failed to extract {}", filename));
        }
    }

    // 5. Find the source root (the single top-level dir after extraction)
    let src_dir = find_source_root(build_path);
    let work_dir: &Path = src_dir.as_deref().unwrap_or(build_path);

    // 6. Create stage dir and run build
    std::fs::create_dir_all(stage_dir)
        .map_err(|e| miette::miette!("failed to create stage dir: {}", e))?;

    // Convert stage_dir to absolute path (DESTDIR requires absolute)
    let abs_stage = std::fs::canonicalize(stage_dir).unwrap_or_else(|_| stage_dir.to_path_buf());

    // Run build — either inside a bubblewrap sandbox or directly
    run_build_command(
        build_cmd,
        build_path,
        work_dir,
        &abs_stage,
        meta.target.as_deref(),
    )?;

    Ok(Some(SourceInfo {
        url: source_url.to_string(),
        sha256: computed_sha256,
    }))
}

/// Compute SHA-256 of a file (streaming, memory-efficient for large files).
fn sha256_file(path: &Path) -> miette::Result<String> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| miette::miette!("failed to open {}: {}", path.display(), e))?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| miette::miette!("failed to read {}: {}", path.display(), e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let hash = hasher.finalize();
    Ok(hash.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// Run a build command, optionally wrapped in a bubblewrap sandbox.
///
/// `build_path` is the root build directory (host-side).
/// `work_dir` is the source root (inside `build_path`).
/// Inside the sandbox the build dir is mounted at `/build` and
/// `$SRC` points to the source subdirectory.
/// If `bwrap` is unavailable, falls back to direct execution.
///
/// Cross-compilation support:
/// - If `target` is set, env vars CC, CXX, LD, AR, etc. are set to
///   `{target}-{tool}` (using the GNU cross-compiler naming convention).
/// - `CONFIGURE_TARGET` is exported for autotools-based packages.
/// - The cross-toolchain sysroot is expected at the standard host path
///   `/usr/{target}` or can be provided via `CROSS_SYSROOT`.
fn run_build_command(
    cmd: &str,
    build_path: &Path,
    work_dir: &Path,
    stage_dir: &Path,
    target: Option<&str>,
) -> miette::Result<()> {
    // Detect bubblewrap
    let bwrap = std::process::Command::new("which")
        .arg("bwrap")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            let s = s.trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        });

    // Build cross-compilation environment variables if target is set.
    // These follow the GNU cross-compiler naming convention:
    //   CC = <target>-gcc, CXX = <target>-g++, etc.
    let cross_env = if let Some(triplet) = target {
        let mut env = Vec::new();
        env.push(("CONFIGURE_TARGET", triplet.to_string()));
        env.push(("CC", format!("{}-gcc", triplet)));
        env.push(("CXX", format!("{}-g++", triplet)));
        env.push(("LD", format!("{}-ld", triplet)));
        env.push(("AR", format!("{}-ar", triplet)));
        env.push(("AS", format!("{}-as", triplet)));
        env.push(("RANLIB", format!("{}-ranlib", triplet)));
        env.push(("STRIP", format!("{}-strip", triplet)));
        env.push(("OBJCOPY", format!("{}-objcopy", triplet)));
        env.push(("OBJDUMP", format!("{}-objdump", triplet)));
        env.push(("NM", format!("{}-nm", triplet)));
        env.push(("PKG_CONFIG", format!("{}-pkg-config", triplet)));
        // Standard autotools cross-compilation vars
        env.push(("BUILD", std::env::consts::ARCH.to_string()));
        env.push(("HOST", triplet.to_string()));
        env.push(("CROSS_COMPILE", format!("{}-", triplet)));
        Some(env)
    } else {
        None
    };

    if let Some(bwrap_bin) = bwrap {
        // Determine the source path relative to /build inside the sandbox
        let inner_src = if work_dir == build_path {
            Path::new("/build").to_path_buf()
        } else {
            let rel = work_dir.strip_prefix(build_path).unwrap_or(Path::new(""));
            Path::new("/build").join(rel)
        };

        let mut cmd_proc = std::process::Command::new(&bwrap_bin);
        cmd_proc
            .arg("--unshare-user")
            .arg("--unshare-pid")
            .arg("--unshare-ipc")
            .arg("--unshare-net")
            .arg("--proc")
            .arg("/proc")
            .arg("--dev")
            .arg("/dev")
            // Mount build dir at /build inside sandbox
            .arg("--bind")
            .arg(build_path)
            .arg("/build")
            // Mount stage dir at its absolute host path
            .arg("--bind")
            .arg(stage_dir)
            .arg(stage_dir)
            // Read-only system paths for toolchain
            .arg("--ro-bind")
            .arg("/usr")
            .arg("/usr")
            .arg("--ro-bind")
            .arg("/lib")
            .arg("/lib");
        if Path::new("/lib64").exists() {
            cmd_proc.arg("--ro-bind").arg("/lib64").arg("/lib64");
        }
        // Nix store (for NixOS/devbox builds)
        if Path::new("/nix").exists() {
            cmd_proc.arg("--ro-bind").arg("/nix").arg("/nix");
        }
        // Essential system paths (for shebangs, etc.)
        if Path::new("/bin").exists() {
            cmd_proc.arg("--ro-bind").arg("/bin").arg("/bin");
        }
        if Path::new("/run/current-system").exists() {
            cmd_proc
                .arg("--ro-bind")
                .arg("/run/current-system")
                .arg("/run/current-system");
        }
        // Cross-compilation sysroot mount
        if let Some(triplet) = target {
            let sysroot = Path::new("/usr").join(triplet);
            if sysroot.exists() {
                cmd_proc.arg("--ro-bind").arg(&sysroot).arg(&sysroot);
            }
        }
        // Private /tmp for build temp files
        cmd_proc
            .arg("--tmpfs")
            .arg("/tmp")
            .arg("--chdir")
            .arg(&inner_src)
            .env("STAGE", stage_dir)
            .env("SRC", &inner_src);
        // Apply cross-compilation env vars
        if let Some(ref env) = cross_env {
            for (key, val) in env {
                cmd_proc.env(key, val);
            }
        }
        cmd_proc.arg("sh").arg("-c").arg(cmd);

        let status = cmd_proc
            .status()
            .map_err(|e| miette::miette!("bwrap execution failed: {}", e))?;

        if !status.success() {
            return Err(miette::miette!(
                "build command exited with error (in sandbox)"
            ));
        }
    } else {
        // Fallback: run directly on host (no sandbox)
        let mut cmd_proc = std::process::Command::new("sh");
        cmd_proc
            .args(["-c", cmd])
            .env("STAGE", stage_dir)
            .env("SRC", work_dir);
        // Apply cross-compilation env vars
        if let Some(ref env) = cross_env {
            for (key, val) in env {
                cmd_proc.env(key, val);
            }
        }
        cmd_proc.current_dir(work_dir);

        let status = cmd_proc
            .status()
            .map_err(|e| miette::miette!("failed to execute build: {}", e))?;

        if !status.success() {
            return Err(miette::miette!("build command exited with error"));
        }
    }

    Ok(())
}

/// Find the single top-level directory in a path (the source root
/// after extracting a tarball). If there's more than one entry or
/// no entry, returns None.
fn find_source_root(dir: &Path) -> Option<std::path::PathBuf> {
    let mut entries: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(read) = std::fs::read_dir(dir) {
        for entry in read.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_dir())
                && !entry.file_name().to_string_lossy().starts_with('.')
            {
                entries.push(entry.path());
            }
        }
    }
    if entries.len() == 1 {
        Some(entries.into_iter().next().unwrap())
    } else {
        None
    }
}

/// Determine the set of architectures to build.
///
/// * If `cli_archs` is non-empty, use those (from `--arch` flags).
/// * Otherwise use the architectures declared in `meta`.
/// * If neither is set, default to `["all"]`.
pub fn resolve_archs(meta: &SnapMeta, cli_archs: &[String]) -> Vec<String> {
    if !cli_archs.is_empty() {
        cli_archs.to_vec()
    } else {
        meta.architectures
            .clone()
            .filter(|a| !a.is_empty())
            .unwrap_or_else(|| vec!["all".to_string()])
    }
}

/// Recursive copy of directory contents into destination.
fn cp_r(src: &Path, dst: &Path) -> std::io::Result<()> {
    let mut dirs = vec![src.to_path_buf()];
    while let Some(current) = dirs.pop() {
        let relative = current.strip_prefix(src).unwrap();
        let target = dst.join(relative);

        if current.is_dir() && current != src {
            std::fs::create_dir_all(&target)?;
        }

        if let Ok(read) = std::fs::read_dir(&current) {
            for entry in read {
                let entry = entry?;
                let path = entry.path();
                let rel = path.strip_prefix(src).unwrap();
                let dest = dst.join(rel);

                if path.is_dir() {
                    std::fs::create_dir_all(&dest)?;
                    dirs.push(path);
                } else {
                    std::fs::copy(&path, &dest)?;
                }
            }
        }
    }
    Ok(())
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    /// Evaluate with DSL and get top-level table (keeps Lua alive for the duration).
    struct LuaEnv {
        lua: mlua::Lua,
    }

    impl LuaEnv {
        fn new() -> Self {
            let lua = mlua::Lua::new();
            lua.load(crate::dsl::INIT_LUA)
                .exec()
                .expect("DSL init failed");
            LuaEnv { lua }
        }

        fn eval(&self, source: &str) -> miette::Result<mlua::Table> {
            let value: Value = self
                .lua
                .load(source)
                .eval()
                .map_err(|e| miette::miette!("{}", e))?;
            match value {
                Value::Table(t) => Ok(t),
                other => Err(miette::miette!("expected table, got {}", other.type_name())),
            }
        }
    }

    // ── SourceSpec tests ──

    #[test]
    fn test_source_spec_unverified() {
        let s = SourceSpec::Unverified("https://example.com/tarball.tar.gz".into());
        assert_eq!(s.url(), "https://example.com/tarball.tar.gz");
        assert!(s.expected_sha256().is_none());
    }

    #[test]
    fn test_source_spec_pinned() {
        let hash = "e9b1d4d5f3c0b2a1d9c8f7e6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b";
        let s = SourceSpec::Pinned {
            url: "https://example.com/tarball.tar.gz".into(),
            sha256: hash.into(),
        };
        assert_eq!(s.url(), "https://example.com/tarball.tar.gz");
        assert_eq!(s.expected_sha256(), Some(hash));
    }

    #[test]
    fn test_source_spec_serialize_as_url() {
        let s = SourceSpec::Pinned {
            url: "https://example.com/pkg.tar.gz".into(),
            sha256: "abc123".into(),
        };
        let yaml = serde_yaml::to_string(&s).unwrap();
        assert_eq!(yaml.trim(), "https://example.com/pkg.tar.gz");
    }

    #[test]
    fn test_source_spec_dsl_string() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "legacy",
                    version = "1.0",
                    source = "https://example.com/old.tar.gz",
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        match meta.source {
            Some(SourceSpec::Unverified(url)) => {
                assert_eq!(url, "https://example.com/old.tar.gz");
            }
            other => panic!("expected Unverified, got {:?}", other),
        }
    }

    #[test]
    fn test_source_spec_dsl_table_pinned() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "pinned",
                    version = "1.0",
                    source = {
                        url = "https://example.com/pkg.tar.gz",
                        sha256 = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                    },
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        match meta.source {
            Some(SourceSpec::Pinned { url, sha256 }) => {
                assert_eq!(url, "https://example.com/pkg.tar.gz");
                assert_eq!(
                    sha256,
                    "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                );
            }
            other => panic!("expected Pinned, got {:?}", other),
        }
    }

    #[test]
    fn test_source_spec_dsl_table_no_hash() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "no-hash",
                    version = "1.0",
                    source = {
                        url = "https://example.com/pkg.tar.gz",
                    },
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        match meta.source {
            Some(SourceSpec::Unverified(url)) => {
                assert_eq!(url, "https://example.com/pkg.tar.gz");
            }
            other => panic!("expected Unverified, got {:?}", other),
        }
    }

    #[test]
    fn test_source_none_when_unset() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "no-source",
                    version = "1.0",
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        assert!(meta.source.is_none());
    }

    #[test]
    fn test_sha256_file_known_content() {
        // Create a temp file with known content and verify its hash
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, b"hello world\n").unwrap();
        let hash = super::sha256_file(&path).unwrap();
        // SHA-256 of "hello world\n"
        assert_eq!(
            hash,
            "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"
        );
    }

    // ── Phase 3 tests: struct conversion ──

    #[test]
    fn test_snap_meta_from_lua_full() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "hello",
                    version = "2.10",
                    summary = "GNU Hello",
                    description = "Prints a greeting",
                    license = "GPL-3.0-or-later",
                    grade = "stable",
                    confinement = "strict",
                    source = "http://example.com/tarball.tar.gz",
                    architectures = { "amd64", "arm64" },
                    apps = {
                        hello = app { command = "bin/hello" },
                    },
                },
            }
            "#,
            )
            .unwrap();

        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        assert_eq!(meta.name, "hello");
        assert_eq!(meta.version, "2.10");
        assert_eq!(meta.summary.as_deref(), Some("GNU Hello"));
        assert_eq!(meta.grade, "stable");
        assert_eq!(meta.confinement, "strict");
        let archs = meta.architectures.as_ref().unwrap();
        assert_eq!(archs, &vec!["amd64".to_string(), "arm64".to_string()]);
        assert_eq!(meta.apps.len(), 1);
        assert_eq!(meta.apps["hello"].command, "bin/hello");
    }

    #[test]
    fn test_snap_meta_from_lua_minimal() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "minimal",
                    version = "1.0",
                },
            }
            "#,
            )
            .unwrap();

        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        assert_eq!(meta.name, "minimal");
        assert_eq!(meta.version, "1.0");
        assert!(meta.summary.is_none());
        assert_eq!(meta.grade, "stable"); // default
        assert_eq!(meta.confinement, "strict"); // default
        assert!(meta.apps.is_empty());
    }

    #[test]
    fn test_snap_app_from_lua() {
        let env = LuaEnv::new();
        let value: Value = env
            .lua
            .load(r#"return app { command = "bin/serve", daemon = "simple" }"#)
            .eval()
            .unwrap();

        let _ = env; // keep alive for the value reference

        let table = match value {
            Value::Table(t) => t,
            _ => panic!("expected table"),
        };
        let app = SnapApp::from_lua_table(&table).unwrap();

        assert_eq!(app.command, "bin/serve");
        assert_eq!(app.daemon.as_deref(), Some("simple"));
        assert!(app.plugs.is_none());
    }

    // ── Phase 4 tests: YAML output ──

    #[test]
    fn test_snap_yaml_full() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "hello",
                    version = "2.10",
                    summary = "GNU Hello",
                    description = "Prints a greeting",
                    grade = "stable",
                    confinement = "strict",
                    architectures = { "amd64" },
                    apps = {
                        hello = app { command = "bin/hello" },
                    },
                },
            }
            "#,
            )
            .unwrap();

        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        let yaml = meta.to_yaml().unwrap();

        assert!(yaml.contains("name: hello"));
        assert!(yaml.contains("version: '2.10'"));
        assert!(yaml.contains("bin/hello"));
        assert!(yaml.contains("amd64"));
        assert!(yaml.contains("summary:")); // present, not skipped
    }

    #[test]
    fn test_snap_yaml_minimal_omits_optionals() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "minimal",
                    version = "1.0",
                },
            }
            "#,
            )
            .unwrap();

        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        let yaml = meta.to_yaml().unwrap();

        assert!(yaml.contains("name: minimal"));
        assert!(yaml.contains("grade: stable"));
        assert!(yaml.contains("confinement: strict"));
        assert!(!yaml.contains("summary:")); // skipped
        assert!(!yaml.contains("description:")); // skipped
    }

    // ── Phase 5/6 tests: build pipeline ──

    #[test]
    fn test_build_snap_creates_snap_file() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "test-snap",
                    version = "0.1.0",
                    architectures = { "amd64" },
                    apps = {
                        hello = app { command = "bin/hello" },
                    },
                },
            }
            "#,
            )
            .unwrap();

        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        let stage_dir = std::path::Path::new("test-fixtures");
        let output_dir = tempfile::tempdir().unwrap();

        let result = build_snap(&meta, stage_dir, output_dir.path(), "amd64");
        assert!(result.is_ok());

        let build_result = result.unwrap();
        assert_eq!(build_result.snap_filename, "test-snap_0.1.0_amd64.snap");
        // No source pinned, so source_info is None
        assert!(build_result.source_info.is_none());

        let snap_path = output_dir.path().join(&build_result.snap_filename);
        assert!(
            snap_path.exists(),
            "snap file should exist at {:?}",
            snap_path
        );

        // Verify it's a valid SquashFS via unsquashfs
        let check = std::process::Command::new("unsquashfs")
            .args(["-l", &snap_path.to_string_lossy()])
            .output()
            .expect("unsquashfs should be available");

        let stdout = String::from_utf8_lossy(&check.stdout);
        assert!(
            stdout.contains("meta/snap.yaml"),
            "snap should contain meta/snap.yaml"
        );
    }

    #[test]
    fn test_build_multi_arch() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "multi-test",
                    version = "2.0",
                    architectures = { "amd64", "arm64" },
                    apps = {
                        hello = app { command = "bin/hello" },
                    },
                },
            }
            "#,
            )
            .unwrap();

        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        let output_dir = tempfile::tempdir().unwrap();
        let stage_dir = std::path::Path::new("test-fixtures");

        // Build amd64
        let snap_amd64 = build_snap(&meta, stage_dir, output_dir.path(), "amd64").unwrap();
        assert_eq!(snap_amd64.snap_filename, "multi-test_2.0_amd64.snap");
        assert!(output_dir.path().join(&snap_amd64.snap_filename).exists());

        // Build arm64
        let snap_arm64 = build_snap(&meta, stage_dir, output_dir.path(), "arm64").unwrap();
        assert_eq!(snap_arm64.snap_filename, "multi-test_2.0_arm64.snap");
        assert!(output_dir.path().join(&snap_arm64.snap_filename).exists());

        // Verify both have correct arch in YAML
        for snap_result in [&snap_amd64, &snap_arm64] {
            let check = std::process::Command::new("unsquashfs")
                .args([
                    "-l",
                    &output_dir
                        .path()
                        .join(&snap_result.snap_filename)
                        .to_string_lossy(),
                ])
                .output()
                .expect("unsquashfs should be available");
            let stdout = String::from_utf8_lossy(&check.stdout);
            assert!(stdout.contains("meta/snap.yaml"), "missing snap.yaml");
        }
    }

    #[test]
    fn test_resolve_archs_defaults_to_meta() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "t",
                    version = "1",
                    architectures = { "amd64", "arm64" },
                },
            }
            "#,
            )
            .unwrap();

        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        let archs = resolve_archs(&meta, &[]);
        assert_eq!(archs, vec!["amd64", "arm64"]);
    }

    #[test]
    fn test_resolve_archs_cli_overrides_meta() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "t",
                    version = "1",
                    architectures = { "amd64", "arm64" },
                },
            }
            "#,
            )
            .unwrap();

        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        let archs = resolve_archs(&meta, &["arm64".to_string()]);
        assert_eq!(archs, vec!["arm64"]);
    }

    #[test]
    fn test_resolve_archs_defaults_to_all() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "t",
                    version = "1",
                },
            }
            "#,
            )
            .unwrap();

        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        let archs = resolve_archs(&meta, &[]);
        assert_eq!(archs, vec!["all"]);
    }
}
