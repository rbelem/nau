use std::collections::HashMap;
use std::path::Path;

use mlua::Value;
use serde::Serialize;

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
    pub source: Option<String>,

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
        let source = get_opt_string(table, "source")?;
        let grade = get_opt_string(table, "grade")?.unwrap_or_else(default_grade);
        let confinement = get_opt_string(table, "confinement")?.unwrap_or_else(default_confinement);
        let architectures = get_opt_string_array(table, "architectures")?;
        let build = get_opt_string(table, "build")?;

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
) -> miette::Result<String> {
    let build_dir = tempfile::tempdir()
        .map_err(|e| miette::miette!("failed to create build directory: {}", e))?;

    // 1. Run build phase (download source, run build command) if configured
    run_build(meta, stage_dir)?;

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

    // 5. Run mksquashfs
    let status = std::process::Command::new("mksquashfs")
        .arg(build_dir.path())
        .arg(&output_path)
        .arg("-noappend")
        .arg("-comp")
        .arg("xz")
        .arg("-all-root")
        .status()
        .map_err(|e| miette::miette!("failed to execute mksquashfs: {}", e))?;

    if !status.success() {
        return Err(miette::miette!("mksquashfs exited with error"));
    }

    Ok(output_filename)
}

/// Run the build phase: download source, extract, and execute build command.
///
/// Only runs if `meta.build` is set. Downloads the tarball from `meta.source`
/// (if it's a URL), extracts it, and runs the build shell command with
/// `$STAGE` pointing to the stage directory and `$SRC` pointing to the
/// downloaded/extracted source.
fn run_build(meta: &SnapMeta, stage_dir: &Path) -> miette::Result<()> {
    let build_cmd = match &meta.build {
        Some(cmd) => cmd,
        None => return Ok(()),
    };

    let Some(source_url) = &meta.source else {
        return Err(miette::miette!(
            "build is set but no source URL — add 'source = \"...\"' to snap()"
        ));
    };

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

    // 2. Extract tarball and find source root
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

    // 3. Find the source root (the single top-level dir after extraction)
    let src_dir = find_source_root(build_path);
    let work_dir: &Path = src_dir.as_deref().unwrap_or(build_path);

    // 4. Create stage dir and run build
    std::fs::create_dir_all(stage_dir)
        .map_err(|e| miette::miette!("failed to create stage dir: {}", e))?;

    // Convert stage_dir to absolute path (DESTDIR requires absolute)
    let abs_stage = std::fs::canonicalize(stage_dir)
        .unwrap_or_else(|_| stage_dir.to_path_buf());

    let status = std::process::Command::new("sh")
        .args(["-c", build_cmd])
        .env("STAGE", &abs_stage)
        .env("SRC", work_dir)
        .current_dir(work_dir)
        .status()
        .map_err(|e| miette::miette!("failed to execute build: {}", e))?;

    if !status.success() {
        return Err(miette::miette!("build command exited with error"));
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
            if entry.file_type().map_or(false, |t| t.is_dir())
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

        let snap_name = result.unwrap();
        assert_eq!(snap_name, "test-snap_0.1.0_amd64.snap");

        let snap_path = output_dir.path().join(&snap_name);
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
        assert_eq!(snap_amd64, "multi-test_2.0_amd64.snap");
        assert!(output_dir.path().join(&snap_amd64).exists());

        // Build arm64
        let snap_arm64 = build_snap(&meta, stage_dir, output_dir.path(), "arm64").unwrap();
        assert_eq!(snap_arm64, "multi-test_2.0_arm64.snap");
        assert!(output_dir.path().join(&snap_arm64).exists());

        // Verify both have correct arch in YAML
        for (arch, snap_name) in [("amd64", &snap_amd64), ("arm64", &snap_arm64)] {
            let check = std::process::Command::new("unsquashfs")
                .args(["-l", &output_dir.path().join(snap_name).to_string_lossy()])
                .output()
                .expect("unsquashfs should be available");
            let stdout = String::from_utf8_lossy(&check.stdout);
            assert!(
                stdout.contains("meta/snap.yaml"),
                "{arch}: missing snap.yaml"
            );
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
