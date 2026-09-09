//! Built-in builder plugin registry (ADR-0014).
//!
//! Plugins are compiled into shuttle: a part selects one with
//! `plugin = "<name>"` plus an options table, and the plugin expands to a
//! declarative [`BuildPlan`] (commands + env + extra requires/build_deps)
//! consumed by the existing `run_parts` machinery. No dynamic plugin
//! loading in v1.
//!
//! Per ADR-0014 Decision 3, this module is the validation boundary: the Lua
//! DSL only checks that `plugin` names a known plugin and that options are a
//! table; deep option validation happens here and produces named errors
//! (e.g. "cargo: option 'channel' must be a string").
//!
//! Command conventions follow the existing shell-command parts (see
//! `examples/packages/` and `pkgs/`): install with `DESTDIR=$STAGE` from a
//! `--prefix=/usr` configuration, so every plugin part installs into the
//! shared stage exactly like hand-written build commands do.

use std::collections::BTreeMap;
use std::path::Path;

/// Version of the built-in plugin registry. Folded into cache keys for
/// plugin parts (ADR-0014 Decision 5): a shuttle release that changes plugin
/// expansion invalidates cached artifacts built by older plugins. Bumped to
/// "2" when `make` gained `variables`/`prefix`/`install` and `autotools`
/// gained `prefix`/`in_source` (the `make` install line now carries
/// `PREFIX=/usr` by default — v1-cached `make` artifacts are stale).
pub const REGISTRY_VERSION: &str = "2";

/// The toolchain package `cargo` parts add to the snap's effective
/// `build_deps` (ADR-0018 Decision 5, issue #26): the rust toolchain is a
/// build-time-only dependency — it enters the merged build prefix so the
/// sandboxed `cargo install` finds it, and never the runtime closure or a
/// pod.
///
/// Chosen over the generic `toolchain` alias on purpose: alias names live
/// only as data inside the package's Lua (and in the store index), while
/// dependency resolution (`deps::load_meta` → `pkg_source::resolve_pkg`) is
/// purely path-based (`pkgs/t/<name>.lua`). Only the concrete package name
/// resolves.
const CARGO_BUILD_DEP: &str = "toolchain-gcc-gnu-x86_64";

/// One option value from a definition's plugin options table.
#[derive(Debug, Clone, PartialEq)]
pub enum PluginValue {
    Str(String),
    Bool(bool),
    Arr(Vec<String>),
    Map(BTreeMap<String, String>),
}

impl PluginValue {
    /// Canonical JSON for cache keys: maps serialize with sorted keys
    /// (BTreeMap), arrays keep order, booleans map to JSON booleans.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            PluginValue::Str(s) => serde_json::Value::String(s.clone()),
            PluginValue::Bool(b) => serde_json::Value::Bool(*b),
            PluginValue::Arr(items) => serde_json::Value::Array(
                items
                    .iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            ),
            PluginValue::Map(map) => serde_json::Value::Object(
                map.iter()
                    .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                    .collect(),
            ),
        }
    }
}

/// The declarative build plan a plugin expands to (ADR-0014 Decision 4).
///
/// Commands run through the same runner as `build` commands (same sandbox,
/// cwd, `$STAGE`/`$SRC`/`$PART_NAME` semantics), in order, stopping at the
/// first failure. `env` entries are exported to every command of the part.
#[derive(Debug, Clone, PartialEq)]
pub struct BuildPlan {
    pub commands: Vec<String>,
    pub env: Vec<(String, String)>,
    /// Appended to the snap's effective `requires` so dependency resolution
    /// and the cache see the full runtime closure (ADR-0014 Decision 4).
    pub extra_requires: Vec<String>,
    /// Appended to the snap's effective `build_deps` so the toolchain
    /// reaches the build sandbox's merged prefix but never the runtime
    /// closure (ADR-0018 Decision 5, issue #26).
    pub extra_build_deps: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum OptionKind {
    Str,
    Bool,
    Arr,
    Map,
}

impl OptionKind {
    fn expects(self) -> &'static str {
        match self {
            OptionKind::Str => "a string",
            OptionKind::Bool => "true or false",
            OptionKind::Arr => "an array of strings",
            OptionKind::Map => "a string→string map",
        }
    }

    fn matches(self, value: &PluginValue) -> bool {
        matches!(
            (self, value),
            (OptionKind::Str, PluginValue::Str(_))
                | (OptionKind::Bool, PluginValue::Bool(_))
                | (OptionKind::Arr, PluginValue::Arr(_))
                | (OptionKind::Map, PluginValue::Map(_))
        )
    }
}

struct OptionSpec {
    name: &'static str,
    kind: OptionKind,
    required: bool,
}

struct PluginSpec {
    name: &'static str,
    options: &'static [OptionSpec],
}

/// The built-in registry (ADR-0014 Decision 6): option sets grown by demand.
///
/// v2 growth came from dogfood friction blocking real packages: `make`
/// `variables`/`prefix` unblock pciutils, zstd and lm-sensors; `autotools`
/// `in_source` unblocks dhcpcd (non-autoconf configure); `make` `install`
/// supports lib-only parts that stage via their own explicit install part
/// (the bzip2 shared-lib pattern).
const PLUGINS: &[PluginSpec] = &[
    PluginSpec {
        name: "make",
        options: &[
            OptionSpec {
                name: "target",
                kind: OptionKind::Str,
                required: false,
            },
            OptionSpec {
                name: "makefile",
                kind: OptionKind::Str,
                required: false,
            },
            OptionSpec {
                name: "variables",
                kind: OptionKind::Map,
                required: false,
            },
            OptionSpec {
                name: "prefix",
                kind: OptionKind::Str,
                required: false,
            },
            OptionSpec {
                name: "install",
                kind: OptionKind::Bool,
                required: false,
            },
        ],
    },
    PluginSpec {
        name: "cargo",
        options: &[OptionSpec {
            name: "channel",
            kind: OptionKind::Str,
            required: false,
        }],
    },
    PluginSpec {
        name: "cmake",
        options: &[
            OptionSpec {
                name: "generator",
                kind: OptionKind::Str,
                required: false,
            },
            OptionSpec {
                name: "defines",
                kind: OptionKind::Map,
                required: false,
            },
        ],
    },
    PluginSpec {
        name: "autotools",
        options: &[
            OptionSpec {
                name: "args",
                kind: OptionKind::Arr,
                required: false,
            },
            OptionSpec {
                name: "prefix",
                kind: OptionKind::Str,
                required: false,
            },
            OptionSpec {
                name: "in_source",
                kind: OptionKind::Bool,
                required: false,
            },
        ],
    },
];

/// Names of every built-in plugin (sorted alphabetically).
pub fn plugin_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = PLUGINS.iter().map(|p| p.name).collect();
    names.sort_unstable();
    names
}

/// Whether `name` selects a built-in plugin.
pub fn is_known_plugin(name: &str) -> bool {
    PLUGINS.iter().any(|p| p.name == name)
}

/// Validate one plugin part's options and expand it to its [`BuildPlan`].
///
/// This is the deep-validation boundary (ADR-0014 Decision 3): every error
/// names the plugin and the option.
pub fn expand(
    plugin: &str,
    options: Option<&BTreeMap<String, PluginValue>>,
) -> miette::Result<BuildPlan> {
    let spec = PLUGINS.iter().find(|p| p.name == plugin).ok_or_else(|| {
        miette::miette!(
            "unknown plugin '{}' (available: {})",
            plugin,
            plugin_names().join(", ")
        )
    })?;
    let opts = validate(spec, options)?;
    match spec.name {
        "make" => Ok(make_plan(&opts)),
        "cargo" => cargo_plan(&opts),
        "cmake" => Ok(cmake_plan(&opts)),
        "autotools" => Ok(autotools_plan(&opts)),
        other => Err(miette::miette!(
            "internal: plugin '{other}' has no expansion"
        )),
    }
}

/// Check every provided option against the plugin's schema and collect the
/// matches; then verify all required options were provided.
fn validate<'a>(
    spec: &PluginSpec,
    options: Option<&'a BTreeMap<String, PluginValue>>,
) -> miette::Result<Vec<(&'static str, &'a PluginValue)>> {
    let mut found = Vec::new();
    if let Some(options) = options {
        for (key, value) in options {
            let Some(ospec) = spec.options.iter().find(|o| o.name == key.as_str()) else {
                let available = spec
                    .options
                    .iter()
                    .map(|o| o.name)
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(miette::miette!(
                    "{}: unknown option '{}' (available: {})",
                    spec.name,
                    key,
                    available
                ));
            };
            if !ospec.kind.matches(value) {
                return Err(miette::miette!(
                    "{}: option '{}' must be {}",
                    spec.name,
                    key,
                    ospec.kind.expects()
                ));
            }
            found.push((ospec.name, value));
        }
    }
    for ospec in spec.options.iter().filter(|o| o.required) {
        if !found.iter().any(|(name, _)| *name == ospec.name) {
            return Err(miette::miette!(
                "{}: missing required option '{}'",
                spec.name,
                ospec.name
            ));
        }
    }
    Ok(found)
}

fn opt_str<'a>(opts: &'a [(&'static str, &'a PluginValue)], key: &str) -> Option<&'a str> {
    opts.iter()
        .find(|(name, _)| *name == key)
        .and_then(|(_, v)| match v {
            PluginValue::Str(s) => Some(s.as_str()),
            _ => None,
        })
}

fn opt_arr<'a>(opts: &'a [(&'static str, &'a PluginValue)], key: &str) -> &'a [String] {
    opts.iter()
        .find(|(name, _)| *name == key)
        .and_then(|(_, v)| match v {
            PluginValue::Arr(items) => Some(items.as_slice()),
            _ => None,
        })
        .unwrap_or(&[])
}

fn opt_map<'a>(
    opts: &'a [(&'static str, &'a PluginValue)],
    key: &str,
) -> Option<&'a BTreeMap<String, String>> {
    opts.iter()
        .find(|(name, _)| *name == key)
        .and_then(|(_, v)| match v {
            PluginValue::Map(map) => Some(map),
            _ => None,
        })
}

fn opt_bool(opts: &[(&'static str, &PluginValue)], key: &str) -> Option<bool> {
    opts.iter()
        .find(|(name, _)| *name == key)
        .and_then(|(_, v)| match v {
            PluginValue::Bool(b) => Some(*b),
            _ => None,
        })
}

/// `make` part: build + install into `$STAGE`. The Makefile lives in `$SRC`
/// (part work dirs are siblings of the shared source dir), so commands run
/// there via `make -C`.
///
/// Options (ADR-0014 §6 growth — dogfood friction from pciutils, zstd,
/// lm-sensors and lib-only parts):
///
/// - `variables`: string→string map emitted as `VAR=VALUE` arguments on both
///   commands, canonicalized to sorted order. This is how non-autoconf
///   Makefiles get their prefix (pciutils' `PREFIX=/usr`) and build flags.
/// - `prefix`: install prefix, default `"usr"` (emitted as `PREFIX=/usr` —
///   the corpus convention, `make install PREFIX=/usr DESTDIR=$STAGE`).
///   Leading slashes in the value are normalized (`"/opt"` and `"opt"` both
///   give `PREFIX=/opt`). Emitted on the install command only; build-time
///   prefix spellings (zstd/lm-sensors' lowercase `prefix=/usr`) belong in
///   `variables`. A `variables` entry named `PREFIX` replaces the
///   prefix-derived one.
/// - `install`: default `true`. When `false` the plan ends after the build
///   command — for lib-only or custom-Makefile parts that stage files via
///   their own explicit install part (the bzip2 shared-lib pattern). With
///   no raw command channel on plugin parts, staging then is entirely the
///   part author's responsibility; choosing `install = false` without
///   arranging staging yields a part that installs nothing, by design.
fn make_plan(opts: &[(&'static str, &PluginValue)]) -> BuildPlan {
    let file_arg = match opt_str(opts, "makefile") {
        Some(f) => format!(" -f {f}"),
        None => String::new(),
    };
    let target_arg = match opt_str(opts, "target") {
        Some(t) => format!(" {t}"),
        None => String::new(),
    };
    let install = opt_bool(opts, "install").unwrap_or(true);
    let prefix = opt_str(opts, "prefix")
        .unwrap_or("usr")
        .trim_start_matches('/');
    let variables = opt_map(opts, "variables");
    // BTreeMap iteration keeps the emitted order canonical regardless of the
    // definition's table order.
    let mut var_args = String::new();
    if let Some(vars) = variables {
        for (key, value) in vars {
            var_args.push_str(&format!(" {key}={value}"));
        }
    }
    // The install command carries the prefix; an explicit `variables` PREFIX
    // entry replaces the derived one instead of doubling it.
    let mut install_args = var_args.clone();
    if !variables.is_some_and(|vars| vars.contains_key("PREFIX")) {
        install_args.push_str(&format!(" PREFIX=/{prefix}"));
    }
    let mut commands = vec![format!("make -C $SRC{var_args}{file_arg}{target_arg}")];
    if install {
        commands.push(format!(
            "make -C $SRC{install_args}{file_arg} install DESTDIR=$STAGE"
        ));
    }
    BuildPlan {
        commands,
        env: Vec::new(),
        extra_requires: Vec::new(),
        extra_build_deps: Vec::new(),
    }
}

/// `cargo` part: build the crate found in `$SRC` and install its binaries
/// into `$STAGE/bin` via `cargo install --root`. An explicit channel rides
/// as `RUSTUP_TOOLCHAIN` (rustup's selection env var), and the rust
/// toolchain package is added to the snap's `build_deps` so the sandbox
/// stays hermetic (ADR-0018 Decision 5: build-time only, never a runtime
/// closure member).
fn cargo_plan(opts: &[(&'static str, &PluginValue)]) -> miette::Result<BuildPlan> {
    let mut env = Vec::new();
    if let Some(channel) = opt_str(opts, "channel") {
        if !matches!(channel, "stable" | "beta" | "nightly") {
            return Err(miette::miette!(
                "cargo: option 'channel' must be one of: stable, beta, nightly (got '{channel}')"
            ));
        }
        env.push(("RUSTUP_TOOLCHAIN".to_string(), channel.to_string()));
    }
    Ok(BuildPlan {
        commands: vec!["cargo install --path $SRC --root $STAGE".to_string()],
        env,
        extra_requires: Vec::new(),
        extra_build_deps: vec![CARGO_BUILD_DEP.to_string()],
    })
}

/// `cmake` part: out-of-tree configure from `$SRC` into `build/`, build,
/// then install into `$STAGE` via `DESTDIR` — the convention used by the
/// repo's hand-written cmake builds (see `pkgs/c/clang.lua`).
fn cmake_plan(opts: &[(&'static str, &PluginValue)]) -> BuildPlan {
    let mut configure = String::from("cmake -S $SRC -B build");
    if let Some(generator) = opt_str(opts, "generator") {
        configure.push_str(&format!(" -G \"{generator}\""));
    }
    if let Some(defines) = opt_map(opts, "defines") {
        // BTreeMap iteration keeps -D flags deterministic regardless of the
        // definition's table order.
        for (key, value) in defines {
            configure.push_str(&format!(" -D{key}={value}"));
        }
    }
    configure.push_str(" -DCMAKE_INSTALL_PREFIX=/usr");
    BuildPlan {
        commands: vec![
            configure,
            "cmake --build build".to_string(),
            "DESTDIR=$STAGE cmake --install build".to_string(),
        ],
        env: Vec::new(),
        extra_requires: Vec::new(),
        extra_build_deps: Vec::new(),
    }
}

/// `autotools` part: VPATH configure from `$SRC` into the part work dir,
/// build, install into `$STAGE` — the convention used by the repo's
/// hand-written `./configure --prefix=/usr && make install DESTDIR=$STAGE`
/// builds.
///
/// Options (ADR-0014 §6 growth — dogfood friction from dhcpcd):
///
/// - `prefix`: configure prefix, default `"usr"` (the corpus
///   `--prefix=/usr DESTDIR=$STAGE` convention; leading slashes in the value
///   are normalized).
/// - `in_source`: default `false`. When `true`, configure and make run in
///   `$SRC` directly — for non-autoconf configure scripts (dhcpcd's) that
///   write their Makefile into the source dir, which breaks the VPATH
///   `mkdir + $SRC/configure` layout.
fn autotools_plan(opts: &[(&'static str, &PluginValue)]) -> BuildPlan {
    let args = match opt_arr(opts, "args") {
        [] => String::new(),
        items => format!(" {}", items.join(" ")),
    };
    let prefix = opt_str(opts, "prefix")
        .unwrap_or("usr")
        .trim_start_matches('/');
    if opt_bool(opts, "in_source").unwrap_or(false) {
        BuildPlan {
            commands: vec![
                format!("cd $SRC && ./configure --prefix=/{prefix}{args}"),
                "cd $SRC && make".to_string(),
                "cd $SRC && make install DESTDIR=$STAGE".to_string(),
            ],
            env: Vec::new(),
            extra_requires: Vec::new(),
            extra_build_deps: Vec::new(),
        }
    } else {
        BuildPlan {
            commands: vec![
                format!("$SRC/configure --prefix=/{prefix}{args}"),
                "make".to_string(),
                "make install DESTDIR=$STAGE".to_string(),
            ],
            env: Vec::new(),
            extra_requires: Vec::new(),
            extra_build_deps: Vec::new(),
        }
    }
}

// ── adopt-info rung 3: plugin-owned metadata extraction ──

/// One version value extracted from a pinned source tree, with the file it
/// came from (provenance feeds warnings and disagreement errors).
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractedVersion {
    pub value: String,
    /// File the value came from, relative to the source root.
    pub from: String,
}

/// Plugin-owned version extraction for adopt-info snaps: scan the pinned
/// source tree (post-unpack) for the plugin's canonical version
/// declaration. Deterministic line patterns only — no regex engine, no
/// TOML/JSON parser.
///
/// All candidate files are scanned and every hit returned, so two
/// *disagreeing* sources within the part are detected by the caller (which
/// hard-errors instead of arbitrarily picking one). A plugin with no
/// canonical version file (`make` Makefiles declare nothing standard)
/// yields no hits. Build-time only: nothing here feeds the parts cache key
/// (ADR-0014 Decision 5), so [`REGISTRY_VERSION`] is unaffected.
pub fn extract_versions(plugin: &str, src: &Path) -> Vec<ExtractedVersion> {
    match plugin {
        "autotools" => extract_autotools(src),
        "cargo" => extract_cargo(src),
        "cmake" => extract_cmake(src),
        "meson" => extract_meson(src),
        _ => Vec::new(),
    }
}

/// Read a file relative to the source root, if it exists and is UTF-8.
fn read_source_file(src: &Path, name: &str) -> Option<String> {
    std::fs::read_to_string(src.join(name)).ok()
}

/// `autotools`: the version is the second `AC_INIT` argument, in any of the
/// configure script template variants (a tree may carry several; every hit
/// is returned so disagreement is detectable).
fn extract_autotools(src: &Path) -> Vec<ExtractedVersion> {
    let mut hits = Vec::new();
    for name in ["configure.ac", "configure.in", "configure.ac.in"] {
        let Some(content) = read_source_file(src, name) else {
            continue;
        };
        // First AC_INIT in a file wins for that file.
        for line in content.lines() {
            let Some(rest) = line.trim().strip_prefix("AC_INIT") else {
                continue;
            };
            let Some(args) = macro_args(rest) else {
                continue;
            };
            if let Some(v) = unquoted(nth_macro_arg(args, 1)) {
                if !v.is_empty() {
                    hits.push(ExtractedVersion {
                        value: v,
                        from: name.to_string(),
                    });
                    break;
                }
            }
        }
    }
    hits
}

/// Contents of the parenthesized argument list that follows `s` (m4 macro
/// invocations are single-line in practice; the list ends at the last ')'
/// on the line).
fn macro_args(s: &str) -> Option<&str> {
    let s = s.trim_start().strip_prefix('(')?;
    let end = s.rfind(')')?;
    Some(&s[..end])
}

/// Split a macro argument list on top-level commas (m4 quote brackets `[]`
/// shield commas) and return the `n`-th argument, unquoted.
fn nth_macro_arg(args: &str, n: usize) -> Option<String> {
    let mut depth = 0usize;
    let mut fields: Vec<String> = vec![String::new()];
    for c in args.chars() {
        match c {
            '[' => {
                depth += 1;
                fields.last_mut().unwrap().push(c);
            }
            ']' if depth > 0 => {
                depth -= 1;
                fields.last_mut().unwrap().push(c);
            }
            ',' if depth == 0 => fields.push(String::new()),
            c => fields.last_mut().unwrap().push(c),
        }
    }
    fields.into_iter().nth(n)
}

/// Trim whitespace and strip one layer of m4 brackets or quotes.
fn unquoted(arg: Option<String>) -> Option<String> {
    let mut v = arg?.trim().to_string();
    for (open, close) in [('[', ']'), ('\'', '\'')] {
        if let Some(inner) = v.strip_prefix(open).and_then(|s| s.strip_suffix(close)) {
            v = inner.trim().to_string();
            break;
        }
    }
    Some(v)
}

/// `cargo`: the `version` key in the `[package]` section of `Cargo.toml`.
/// Section-aware so dependency `version = "…"` keys elsewhere in the file
/// can never be mistaken for the crate's own version.
fn extract_cargo(src: &Path) -> Vec<ExtractedVersion> {
    let Some(content) = read_source_file(src, "Cargo.toml") else {
        return Vec::new();
    };
    let mut hits = Vec::new();
    let mut in_package = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_package = trimmed.eq_ignore_ascii_case("[package]");
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some(value) = toml_string_field(trimmed, "version") {
            hits.push(ExtractedVersion {
                value,
                from: "Cargo.toml".to_string(),
            });
            break;
        }
    }
    hits
}

/// Value of a `key = "…"` line (bare string form only — tables and arrays
/// are not version declarations).
fn toml_string_field(line: &str, key: &str) -> Option<String> {
    let (k, v) = line.split_once('=')?;
    if k.trim() != key {
        return None;
    }
    let v = v.trim();
    let inner = v.strip_prefix('"')?.strip_suffix('"')?;
    Some(inner.to_string())
}

/// `cmake`: `project(<NAME> VERSION <ver> …)` in the top-level
/// `CMakeLists.txt` (the version keyword argument).
fn extract_cmake(src: &Path) -> Vec<ExtractedVersion> {
    let Some(content) = read_source_file(src, "CMakeLists.txt") else {
        return Vec::new();
    };
    for line in content.lines() {
        let lower = lowercase(line.trim_start());
        let Some(rest) = lower.strip_prefix("project(") else {
            continue;
        };
        let mut tokens = rest.split_whitespace();
        while let Some(tok) = tokens.next() {
            if tok.eq_ignore_ascii_case("VERSION") {
                if let Some(v) = tokens.next() {
                    let v = v.trim_end_matches([')', ',']);
                    if !v.is_empty() {
                        return vec![ExtractedVersion {
                            value: v.to_string(),
                            from: "CMakeLists.txt".to_string(),
                        }];
                    }
                }
            }
        }
    }
    Vec::new()
}

fn lowercase(s: &str) -> String {
    s.chars().flat_map(char::to_lowercase).collect()
}

/// `meson`: the `version` keyword argument of `project()` in the top-level
/// `meson.build`. The call commonly spans lines, so the kwarg is searched
/// for on its own terms (`version : '…'` with any spacing); a match also
/// requires a quote right after the colon, which non-kwarg text (e.g. the
/// word inside an error message string) does not produce.
fn extract_meson(src: &Path) -> Vec<ExtractedVersion> {
    let Some(content) = read_source_file(src, "meson.build") else {
        return Vec::new();
    };
    for line in content.lines() {
        let lower = lowercase(line);
        let Some(idx) = lower.find("version") else {
            continue;
        };
        let Some(after) = line[idx + "version".len()..].trim_start().strip_prefix(':') else {
            continue;
        };
        let after = after.trim_start();
        let Some(quote) = after.chars().next() else {
            continue;
        };
        if quote != '\'' && quote != '"' {
            continue;
        }
        let inner = &after[1..];
        if let Some(end) = inner.find(quote) {
            let v = &inner[..end];
            if !v.is_empty() {
                return vec![ExtractedVersion {
                    value: v.to_string(),
                    from: "meson.build".to_string(),
                }];
            }
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(entries: &[(&str, &str)]) -> BTreeMap<String, PluginValue> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), PluginValue::Str(v.to_string())))
            .collect()
    }

    fn expand_map(plugin: &str, entries: &[(&str, &str)]) -> miette::Result<BuildPlan> {
        expand(plugin, Some(&map(entries)))
    }

    // ── Registry ──

    #[test]
    fn test_plugin_names_sorted_complete() {
        assert_eq!(plugin_names(), vec!["autotools", "cargo", "cmake", "make"]);
        for name in plugin_names() {
            assert!(is_known_plugin(name));
        }
        assert!(!is_known_plugin("gmake"));
    }

    // ── make ──

    #[test]
    fn test_expand_make_defaults() {
        let plan = expand_map("make", &[]).unwrap();
        assert_eq!(
            plan.commands,
            vec![
                "make -C $SRC",
                "make -C $SRC PREFIX=/usr install DESTDIR=$STAGE",
            ]
        );
        assert!(plan.env.is_empty());
        assert!(plan.extra_requires.is_empty());
        assert!(plan.extra_build_deps.is_empty());
    }

    #[test]
    fn test_expand_make_target_and_makefile() {
        let plan =
            expand_map("make", &[("target", "all"), ("makefile", "Makefile.linux")]).unwrap();
        assert_eq!(
            plan.commands,
            vec![
                "make -C $SRC -f Makefile.linux all",
                "make -C $SRC PREFIX=/usr -f Makefile.linux install DESTDIR=$STAGE",
            ]
        );
    }

    #[test]
    fn test_expand_make_variables_sorted_on_both_commands() {
        // Inserted out of order; the emitted command line must be canonical.
        // A variables PREFIX entry replaces the prefix-derived one.
        let mut options = BTreeMap::new();
        options.insert(
            "variables".to_string(),
            PluginValue::Map(
                [
                    ("ZED".to_string(), "1".to_string()),
                    ("ALPHA".to_string(), "2".to_string()),
                    ("PREFIX".to_string(), "/opt/tools".to_string()),
                ]
                .into_iter()
                .collect(),
            ),
        );
        let plan = expand("make", Some(&options)).unwrap();
        assert_eq!(
            plan.commands,
            vec![
                "make -C $SRC ALPHA=2 PREFIX=/opt/tools ZED=1",
                "make -C $SRC ALPHA=2 PREFIX=/opt/tools ZED=1 install DESTDIR=$STAGE",
            ]
        );
    }

    #[test]
    fn test_expand_make_prefix_default_and_override() {
        // Default prefix is "usr" (locked by test_expand_make_defaults);
        // override changes the install line only.
        let plan = expand_map("make", &[("prefix", "/opt")]).unwrap();
        assert_eq!(
            plan.commands,
            vec![
                "make -C $SRC",
                "make -C $SRC PREFIX=/opt install DESTDIR=$STAGE",
            ]
        );
    }

    #[test]
    fn test_expand_make_install_false_emits_build_only() {
        let mut options = BTreeMap::new();
        options.insert("install".to_string(), PluginValue::Bool(false));
        let plan = expand("make", Some(&options)).unwrap();
        assert_eq!(plan.commands, vec!["make -C $SRC"]);

        // Same shape with variables: the build line still carries them.
        options.insert(
            "variables".to_string(),
            PluginValue::Map(
                [("CFLAGS".to_string(), "-O2".to_string())]
                    .into_iter()
                    .collect(),
            ),
        );
        let plan = expand("make", Some(&options)).unwrap();
        assert_eq!(plan.commands, vec!["make -C $SRC CFLAGS=-O2"]);
    }

    #[test]
    fn test_expand_make_variables_must_be_map() {
        let err = expand_map("make", &[("variables", "CFLAGS=-O2")])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("make: option 'variables' must be a string→string map"),
            "got: {err}"
        );
    }

    #[test]
    fn test_expand_make_install_must_be_boolean() {
        let err = expand_map("make", &[("install", "no")])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("make: option 'install' must be true or false"),
            "got: {err}"
        );
    }

    // ── cargo ──

    #[test]
    fn test_expand_cargo_channel_sets_env_and_build_dep() {
        let plan = expand_map("cargo", &[("channel", "nightly")]).unwrap();
        assert_eq!(
            plan.commands,
            vec!["cargo install --path $SRC --root $STAGE"]
        );
        assert_eq!(
            plan.env,
            vec![("RUSTUP_TOOLCHAIN".to_string(), "nightly".to_string())]
        );
        assert!(plan.extra_requires.is_empty());
        assert_eq!(plan.extra_build_deps, vec![CARGO_BUILD_DEP]);
    }

    #[test]
    fn test_expand_cargo_defaults() {
        let plan = expand_map("cargo", &[]).unwrap();
        assert!(plan.env.is_empty());
        assert!(plan.extra_requires.is_empty());
        assert_eq!(plan.extra_build_deps, vec![CARGO_BUILD_DEP]);
    }

    #[test]
    fn test_expand_cargo_rejects_unknown_channel() {
        let err = expand_map("cargo", &[("channel", "fork")])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("cargo: option 'channel' must be one of: stable, beta, nightly"),
            "got: {err}"
        );
    }

    // ── cmake ──

    #[test]
    fn test_expand_cmake_defaults() {
        let plan = expand_map("cmake", &[]).unwrap();
        assert_eq!(
            plan.commands,
            vec![
                "cmake -S $SRC -B build -DCMAKE_INSTALL_PREFIX=/usr",
                "cmake --build build",
                "DESTDIR=$STAGE cmake --install build",
            ]
        );
    }

    #[test]
    fn test_expand_cmake_defines_sorted_and_generator() {
        let mut options = BTreeMap::new();
        options.insert(
            "generator".to_string(),
            PluginValue::Str("Ninja".to_string()),
        );
        // Insert defines out of order: canonical output must still be sorted.
        options.insert(
            "defines".to_string(),
            PluginValue::Map(
                [
                    ("B_FLAG".to_string(), "2".to_string()),
                    ("A_FLAG".to_string(), "1".to_string()),
                ]
                .into_iter()
                .collect(),
            ),
        );
        let plan = expand("cmake", Some(&options)).unwrap();
        assert_eq!(
            plan.commands[0],
            "cmake -S $SRC -B build -G \"Ninja\" -DA_FLAG=1 -DB_FLAG=2 -DCMAKE_INSTALL_PREFIX=/usr"
                .to_string()
        );
    }

    // ── autotools ──

    #[test]
    fn test_expand_autotools_args_order_preserved() {
        let mut options = BTreeMap::new();
        options.insert(
            "args".to_string(),
            PluginValue::Arr(vec!["--disable-nls".into(), "--with-ssl".into()]),
        );
        let plan = expand("autotools", Some(&options)).unwrap();
        assert_eq!(
            plan.commands,
            vec![
                "$SRC/configure --prefix=/usr --disable-nls --with-ssl",
                "make",
                "make install DESTDIR=$STAGE",
            ]
        );
    }

    #[test]
    fn test_expand_autotools_defaults() {
        let plan = expand_map("autotools", &[]).unwrap();
        assert_eq!(plan.commands[0], "$SRC/configure --prefix=/usr");
    }

    #[test]
    fn test_expand_autotools_prefix_override() {
        let plan = expand_map("autotools", &[("prefix", "/opt")]).unwrap();
        assert_eq!(
            plan.commands,
            vec![
                "$SRC/configure --prefix=/opt",
                "make",
                "make install DESTDIR=$STAGE",
            ]
        );
    }

    #[test]
    fn test_expand_autotools_in_source_runs_in_src() {
        // Non-autoconf configure (dhcpcd): everything runs in $SRC directly
        // instead of the VPATH work-dir layout.
        let mut options = BTreeMap::new();
        options.insert("in_source".to_string(), PluginValue::Bool(true));
        options.insert("prefix".to_string(), PluginValue::Str("/opt".into()));
        options.insert(
            "args".to_string(),
            PluginValue::Arr(vec!["--sysconfdir=/etc".into()]),
        );
        let plan = expand("autotools", Some(&options)).unwrap();
        assert_eq!(
            plan.commands,
            vec![
                "cd $SRC && ./configure --prefix=/opt --sysconfdir=/etc",
                "cd $SRC && make",
                "cd $SRC && make install DESTDIR=$STAGE",
            ]
        );
    }

    #[test]
    fn test_expand_autotools_in_source_defaults_false_keeps_vpath() {
        let mut options = BTreeMap::new();
        options.insert("in_source".to_string(), PluginValue::Bool(false));
        let plan = expand("autotools", Some(&options)).unwrap();
        assert_eq!(
            plan.commands,
            vec![
                "$SRC/configure --prefix=/usr",
                "make",
                "make install DESTDIR=$STAGE",
            ]
        );
    }

    #[test]
    fn test_expand_autotools_in_source_must_be_boolean() {
        let err = expand_map("autotools", &[("in_source", "yes")])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("autotools: option 'in_source' must be true or false"),
            "got: {err}"
        );
    }

    // ── Schema validation (ADR-0014 Decision 3 named errors) ──

    #[test]
    fn test_unknown_option_names_plugin_and_available() {
        let err = expand_map("make", &[("jobs", "4")])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(
                "make: unknown option 'jobs' (available: target, makefile, variables, prefix, install)"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_wrong_type_error_is_named() {
        let mut options = map(&[]);
        options.insert(
            "channel".to_string(),
            PluginValue::Arr(vec!["stable".into()]),
        );
        let err = expand("cargo", Some(&options)).unwrap_err().to_string();
        assert!(
            err.contains("cargo: option 'channel' must be a string"),
            "got: {err}"
        );
    }

    #[test]
    fn test_missing_required_option_error() {
        // v1 plugins have no required options (ADR-0014 §6); exercise the
        // required-option machinery with a test-only schema.
        let spec = PluginSpec {
            name: "test",
            options: &[OptionSpec {
                name: "needed",
                kind: OptionKind::Str,
                required: true,
            }],
        };
        let err = validate(&spec, None).unwrap_err().to_string();
        assert_eq!(err, "test: missing required option 'needed'");

        let options = map(&[("needed", "x")]);
        assert!(validate(&spec, Some(&options)).is_ok());
    }

    #[test]
    fn test_unknown_plugin_lists_available() {
        let err = expand("gmake", None).unwrap_err().to_string();
        assert!(
            err.contains("unknown plugin 'gmake' (available: autotools, cargo, cmake, make)"),
            "got: {err}"
        );
    }

    #[test]
    fn test_plugin_value_to_json_canonical() {
        let mut m = BTreeMap::new();
        m.insert("z".to_string(), "1".to_string());
        m.insert("a".to_string(), "2".to_string());
        assert_eq!(
            serde_json::to_string(&PluginValue::Map(m).to_json()).unwrap(),
            r#"{"a":"2","z":"1"}"#
        );
        assert_eq!(
            serde_json::to_string(&PluginValue::Arr(vec!["b".into(), "a".into()]).to_json())
                .unwrap(),
            r#"["b","a"]"#
        );
        assert_eq!(
            serde_json::to_string(&PluginValue::Bool(true).to_json()).unwrap(),
            "true"
        );
        assert_eq!(
            serde_json::to_string(&PluginValue::Bool(false).to_json()).unwrap(),
            "false"
        );
    }

    // ── adopt-info rung 3: plugin-owned version extractors ──

    fn fixture(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, content) in files {
            if let Some(parent) = Path::new(name).parent() {
                std::fs::create_dir_all(dir.path().join(parent)).unwrap();
            }
            std::fs::write(dir.path().join(name), content).unwrap();
        }
        dir
    }

    fn versions(plugin: &str, files: &[(&str, &str)]) -> Vec<ExtractedVersion> {
        let dir = fixture(files);
        extract_versions(plugin, dir.path())
    }

    #[test]
    fn test_extract_autotools_ac_init_bracketed_and_bare() {
        let hits = versions(
            "autotools",
            &[(
                "configure.ac",
                "AC_INIT([smartmontools], [7.4], [bugs@example.org])\n",
            )],
        );
        assert_eq!(
            hits,
            vec![ExtractedVersion {
                value: "7.4".into(),
                from: "configure.ac".into()
            }]
        );

        // Unbracketed form and extra spacing around the macro.
        let hits = versions("autotools", &[("configure.ac", "  AC_INIT(foo, 1.2.3)\n")]);
        assert_eq!(hits[0].value, "1.2.3");
    }

    #[test]
    fn test_extract_autotools_scan_configure_in_variant() {
        // No configure.ac — the configure.in variant carries the version.
        let hits = versions("autotools", &[("configure.in", "AC_INIT(pkg, 0.9.1)\n")]);
        assert_eq!(hits[0].value, "0.9.1");
        assert_eq!(hits[0].from, "configure.in");
    }

    #[test]
    fn test_extract_autotools_all_hits_returned_for_disagreement() {
        // Both variants present: every hit must be returned so the caller
        // can hard-error on disagreement instead of picking one.
        let hits = versions(
            "autotools",
            &[
                ("configure.ac", "AC_INIT([pkg], [1.0])\n"),
                ("configure.in", "AC_INIT([pkg], [2.0])\n"),
            ],
        );
        assert_eq!(
            hits,
            vec![
                ExtractedVersion {
                    value: "1.0".into(),
                    from: "configure.ac".into()
                },
                ExtractedVersion {
                    value: "2.0".into(),
                    from: "configure.in".into()
                },
            ]
        );
    }

    #[test]
    fn test_extract_cargo_package_section_only() {
        let hits = versions(
            "cargo",
            &[(
                "Cargo.toml",
                "[package]\nname = \"demo\"\nversion = \"0.8.2\"\nedition = \"2021\"\n\n\
                 [dependencies]\nserde = { version = \"1.0\", features = [\"derive\"] }\ntoml = \"0.5\"\n",
            )],
        );
        assert_eq!(
            hits,
            vec![ExtractedVersion {
                value: "0.8.2".into(),
                from: "Cargo.toml".into()
            }]
        );
    }

    #[test]
    fn test_extract_cmake_project_version_token() {
        let hits = versions(
            "cmake",
            &[(
                "CMakeLists.txt",
                "cmake_minimum_required(VERSION 3.16)\nproject(XZ VERSION 5.6.4 LANGUAGES C)\n",
            )],
        );
        assert_eq!(
            hits,
            vec![ExtractedVersion {
                value: "5.6.4".into(),
                from: "CMakeLists.txt".into()
            }]
        );

        // A project() without VERSION yields nothing (not a false pick).
        let hits = versions("cmake", &[("CMakeLists.txt", "project(ninja CXX)\n")]);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_extract_meson_version_kwarg_multiline() {
        // project() calls commonly span lines — the kwarg is what counts.
        let hits = versions(
            "meson",
            &[(
                "meson.build",
                "project('foo', 'c',\n  version: '1.10.0',\n  license: 'GPL2+')\n",
            )],
        );
        assert_eq!(
            hits,
            vec![ExtractedVersion {
                value: "1.10.0".into(),
                from: "meson.build".into()
            }]
        );

        // Same-line form and loose spacing around the colon.
        let hits = versions(
            "meson",
            &[("meson.build", "project('foo', version : '2.0')\n")],
        );
        assert_eq!(hits[0].value, "2.0");
    }

    #[test]
    fn test_extract_meson_ignores_non_kwarg_version_text() {
        // "version" inside a string with no quoted value after the colon
        // must not produce a hit.
        let hits = versions(
            "meson",
            &[(
                "meson.build",
                "error('version: unsupported')\nproject('x')\n",
            )],
        );
        assert!(hits.is_empty());
    }

    #[test]
    fn test_extract_make_has_no_canonical_version_file() {
        let hits = versions(
            "make",
            &[("Makefile", "VERSION = 1.2.3\nPREFIX ?= /usr/local\n")],
        );
        assert!(hits.is_empty());
    }

    #[test]
    fn test_extract_versions_absent_files_yield_no_hits() {
        let dir = tempfile::tempdir().unwrap();
        assert!(extract_versions("autotools", dir.path()).is_empty());
        assert!(extract_versions("cargo", dir.path()).is_empty());
        assert!(extract_versions("cmake", dir.path()).is_empty());
        assert!(extract_versions("meson", dir.path()).is_empty());
    }
}
