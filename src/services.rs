//! Declarative pod services (ADR-0032 Decisions 4–7, 11; issue #106).
//!
//! Packages declare `services = { … }` alongside `apps` (the `service()`
//! constructor, ticket #105); pods override per-service options in their
//! `pod {}` block. This module is the emitter family's third member: the
//! recorded declarations are resolved (package defaults folded with the
//! pod-level overrides) into a generation-scoped `units.json`, and the
//! rendered systemd user units are written INSIDE the pod generation
//! (a `services/` directory beside the launchers and the bin farm),
//! surfaced through user-level symlinks in the systemd user unit dir.
//!
//! The mechanism mirrors the desktop launchers (`desktop.rs`) and the
//! font surface (`fonts.rs`): the generation is the versioned source of
//! truth, install/remove/rollback re-emit the target generation's unit
//! set, and unit ids are pod-namespaced (`shuttle-pod-<pod>-<svc>`) so
//! two pods' same-named services coexist exactly like their binaries.
//! Nothing is ever written outside the pod state and the user's config
//! directory.
//!
//! The record/emit split is the rollback seam, and the two halves have
//! different callers:
//!
//! - `record` resolves the DECLARATIONS against the pod-level overrides
//!   and writes `units.json`. It is called ONLY from the reconcile tail
//!   (`present_active`) — the one caller that has override context. A
//!   rollback has no declaration context (and must not re-resolve
//!   against the CURRENT declaration): it re-emits through `farm::emit`,
//!   which serves the target generation's RECORDED `units.json`. That is
//!   why `rollback_pod_with` threads no overrides.
//! - `emit` renders artifacts + user links from `units.json` alone. It
//!   is called from `farm::emit`, so every re-emit path (sync tail,
//!   rollback) gets services for free.
//!
//! Every enabled service carries `[Install] WantedBy=default.target`;
//! `enabled = false` records the service and writes its artifact but
//! withholds the user-level link (NixOS `enable` semantics — declaring
//! never starts anything, ADR-0032 Decision 7). The reconcile diff /
//! start / stop tails are ticket #107.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use crate::runtime::{Generation, RuntimeStore};

/// The services directory inside a generation:
/// `<root>/generations/<n>/services` (the launchers'/farm's sibling).
pub const SERVICES_DIR: &str = "services";

/// The recorded-units file inside [`SERVICES_DIR`]: the generation's
/// whole service surface, written by [`record`] and the ONLY input of
/// [`emit`] (rollback re-emits from it without any declaration context).
const UNITS_FILE: &str = "units.json";

/// The one built-in interpolation reference (ADR-0032 Decision 2) — the
/// same spelling `snap.rs` validates against; kept as a local constant
/// so this module's expansion stays self-contained.
const SERVICE_EXTENSIONS_REF: &str = "extensions";

/// One recorded service unit: the shared vocabulary with options
/// resolved, plus the fully rendered artifact text and its content hash.
/// Serialized into `units.json` as a name-sorted array (deterministic —
/// the file must be byte-stable across re-records).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ServiceUnit {
    /// The service name (its key in the declaring package's `services`).
    pub name: String,
    /// The package that won the name (higher layer wins a shared name).
    pub pkg: String,
    /// The layer the winning package was installed at.
    pub layer: crate::farm::ClaimLayer,
    /// The daemon kind (`simple`/`notify`/`forking`) — the systemd
    /// `Type=` on this backend.
    pub daemon: crate::snap::ServiceDaemon,
    /// The resolved enablement (pod override > package default > false).
    pub enabled: bool,
    /// The absolute farm path of the service binary:
    /// `<root>/current/<svc>` — the `current` flip is the activation
    /// seam, exactly like desktop `Exec` lines.
    pub exec: String,
    /// The resolved arguments (`${}` refs and `%h`/`%p` specifiers
    /// already expanded to literals).
    pub args: Vec<String>,
    /// The resolved options (package defaults folded with the pod-level
    /// overrides, specifiers NOT expanded — the record contract) —
    /// recorded so the cross-pod endpoint scan can read endpoint-ish
    /// option values (ADR-0032 Decision 9 also names data dirs, which
    /// need not appear in any arg). The scan expands `%h`/`%p`/`${ref}`
    /// at COMPARISON time — recorded values are never compared raw
    /// (issue #107: identical raw templates resolve to per-pod paths).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, serde_json::Value>,
    /// The service-declared environment literals (the generation's
    /// recorded env and the loader-lib `LD_LIBRARY_PATH` are composed
    /// into the rendered `text`, not duplicated here).
    pub environment: BTreeMap<String, String>,
    /// The advisory `after` ordering targets, as declared.
    pub after: Vec<String>,
    /// The fully rendered `.service` file.
    pub text: String,
    /// Content hash of this record: lowercase-hex sha256 over the
    /// rendered unit text (UTF-8 bytes), one 0x00 separator byte, then
    /// the owning package's `sha3_384` digest as lowercase ASCII hex.
    /// The separator keeps the concatenation unambiguous; the package
    /// digest makes a binary-only upgrade hash-visible (ADR-0032
    /// Decisions 4 and 8 — the hash must move when the binary moves).
    pub hash: String,
}

/// The `units.json` envelope.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
struct UnitsFile {
    units: Vec<ServiceUnit>,
}

/// Path of generation `n`'s recorded units file.
pub fn units_path(store: &RuntimeStore, n: u64) -> PathBuf {
    store.generation_dir(n).join(SERVICES_DIR).join(UNITS_FILE)
}

/// The unit file name for one service: pod-namespaced
/// (`shuttle-pod-<pod>-<svc>.service`) so two pods' same-named services
/// coexist in the shared systemd user namespace.
fn unit_name(pod: &str, svc: &str) -> String {
    format!("shuttle-pod-{pod}-{svc}.service")
}

// ── Backend selection (ADR-0032 Decision 11) ──

/// The service backend that owns the emitted artifacts. Selection is
/// fail-closed per Decision 11; reachability probing of the systemd user
/// manager (and the portable/launchd emitters themselves) is deferred —
/// until it lands every non-systemd selection is a named error at
/// emit time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceBackend {
    Systemd,
    Launchd,
    Portable,
}

impl ServiceBackend {
    fn label(self) -> &'static str {
        match self {
            ServiceBackend::Systemd => "systemd",
            ServiceBackend::Launchd => "launchd",
            ServiceBackend::Portable => "portable",
        }
    }
}

/// Parse one `SHUTTLE_SERVICE_BACKEND` override value (pure; the test
/// seam for the override grammar).
fn backend_from_override(value: &str) -> miette::Result<ServiceBackend> {
    match value {
        "systemd" => Ok(ServiceBackend::Systemd),
        "launchd" => Ok(ServiceBackend::Launchd),
        "portable" => Ok(ServiceBackend::Portable),
        other => miette::bail!(
            "invalid SHUTTLE_SERVICE_BACKEND '{other}' — must be systemd, launchd, or \
             portable (ADR-0032 Decision 11)"
        ),
    }
}

/// Select the service backend (ADR-0032 Decision 11): the
/// `SHUTTLE_SERVICE_BACKEND` override wins (tests, explicit choice);
/// a macOS host means launchd; anything else is systemd. Reachability
/// probing of the user manager is ticket #107.
pub fn select_backend() -> miette::Result<ServiceBackend> {
    if let Ok(value) = std::env::var("SHUTTLE_SERVICE_BACKEND") {
        if !value.is_empty() {
            return backend_from_override(&value);
        }
    }
    if cfg!(target_os = "macos") {
        return Ok(ServiceBackend::Launchd);
    }
    Ok(ServiceBackend::Systemd)
}

/// Fail closed when the selected backend has no reconcile implementation
/// (Decision 11 sequencing: systemd first; portable and launchd come
/// later). The reconcile tails use this as their named-no-op gate; the
/// emit path carries its own (a skipped emit must still fail on unknown
/// override values while no-oping on the known non-systemd backends).
fn ensure_systemd_backend() -> miette::Result<()> {
    match select_backend()? {
        ServiceBackend::Systemd => Ok(()),
        other => miette::bail!(
            "service backend '{}' is not implemented yet (ADR-0032 Decision 11 sequencing)",
            other.label()
        ),
    }
}

// ── Surfaces ──

/// The systemd user unit dir the enabled unit links live in:
/// `$XDG_CONFIG_HOME/systemd/user`, else `$HOME/.config/systemd/user`.
/// This mirrors systemd's own config resolution and is the test seam —
/// tests MUST redirect `XDG_CONFIG_HOME` (or use [`emit_in`]).
pub fn user_systemd_unit_dir() -> PathBuf {
    let config = match std::env::var("XDG_CONFIG_HOME") {
        Ok(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".config"),
    };
    config.join("systemd").join("user")
}

// ── Record (declaration context required) ──

/// Resolve the generation's service declarations (package records folded
/// with the pod-level overrides) and write `units.json`.
///
/// Present-only by design: `present_active` is the one caller with
/// override context. A rollback re-emits through `farm::emit`, which
/// serves the target generation's RECORDED `units.json` — no override
/// threading there, by intent (see the module docs).
///
/// Must run AFTER `farm::write_generation_env`: the rendered text
/// composes the generation's recorded env. The loader-lib dirs come from
/// [`crate::farm::loader_lib_dirs`] — the same computation
/// `record_loader_libs` writes — so a generation's very first record
/// already carries `LD_LIBRARY_PATH` with no ordering dependency on the
/// recorded file.
pub fn record(
    store: &RuntimeStore,
    gen: &Generation,
    pod_overrides: &BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    secrets_envfile: Option<&str>,
) -> miette::Result<()> {
    let pod = crate::desktop::pod_name(store)?;
    record_in(store, gen, pod_overrides, &pod, secrets_envfile)
}

/// [`record`] with an explicit pod name (tests).
pub fn record_in(
    store: &RuntimeStore,
    gen: &Generation,
    pod_overrides: &BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    pod: &str,
    secrets_envfile: Option<&str>,
) -> miette::Result<()> {
    let current = store.root().join(crate::farm::CURRENT_LINK);
    let ctx = ResolveCtx {
        pod,
        home: &std::env::var("HOME").unwrap_or_else(|_| ".".into()),
        extensions: current.join("extensions").to_string_lossy().into_owned(),
        gen_env: read_generation_env(&crate::farm::env_path(store, gen.n))?,
        loader_libs: crate::farm::loader_lib_dirs(store, gen),
        current: current.to_string_lossy().into_owned(),
        // ADR-0042 D3 (issue #184): the pod's 0600 runtime envfile,
        // derived from the references' decl-hash alone — record bakes
        // the PATH into the unit text without resolving (sync never
        // resolves). `None` for a secret-less pod: no line, nothing
        // that could fail a start.
        secrets_envfile: secrets_envfile.map(str::to_string),
    };

    // Shared service names resolve at emit time exactly like binaries:
    // packages iterate in layer order, a later (higher-layer) claim
    // overwrites an earlier one, and the resolution is never silent.
    let (winners, shuttle_services) = resolve_service_claims(gen);

    let mut units = Vec::new();
    for (svc, pkg) in &winners {
        let decl = &pkg.services[svc.as_str()];
        let empty = BTreeMap::new();
        let overrides = pod_overrides.get(svc).unwrap_or(&empty);
        let resolved = crate::pod::resolve_service_options(
            svc,
            &decl.options,
            overrides,
            "the pod declaration",
            "the package default",
        )?;
        let unit = build_unit(&ctx, svc, pkg, decl, &resolved, &shuttle_services)?;
        units.push(unit);
    }

    let file = UnitsFile { units };
    let path = units_path(store, gen.n);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("creating {}: {e}", parent.display()))?;
    }
    let body = serde_json::to_vec(&file).map_err(|e| miette::miette!("serializing units: {e}"))?;
    std::fs::write(&path, body).map_err(|e| miette::miette!("writing {}: {e}", path.display()))
}

/// Resolve which package owns each declared service name: packages
/// iterate in layer order ([`crate::farm::layered_packages`]) so a
/// later (higher-layer) claim overwrites an earlier one, warning through
/// the shared classifier. Returns the winners (name-ordered — the
/// `units.json` array order) plus the full declared-name set the `after`
/// rendering needs.
fn resolve_service_claims(
    gen: &Generation,
) -> (
    BTreeMap<String, &crate::runtime::InstalledPackage>,
    BTreeSet<String>,
) {
    let mut seen: BTreeMap<&str, (&str, crate::farm::ClaimLayer)> = Default::default();
    let mut winners: BTreeMap<String, &crate::runtime::InstalledPackage> = BTreeMap::new();
    for pkg in crate::farm::layered_packages(gen) {
        for svc in pkg.services.keys() {
            if let Some((incumbent_pkg, incumbent_layer)) = seen.get(svc.as_str()) {
                crate::farm::warn_emit_collision(
                    "service",
                    svc,
                    &pkg.name,
                    incumbent_pkg,
                    *incumbent_layer == pkg.layer,
                );
            }
            seen.insert(svc, (&pkg.name, pkg.layer));
            winners.insert(svc.clone(), pkg);
        }
    }
    let names = winners.keys().cloned().collect();
    (winners, names)
}

/// Everything one unit's resolution needs, gathered once per record.
struct ResolveCtx<'a> {
    pod: &'a str,
    /// `$HOME` (the `%h` expansion; the pod.rs fallback applies).
    home: &'a str,
    /// The absolute extensions dir through `current` (the one built-in
    /// `${extensions}` reference).
    extensions: String,
    /// The generation's recorded env (ADR-0030), composed into the unit.
    gen_env: BTreeMap<String, String>,
    /// The generation's loader-lib dirs (generation-relative), composed
    /// into one `LD_LIBRARY_PATH` line through `current`.
    loader_libs: Vec<String>,
    /// The absolute `current` path.
    current: String,
    /// The pod's 0600 runtime secrets envfile (ADR-0042 D3, issue
    /// #184) — recorded as a mandatory `EnvironmentFile=` line. `None`
    /// for a secret-less pod (no line: an envfile nothing writes must
    /// never fail a start).
    secrets_envfile: Option<String>,
}

/// Resolve and render one service unit (a `record` inner step, split
/// out to keep each function's shape small).
fn build_unit(
    ctx: &ResolveCtx,
    svc: &str,
    pkg: &crate::runtime::InstalledPackage,
    decl: &crate::snap::ServiceDecl,
    resolved: &crate::pod::ResolvedServiceOptions,
    shuttle_services: &BTreeSet<String>,
) -> miette::Result<ServiceUnit> {
    let args = expand_all_args(svc, &decl.args, &resolved.options, ctx)?;

    // Environment composition: service-declared literals first, then the
    // generation's recorded env pairs, then the loader-lib
    // LD_LIBRARY_PATH (only when non-empty). Later lines win in systemd,
    // so the generation env composes OVER the declared literals — the
    // same pod-beats-package layering as everything else.
    let mut environment = decl.environment.clone();
    environment.extend(ctx.gen_env.iter().map(|(k, v)| (k.clone(), v.clone())));
    let ld_library_path = loader_libs_line(ctx);

    let text = render_unit(
        ctx,
        svc,
        decl,
        &args,
        &environment,
        ld_library_path,
        shuttle_services,
    )?;

    Ok(ServiceUnit {
        name: svc.to_string(),
        pkg: pkg.name.clone(),
        layer: pkg.layer,
        daemon: decl.daemon,
        enabled: resolved.enabled,
        exec: format!("{}/{}", ctx.current, svc),
        args,
        options: resolved.options.clone(),
        environment: decl.environment.clone(),
        after: decl.after.clone(),
        hash: unit_hash(&text, &pkg.sha3_384),
        text,
    })
}

/// Expand every declared arg (`${ref}` + `%h`/`%p`/`%%`).
fn expand_all_args(
    svc: &str,
    args: &[String],
    options: &BTreeMap<String, serde_json::Value>,
    ctx: &ResolveCtx,
) -> miette::Result<Vec<String>> {
    let mut resolving = Vec::new();
    args.iter()
        .map(|arg| expand_specifiers(svc, "args", arg, options, ctx, &mut resolving))
        .collect()
}

/// Render the `.service` text for one service. Fixed lines only, plus
/// the `backend_options.systemd` passthrough (rendered verbatim AFTER
/// the fixed lines — systemd's last-wins makes the tail the escape
/// hatch, ADR-0032 Decision 5).
fn render_unit(
    ctx: &ResolveCtx,
    svc: &str,
    decl: &crate::snap::ServiceDecl,
    args: &[String],
    environment: &BTreeMap<String, String>,
    ld_library_path: Option<String>,
    shuttle_services: &BTreeSet<String>,
) -> miette::Result<String> {
    let mut out = String::new();
    out.push_str("[Unit]\n");
    out.push_str(&format!(
        "Description=shuttle pod '{}' service '{}'\n",
        ctx.pod, svc
    ));
    render_after_lines(&mut out, svc, ctx, &decl.after, shuttle_services);
    out.push_str("\n[Service]\n");
    out.push_str(&format!("Type={}\n", daemon_type(decl.daemon)));
    let exec = format!("{}/{}", ctx.current, svc);
    let quoted_args: String = args
        .iter()
        .map(|a| format!(" {}", shell_quote(a)))
        .collect();
    // The exec path is quoted like every arg: a farm root with spaces
    // must not split into binary + phantom args.
    out.push_str(&format!("ExecStart={}{quoted_args}\n", shell_quote(&exec)));
    // ADR-0042 D3/D7 (issue #184): secret values ride the pod's 0600
    // runtime envfile, NEVER the unit text — the mandatory path (no
    // `-` prefix) makes a missing envfile FAIL the unit start naming
    // the path. A silent start-without-secrets is exactly what D7
    // forbids. Rotation never touches this text (values aren't hashed
    // into unit_hash); a reference change moves the decl-hash in the
    // path and the normal unit-diff restart takes it.
    if let Some(envfile) = &ctx.secrets_envfile {
        out.push_str(&format!("EnvironmentFile=\"{envfile}\"\n"));
    }
    for (key, value) in environment {
        out.push_str(&format!(
            "Environment=\"{}={}\"",
            key,
            escape_env_value(value)
        ));
        out.push('\n');
    }
    // Farm-first PATH seam: interpreter-based launchers (wigolo's
    // usr/bin/wigolo execs bare `node`) resolve against the generation
    // root, which carries the farm; systemd's default PATH does not.
    // Baked shape of the hand-written bootstrap unit (t13 §5.4, #104).
    out.push_str(&format!(
        "Environment=\"PATH={}:/usr/bin:/bin\"\n",
        ctx.current
    ));
    if let Some(libs) = ld_library_path {
        out.push_str(&format!("Environment=\"LD_LIBRARY_PATH={libs}\"\n"));
    }
    out.push_str("Restart=on-failure\n");
    out.push_str("RestartSec=5\n");
    render_backend_passthrough(&mut out, svc, decl)?;
    out.push_str("\n[Install]\nWantedBy=default.target\n");
    Ok(out)
}

/// The advisory `After=` lines (ADR-0032 Decision 5): a target that is
/// another declared shuttle service of this generation renders
/// namespaced; anything else (a systemd target like `network.target`,
/// typically) warns and renders raw — advisory, never a readiness
/// contract. A self-reference is a no-op (self-ordering is meaningless).
fn render_after_lines(
    out: &mut String,
    svc: &str,
    ctx: &ResolveCtx,
    after: &[String],
    shuttle_services: &BTreeSet<String>,
) {
    for target in after {
        if target == svc {
            continue;
        }
        if shuttle_services.contains(target.as_str()) {
            out.push_str(&format!("After=shuttle-pod-{}-{target}.service\n", ctx.pod));
            continue;
        }
        crate::output::warn(format!(
            "service '{svc}': after target '{target}' is not a shuttle service of this \
             generation — emitted as a raw unit target (advisory, ADR-0032 Decision 5)"
        ));
        out.push_str(&format!("After={target}.service\n"));
    }
}

/// The `backend_options.systemd` passthrough: verbatim `Key=value`
/// lines after the fixed `[Service]` lines. String, number, and bool
/// values only — anything else is a named render error.
fn render_backend_passthrough(
    out: &mut String,
    svc: &str,
    decl: &crate::snap::ServiceDecl,
) -> miette::Result<()> {
    let Some(systemd) = decl.backend_options.get("systemd") else {
        return Ok(());
    };
    let Some(map) = systemd.as_object() else {
        miette::bail!(
            "service '{svc}': backend_options.systemd must be a table of Key=value \
             settings (ADR-0032 Decision 5)"
        );
    };
    for (key, value) in map {
        let Some(text) = option_text(value) else {
            miette::bail!(
                "service '{svc}': backend_options.systemd key '{key}' must be a string, \
                 number, or boolean (ADR-0032 Decision 5)"
            );
        };
        out.push_str(&format!("{key}={text}\n"));
    }
    Ok(())
}

/// The systemd `Type=` for a declared daemon kind.
fn daemon_type(daemon: crate::snap::ServiceDaemon) -> &'static str {
    match daemon {
        crate::snap::ServiceDaemon::Simple => "simple",
        crate::snap::ServiceDaemon::Notify => "notify",
        crate::snap::ServiceDaemon::Forking => "forking",
    }
}

/// One `LD_LIBRARY_PATH=` value from the generation's loader-lib dirs,
/// each resolved through `current` (`current/../<rel>` resolves, by
/// kernel path resolution, into the generation's own dir — the flip
/// redirects the whole list on rollback, the same seam as the
/// shellenv). `None` when the generation ships no lib dirs.
fn loader_libs_line(ctx: &ResolveCtx) -> Option<String> {
    if ctx.loader_libs.is_empty() {
        return None;
    }
    let libs = ctx
        .loader_libs
        .iter()
        .map(|rel| format!("{}/../{rel}", ctx.current))
        .collect::<Vec<_>>()
        .join(":");
    Some(libs)
}

/// POSIX single-quote a resolved argument: every `'` becomes `'\''`
/// (close the quoting, an escaped quote, reopen), so the baked literal
/// is unambiguous in the `ExecStart` line.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// Escape an `Environment=` value for double quotes.
fn escape_env_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Render a resolved option to its interpolation text: strings verbatim,
/// bools as `true`/`false`, numbers plain; anything else has no text
/// form (`None` — a named error at the reference site).
fn option_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Expand shuttle's specifiers in one declared string (ADR-0032
/// Decision 2): `${ref}` names a declared option of this service or the
/// `extensions` built-in; `%h`/`%p` are shuttle's own emit-time
/// specifiers (home, pod); `%%` is the `%` escape. `%` followed by a
/// non-letter is a literal. Option values may themselves carry
/// specifiers and resolve recursively (cycle-checked). Unknown refs
/// cannot occur (validated at parse) but error anyway if one slips
/// through — fail closed, never leak raw.
fn expand_specifiers(
    service: &str,
    field: &str,
    value: &str,
    options: &BTreeMap<String, serde_json::Value>,
    ctx: &ResolveCtx,
    resolving: &mut Vec<String>,
) -> miette::Result<String> {
    let chars: Vec<char> = value.chars().collect();
    let mut out = String::with_capacity(value.len());
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '$' if chars.get(i + 1) == Some(&'{') => {
                let end = chars[i + 2..]
                    .iter()
                    .position(|&c| c == '}')
                    .map(|p| i + 2 + p);
                let Some(end) = end else {
                    miette::bail!(
                        "service '{service}': field '{field}': unterminated '${{' in \
                         {value:?}"
                    );
                };
                let reference: String = chars[i + 2..end].iter().collect();
                out.push_str(&resolve_ref(
                    service, field, &reference, options, ctx, resolving,
                )?);
                i = end + 1;
            }
            '%' => {
                let (text, advance) =
                    resolve_percent(service, field, chars.get(i + 1).copied(), ctx)?;
                out.push_str(&text);
                i += advance;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// Resolve one `${ref}` occurrence: the `extensions` built-in, or a
/// declared option rendered to text and itself specifier-expanded
/// (recursively, cycle-checked via `resolving`).
fn resolve_ref(
    service: &str,
    field: &str,
    reference: &str,
    options: &BTreeMap<String, serde_json::Value>,
    ctx: &ResolveCtx,
    resolving: &mut Vec<String>,
) -> miette::Result<String> {
    if reference == SERVICE_EXTENSIONS_REF {
        return Ok(ctx.extensions.clone());
    }
    let Some(value) = options.get(reference) else {
        miette::bail!(
            "service '{service}': field '{field}': unknown '${{{reference}}}' reference — \
             must be a declared option of this service or '{SERVICE_EXTENSIONS_REF}' \
             (ADR-0032 Decision 2)"
        );
    };
    if resolving.iter().any(|r| r == reference) {
        miette::bail!(
            "service '{service}': field '{field}': option reference cycle through \
             '{reference}'"
        );
    }
    let Some(text) = option_text(value) else {
        miette::bail!(
            "service '{service}': field '{field}': option '{reference}' is not a string, \
             number, or boolean — nothing to interpolate"
        );
    };
    resolving.push(reference.to_string());
    let expanded = expand_specifiers(service, field, &text, options, ctx, resolving);
    resolving.pop();
    expanded
}

/// Resolve one `%` occurrence: `%h`, `%p`, the `%%` escape, a literal
/// `%` before a non-letter, or (cannot occur — validated at parse) a
/// named error. Returns the text and how many chars it consumed.
fn resolve_percent(
    service: &str,
    field: &str,
    next: Option<char>,
    ctx: &ResolveCtx,
) -> miette::Result<(String, usize)> {
    match next {
        Some('h') => Ok((ctx.home.to_string(), 2)),
        Some('p') => Ok((ctx.pod.to_string(), 2)),
        Some('%') => Ok(("%".into(), 2)),
        Some(c) if c.is_ascii_alphabetic() => miette::bail!(
            "service '{service}': field '{field}': '%{c}' is not a shuttle specifier — \
             only %h, %p, and the escape %% are valid (ADR-0032 Decision 2)"
        ),
        _ => Ok(("%".into(), 1)),
    }
}

/// sha256 over the rendered text + the owning package's digest (see
/// [`ServiceUnit::hash`] for the exact input framing).
fn unit_hash(text: &str, pkg_sha3_384: &str) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(text.as_bytes());
    hasher.update([0u8]);
    hasher.update(pkg_sha3_384.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Tolerant parse of a generation's recorded env object (ADR-0030): a
/// missing file is a generation without declared env — an empty map is
/// the correct answer. A corrupt object fails loudly (trusted data).
fn read_generation_env(path: &std::path::Path) -> miette::Result<BTreeMap<String, String>> {
    let body = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => {
            return Err(miette::miette!("reading {}: {e}", path.display()));
        }
    };
    serde_json::from_str(&body)
        .map_err(|e| miette::miette!("corrupt generation env {}: {e}", path.display()))
}

// ── Emit (units.json is the only input) ──

/// Emit a generation's service surface from its recorded `units.json`:
/// write the unit artifacts INSIDE the generation and link the enabled
/// ones into the systemd user unit dir. A missing or empty units file is
/// still a withdrawal pass — stale links a previous generation left are
/// removed.
///
/// An explicit `SHUTTLE_SERVICE_BACKEND=launchd|portable` is a named
/// no-op, matching the reconcile tail's skip contract for non-systemd
/// hosts (Decision 11): those hosts must keep syncing pods, and emitting
/// systemd-shaped artifacts for them would be wrong. Unknown override
/// values still fail the verb, through [`select_backend`].
pub fn emit(store: &RuntimeStore, gen: &Generation) -> miette::Result<()> {
    match select_backend()? {
        ServiceBackend::Systemd => {}
        other => {
            crate::output::warn(format!(
                "services: skipped — service backend '{}' has no emitter yet \
                 (ADR-0032 Decision 11)",
                other.label()
            ));
            return Ok(());
        }
    }
    let pod = crate::desktop::pod_name(store)?;
    emit_in(store, gen, &user_systemd_unit_dir(), &pod)
}

/// [`emit`] with an explicit unit dir and pod name (tests — never env).
pub fn emit_in(
    store: &RuntimeStore,
    gen: &Generation,
    unit_dir: &std::path::Path,
    pod: &str,
) -> miette::Result<()> {
    let Some(file) = present_units_file(store, gen.n)? else {
        return withdraw_stale_services(unit_dir, pod, &BTreeSet::new());
    };

    let dir = store.generation_dir(gen.n).join(SERVICES_DIR);
    write_service_artifacts(store, gen.n, pod, &file)?;

    // The enabled keep set drives BOTH the user links and the stale-link
    // withdrawal; disabled records get their artifact but no link
    // (ADR-0032 Decision 7 — enablement withholds the link, not the
    // artifact).
    let mut keep: BTreeSet<String> = BTreeSet::new();
    for unit in &file.units {
        let artifact = dir.join(unit_name(pod, &unit.name));
        if !unit.enabled {
            continue;
        }
        keep.insert(unit.name.clone());
        let link = unit_dir.join(unit_name(pod, &unit.name));
        if let Some(parent) = link.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette::miette!("creating {}: {e}", parent.display()))?;
        }
        crate::desktop::link_or_replace(&artifact, &link)?;
    }

    withdraw_stale_services(unit_dir, pod, &keep)
}

/// Read a generation's recorded units file for an emit, treating a
/// missing or empty file as "no present surface". A corrupt file fails
/// loudly — trusted data.
fn present_units_file(store: &RuntimeStore, n: u64) -> miette::Result<Option<UnitsFile>> {
    match read_units_file(store, n)? {
        None => Ok(None),
        Some(file) if file.units.is_empty() => Ok(None),
        Some(file) => Ok(Some(file)),
    }
}

/// Rewrite the generation's `services/` dir: write every recorded unit's
/// artifact, replace the recorded units file by atomic rename, then prune
/// what the previous record left behind. Crash-safety (issue #109 N12):
/// the recorded units file is NEVER removed — it is the rollback
/// re-render source — so a crash at any point leaves either the old or
/// the new `units.json` intact. A stale artifact or a leftover temp file
/// from an interrupted pass is pruned by the next emit.
fn write_service_artifacts(
    store: &RuntimeStore,
    n: u64,
    pod: &str,
    file: &UnitsFile,
) -> miette::Result<()> {
    let dir = store.generation_dir(n).join(SERVICES_DIR);
    std::fs::create_dir_all(&dir)
        .map_err(|e| miette::miette!("creating services {}: {e}", dir.display()))?;
    for unit in &file.units {
        let artifact = dir.join(unit_name(pod, &unit.name));
        std::fs::write(&artifact, &unit.text)
            .map_err(|e| miette::miette!("writing {}: {e}", artifact.display()))?;
    }
    let path = units_path(store, n);
    let body = serde_json::to_vec(file).map_err(|e| miette::miette!("serializing units: {e}"))?;
    let tmp = dir.join(format!(".{UNITS_FILE}.tmp"));
    std::fs::write(&tmp, &body).map_err(|e| miette::miette!("writing {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| miette::miette!("installing {}: {e}", path.display()))?;
    // The prune runs LAST: everything the recorded file names is already
    // on disk, so an interruption here leaves prunable orphans — never a
    // lost record.
    prune_stale_artifacts(&dir, pod, file)
}

/// Remove everything in the generation's `services/` dir the recorded
/// units file does not name (stale artifacts, a leftover atomic-rename
/// temp file). A missing dir or unreadable entry is left to the next emit.
fn prune_stale_artifacts(dir: &std::path::Path, pod: &str, file: &UnitsFile) -> miette::Result<()> {
    let current: BTreeSet<String> = file.units.iter().map(|u| unit_name(pod, &u.name)).collect();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == UNITS_FILE || current.contains(&name) {
            continue;
        }
        let _ = std::fs::remove_file(entry.path());
    }
    Ok(())
}

/// Remove the user-level unit links this pod owns but `keep` does not
/// name (a service removed, disabled, or the pod cleared). Only links
/// matching the pod-namespaced `shuttle-pod-<pod>-*.service` pattern are
/// touched — never other tools' units.
fn withdraw_stale_services(
    unit_dir: &std::path::Path,
    pod: &str,
    keep: &BTreeSet<String>,
) -> miette::Result<()> {
    let prefix = format!("shuttle-pod-{pod}-");
    if let Ok(rd) = std::fs::read_dir(unit_dir) {
        for entry in rd.filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(svc) = name
                .strip_suffix(".service")
                .and_then(|stem| stem.strip_prefix(&prefix))
            else {
                continue;
            };
            if !keep.contains(svc) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    Ok(())
}

/// Withdraw ALL of this pod's user-level unit links (the `desktop::clear`
/// analog; the generation's own `services/` dir is left for the GC).
pub fn clear(store: &RuntimeStore) -> miette::Result<()> {
    let pod = crate::desktop::pod_name(store)?;
    withdraw_stale_services(&user_systemd_unit_dir(), &pod, &BTreeSet::new())
}

/// Read a generation's recorded units file. `None` = the generation has
/// no recorded service surface (nothing declared, or a pre-services
/// generation). A corrupt file fails loudly — trusted data.
fn read_units_file(store: &RuntimeStore, n: u64) -> miette::Result<Option<UnitsFile>> {
    let path = units_path(store, n);
    let body = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(miette::miette!("reading {}: {e}", path.display()));
        }
    };
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|e| miette::miette!("corrupt units file {}: {e}", path.display()))
}

// ── Reconcile tail (ADR-0032 Decision 8, ticket #107) ──
//
// Switch-to-configuration semantics on every generation-changing verb:
// the tail diffs the active generation's recorded units against the
// pod's APPLIED state, then reloads the user manager once and switches:
// enable+start new/changed/newly-enabled units, stop+disable withdrawn
// or newly-disabled ones. Deactivation is stop-then-withdraw — a
// registration is never pulled from under a running service. The tail
// runs AFTER the generation flip on every path (`present_active` and
// `rollback_pod_with`); the flip's emit has already placed the
// generation's link set, so everything here converges the BUS-side
// registrations onto that file-level truth.

/// The per-pod applied-state record:
/// `<pod_dir>/services-state.json`. Written after each SUCCESSFUL
/// reconcile of that pod as the all-units map of what it registered —
/// per-pod reconcile bookkeeping, NOT a journal and NOT a cross-pod
/// registry (ADR-0032 Decision 9 keeps cross-pod questions comparisons).
const STATE_FILE: &str = "services-state.json";

/// One unit's applied registration: the content hash that was live (it
/// covers the rendered artifact AND the owning package's digest, so a
/// binary-only upgrade diffs as changed) and the enablement it was
/// applied with. The package digest is NOT recoverable from the linked
/// unit file, which is exactly why this record exists.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AppliedUnit {
    pub hash: String,
    pub enabled: bool,
    /// Whether this entry's bus steps actually RAN. `false` = the last
    /// reconcile planned the unit but systemctl was unavailable — the
    /// manager was never told, so the classifier re-plans it instead of
    /// diffing clean against a converged-looking state.
    #[serde(default = "default_applied")]
    pub applied: bool,
}

fn default_applied() -> bool {
    true
}

/// The applied-state envelope (see [`STATE_FILE`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AppliedState {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub units: BTreeMap<String, AppliedUnit>,
}

/// What one reconcile did — the report the pod verbs surface. A missing
/// systemctl lands every skipped step in `skipped` (named, never a
/// silent no-op); a systemctl that exists and FAILS is a real error.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ServiceReconcileReport {
    pub pod: String,
    /// True when `daemon-reload` actually ran (once, for a pending diff).
    #[serde(default)]
    pub reloaded: bool,
    /// Units enabled + started (`enable --now`).
    #[serde(default)]
    pub activated: Vec<String>,
    /// Units restarted because their applied hash moved.
    #[serde(default)]
    pub restarted: Vec<String>,
    /// Units stopped + disabled (`disable --now`, before any unlink).
    #[serde(default)]
    pub deactivated: Vec<String>,
    /// Named skips: `"<unit or manager>: <step> — <reason>"`.
    #[serde(default)]
    pub skipped: Vec<String>,
    /// True when the linger warning was emitted (ADR-0032 Decision 8).
    #[serde(default)]
    pub linger_warned: bool,
}

impl ServiceReconcileReport {
    /// True when nothing happened worth printing: no reload, no unit
    /// moved, no skip, no warning. The print-side quiet rule — a no-op
    /// sync stays silent about services.
    pub fn is_trivial(&self) -> bool {
        !self.reloaded
            && !self.linger_warned
            && self.activated.is_empty()
            && self.restarted.is_empty()
            && self.deactivated.is_empty()
            && self.skipped.is_empty()
    }
}

/// Path of a pod's applied-state record (`<pod_dir>/services-state.json`).
fn state_path(dir: &std::path::Path) -> PathBuf {
    dir.join(STATE_FILE)
}

/// Read the applied state. Missing or corrupt → an empty map plus
/// `readable = false`: the diff then treats live links as unknown
/// registrations (conservative: restart), never as silently fine.
fn read_applied_state(dir: &std::path::Path) -> (AppliedState, bool) {
    match std::fs::read_to_string(state_path(dir)) {
        Ok(body) => match serde_json::from_str(&body) {
            Ok(state) => (state, true),
            Err(_) => (AppliedState::default(), false),
        },
        Err(_) => (AppliedState::default(), false),
    }
}

/// Write the applied state (the all-units map of a successful reconcile).
fn write_applied_state(dir: &std::path::Path, state: &AppliedState) -> miette::Result<()> {
    let body =
        serde_json::to_vec(state).map_err(|e| miette::miette!("serializing applied state: {e}"))?;
    std::fs::write(state_path(dir), body)
        .map_err(|e| miette::miette!("writing {}: {e}", state_path(dir).display()))
}

/// The reconcile action one unit needs (the diff's output).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnitAction {
    /// New or newly enabled: `enable --now` (enable + start in one call).
    Activate,
    /// The applied hash moved while the unit stayed enabled — or the
    /// applied entry is missing but a live link exists (unknown running
    /// contract, conservative restart). Restart implies the running
    /// contract (ADR-0032 Decision 8).
    Restart,
    /// Newly disabled, withdrawn, or an unknown live registration on a
    /// now-disabled unit: stop + disable BEFORE any link is withdrawn.
    Deactivate,
}

/// Classify one generation unit against the applied state (pure; the
/// diff core of Decision 8). `live_link` says whether the user-level
/// unit link exists right now; `state_ok` says the applied-state record
/// itself was present and readable. With a readable record, a unit
/// missing an entry is NEW (activate when enabled — the flip's emit may
/// already have placed its link, which makes no difference). With a
/// missing/corrupt RECORD, a live link means an unknown running
/// contract: conservative restart when enabled, deactivate when
/// disabled. A changed-but-dormant unit needs no bus action.
fn classify_unit(
    applied: Option<&AppliedUnit>,
    live_link: bool,
    state_ok: bool,
    unit: &ServiceUnit,
) -> Option<UnitAction> {
    // An entry whose bus steps were skipped (systemctl was missing) is
    // NOT a converged registration: re-plan it from the live-link state
    // so the next run with tools converges instead of diffing clean
    // against a state that lies. `enable --now` is idempotent for an
    // already-enabled unit, and the artifact on disk already matches
    // units.json (the emit ran), so Activate converges without a bounce.
    let unapplied = matches!(applied, Some(a) if !a.applied);
    let applied = if unapplied { None } else { applied };
    match applied {
        Some(a) => match (unit.enabled, a.enabled) {
            (true, false) => Some(UnitAction::Activate),
            (false, true) => Some(UnitAction::Deactivate),
            (true, true) if a.hash != unit.hash => Some(UnitAction::Restart),
            _ => None,
        },
        None if state_ok && !unapplied => {
            if unit.enabled {
                Some(UnitAction::Activate)
            } else {
                None
            }
        }
        None => match (unit.enabled, live_link) {
            (true, false) => Some(UnitAction::Activate),
            (true, true) if unapplied => Some(UnitAction::Activate),
            (true, true) => Some(UnitAction::Restart),
            (false, true) => Some(UnitAction::Deactivate),
            (false, false) => None,
        },
    }
}

/// The diff outcome for one reconcile: which units need which action.
#[derive(Debug, Default)]
struct ReconcilePlan {
    activate: Vec<String>,
    restart: Vec<String>,
    deactivate: Vec<String>,
}

impl ReconcilePlan {
    fn any(&self) -> bool {
        !self.activate.is_empty() || !self.restart.is_empty() || !self.deactivate.is_empty()
    }
}

/// Diff the generation's units + the applied state into a plan (pure
/// aside from the read-only live-link checks).
fn plan_reconcile(
    pod: &str,
    units: &[ServiceUnit],
    applied: &BTreeMap<String, AppliedUnit>,
    state_ok: bool,
    unit_dir: &std::path::Path,
) -> ReconcilePlan {
    let mut plan = ReconcilePlan::default();
    for unit in units {
        let live = unit_dir
            .join(unit_name(pod, &unit.name))
            .symlink_metadata()
            .is_ok();
        match classify_unit(applied.get(&unit.name), live, state_ok, unit) {
            Some(UnitAction::Activate) => plan.activate.push(unit.name.clone()),
            Some(UnitAction::Restart) => plan.restart.push(unit.name.clone()),
            Some(UnitAction::Deactivate) => plan.deactivate.push(unit.name.clone()),
            None => {}
        }
    }
    // Withdrawn: applied but gone from the generation. Enabled ones may
    // still be running under a registration the flip's emit already
    // unlinked — they join the stop phase; disabled ones only leave the
    // state map at the tail's rewrite.
    for (name, a) in applied {
        if a.enabled && !units.iter().any(|u| &u.name == name) {
            plan.deactivate.push(name.clone());
        }
    }
    plan
}

/// Run one `systemctl --user` step. A missing binary is a named SKIP in
/// the report — the file-level truth (links + state) still reconciles,
/// so the next run with tools converges. A binary that exists and fails
/// is a real error: the running contract is not ours to guess around.
/// Returns true only when the step actually ran.
fn run_systemctl(
    tools: &crate::runtime::RuntimeTools,
    args: &[&str],
    what: &str,
    unit: &str,
    report: &mut ServiceReconcileReport,
) -> miette::Result<bool> {
    let Some(systemctl) = &tools.systemctl else {
        report
            .skipped
            .push(format!("{unit}: {what} skipped — systemctl unavailable"));
        return Ok(false);
    };
    let status = std::process::Command::new(systemctl)
        .arg("--user")
        .args(args)
        .status()
        .map_err(|e| miette::miette!("{what}: spawning {}: {e}", systemctl.display()))?;
    if !status.success() {
        miette::bail!(
            "{what}: systemctl --user {} exited {:?}",
            args.join(" "),
            status.code()
        );
    }
    Ok(true)
}

/// The newest on-disk artifact for one unit file: the given generation's
/// first (a newly-disabled unit lives there), else any older generation
/// that still carries it (a withdrawn unit's artifact survives until
/// GC). `None` when no generation on disk can resolve the unit file.
fn find_unit_artifact(
    store: &RuntimeStore,
    gen_n: Option<u64>,
    unit_file: &str,
) -> Option<PathBuf> {
    if let Some(n) = gen_n {
        let candidate = store.generation_dir(n).join(SERVICES_DIR).join(unit_file);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    let mut numbers: Vec<u64> = std::fs::read_dir(store.root().join("generations"))
        .ok()?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse().ok()))
        .collect();
    numbers.sort_unstable_by(|a, b| b.cmp(a));
    numbers
        .into_iter()
        .filter(|n| Some(*n) != gen_n)
        .map(|n| store.generation_dir(n).join(SERVICES_DIR).join(unit_file))
        .find(|candidate| candidate.exists())
}

/// Point a to-deactivate unit's user-level link at a live artifact so
/// `disable --now` finds the unit file. The flip's emit has usually
/// already withdrawn the link, and disabling against a missing unit file
/// would fail — stop-then-withdraw requires the registration to exist at
/// stop time, so it is restored here first (the final emit withdraws it
/// again). Returns whether the unit file is resolvable afterwards.
fn ensure_deactivation_link(
    store: &RuntimeStore,
    gen_n: Option<u64>,
    pod: &str,
    svc: &str,
) -> miette::Result<bool> {
    let name = unit_name(pod, svc);
    let Some(artifact) = find_unit_artifact(store, gen_n, &name) else {
        return Ok(false);
    };
    let link = user_systemd_unit_dir().join(&name);
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("creating {}: {e}", parent.display()))?;
    }
    crate::desktop::link_or_replace(&artifact, &link)?;
    Ok(true)
}

/// The stop phase: for every to-deactivate unit, make sure its
/// registration still resolves, then `systemctl --user disable --now` —
/// stop and disable in one call, BEFORE any link is finally withdrawn
/// (never the reverse, ADR-0032 Decision 8).
fn apply_deactivations(
    store: &RuntimeStore,
    gen_n: Option<u64>,
    unit_dir: &std::path::Path,
    pod: &str,
    names: &[String],
    tools: &crate::runtime::RuntimeTools,
    report: &mut ServiceReconcileReport,
) -> miette::Result<()> {
    for svc in names {
        let linked = if tools.systemctl.is_some() {
            ensure_deactivation_link(store, gen_n, pod, svc)?
        } else {
            false
        };
        let live = unit_dir
            .join(unit_name(pod, svc))
            .symlink_metadata()
            .is_ok();
        if tools.systemctl.is_some() && !linked && !live {
            report.skipped.push(format!(
                "{svc}: disable --now skipped — no unit file on disk to stop from"
            ));
            continue;
        }
        let unit = unit_name(pod, svc);
        let ran = run_systemctl(
            tools,
            &["disable", "--now", &unit],
            "disable --now",
            svc,
            report,
        )?;
        if ran {
            report.deactivated.push(svc.clone());
        }
    }
    Ok(())
}

/// The activation/restart phase: `enable --now` starts the contract,
/// `restart` replaces it — one systemctl call per unit, after the
/// manager reload. Returns the units whose step actually ran.
fn apply_unit_steps(
    pod: &str,
    names: &[String],
    verb: &[&str],
    what: &str,
    tools: &crate::runtime::RuntimeTools,
    report: &mut ServiceReconcileReport,
) -> miette::Result<Vec<String>> {
    let mut ran = Vec::new();
    for svc in names {
        let unit = unit_name(pod, svc);
        let mut args: Vec<&str> = verb.to_vec();
        args.push(&unit);
        if run_systemctl(tools, &args, what, svc, report)? {
            ran.push(svc.clone());
        }
    }
    Ok(ran)
}

/// The Decision 8 linger warning: with enabled services just brought
/// into the running set, a `Linger=no` user means they stop at the last
/// logout. Best-effort and read-only — shuttle NEVER enables linger
/// (a documented one-time manual host step). A missing loginctl (or any
/// probe failure) stays silent. `loginctl` rides the [`RuntimeTools`]
/// seam like every other tool, so `SHUTTLE_POD_TOOLS=absent` silences
/// the probe instead of tests having to scrub PATH.
fn check_linger(
    tools: &crate::runtime::RuntimeTools,
    pod: &str,
    report: &mut ServiceReconcileReport,
) {
    let Some(loginctl) = &tools.loginctl else {
        return;
    };
    let uid = unsafe { libc::getuid() }.to_string();
    let Ok(output) = std::process::Command::new(loginctl)
        .args(["show-user", &uid, "--property=Linger"])
        .output()
    else {
        return;
    };
    if !output.status.success() {
        return;
    }
    if String::from_utf8_lossy(&output.stdout).trim() == "Linger=no" {
        crate::output::warn(format!(
            "pod '{pod}' has enabled services but lingering is off — services stop at \
             your last logout; enable it once with: sudo loginctl enable-linger <user>"
        ));
        report.linger_warned = true;
    }
}

/// Reconcile the pod's service registrations with its active generation
/// (ADR-0032 Decision 8; the tail of every generation-changing verb).
///
/// Order inside the tail: the cross-pod endpoint scan FIRST (a Decision
/// 9 collision is a hard error before ANY mutation), then the diff
/// against the applied state, then — when anything is pending — one
/// `daemon-reload`, then `enable --now` / `restart` / `disable --now`,
/// then the link set is re-emitted to the generation's exact truth and
/// the applied state is rewritten. Runs after the flip; every step
/// converges (idempotent) — a re-run with no diff is a trivial report.
///
/// A non-systemd backend is a named no-op report, never a verb failure:
/// WSL2/SysV hosts must keep syncing pods; their service lifecycle is
/// the portable backend's business (ADR-0032 Decision 10, ticket #108+).
pub fn reconcile(
    store: &RuntimeStore,
    dir: &std::path::Path,
    pod_name: &str,
    tools: &crate::runtime::RuntimeTools,
) -> miette::Result<ServiceReconcileReport> {
    let mut report = ServiceReconcileReport {
        pod: pod_name.to_string(),
        ..Default::default()
    };
    let root = dir
        .parent()
        .ok_or_else(|| miette::miette!("pod dir {} has no parent root", dir.display()))?;
    check_endpoint_collisions(root)?;

    if ensure_systemd_backend().is_err() {
        report.skipped.push(
            "services: skipped — the selected service backend has no reconcile implementation"
                .into(),
        );
        return Ok(report);
    }

    let applied = read_applied_state(dir);
    match store.active_generation()? {
        Some(gen) => {
            let units = present_units_file(store, gen.n)?
                .map(|f| f.units)
                .unwrap_or_default();
            let input = ReconcileInput {
                store,
                gen: &gen,
                dir,
                units: &units,
                applied: &applied.0,
                state_ok: applied.1,
            };
            reconcile_presented(&input, pod_name, tools, &mut report)?;
        }
        None => {
            withdraw_applied_units(store, pod_name, tools, &applied.0, &mut report)?;
            write_applied_state(dir, &AppliedState::default())?;
        }
    }
    Ok(report)
}

/// The withdrawal-on-empty reconcile (`shuttle pod` with nothing
/// active): stop + disable everything the applied state remembers being
/// live, then withdraw all of the pod's links — the same
/// stop-then-withdraw rule, with no generation to serve. Skips the
/// endpoint scan: a pure withdrawal can activate nothing, so it cannot
/// create a collision.
pub fn reconcile_empty(
    dir: &std::path::Path,
    pod_name: &str,
    tools: &crate::runtime::RuntimeTools,
) -> miette::Result<ServiceReconcileReport> {
    let mut report = ServiceReconcileReport {
        pod: pod_name.to_string(),
        ..Default::default()
    };
    if ensure_systemd_backend().is_err() {
        report.skipped.push(
            "services: skipped — the selected service backend has no reconcile implementation"
                .into(),
        );
        return Ok(report);
    }
    let store = RuntimeStore::new(dir.to_path_buf());
    let (applied, _) = read_applied_state(dir);
    withdraw_applied_units(&store, pod_name, tools, &applied, &mut report)?;
    write_applied_state(dir, &AppliedState::default())?;
    Ok(report)
}

/// Stop + disable every applied-enabled unit and withdraw all of the
/// pod's links (the empty-generation tail).
fn withdraw_applied_units(
    store: &RuntimeStore,
    pod_name: &str,
    tools: &crate::runtime::RuntimeTools,
    applied: &AppliedState,
    report: &mut ServiceReconcileReport,
) -> miette::Result<()> {
    let names: Vec<String> = applied
        .units
        .iter()
        .filter(|(_, a)| a.enabled)
        .map(|(n, _)| n.clone())
        .collect();
    let unit_dir = user_systemd_unit_dir();
    apply_deactivations(store, None, &unit_dir, pod_name, &names, tools, report)?;
    withdraw_stale_services(&unit_dir, pod_name, &BTreeSet::new())
}

/// Everything one presented-generation reconcile needs, bundled.
struct ReconcileInput<'a> {
    store: &'a RuntimeStore,
    gen: &'a Generation,
    dir: &'a std::path::Path,
    units: &'a [ServiceUnit],
    applied: &'a AppliedState,
    /// Whether the applied-state record itself was present and readable
    /// (`false` = missing/corrupt — the conservative-restart regime).
    state_ok: bool,
}

/// The presented-generation reconcile: diff, switch, re-emit, record.
fn reconcile_presented(
    input: &ReconcileInput,
    pod_name: &str,
    tools: &crate::runtime::RuntimeTools,
    report: &mut ServiceReconcileReport,
) -> miette::Result<()> {
    let unit_dir = user_systemd_unit_dir();
    let plan = plan_reconcile(
        pod_name,
        input.units,
        &input.applied.units,
        input.state_ok,
        &unit_dir,
    );
    let store = input.store;
    let gen = input.gen;
    if plan.any() {
        let reloaded = run_systemctl(
            tools,
            &["daemon-reload"],
            "daemon-reload",
            "manager",
            report,
        )?;
        report.reloaded = reloaded;
    }
    report.activated = apply_unit_steps(
        pod_name,
        &plan.activate,
        &["enable", "--now"],
        "enable --now",
        tools,
        report,
    )?;
    report.restarted = apply_unit_steps(
        pod_name,
        &plan.restart,
        &["restart"],
        "restart",
        tools,
        report,
    )?;
    apply_deactivations(
        store,
        Some(gen.n),
        &unit_dir,
        pod_name,
        &plan.deactivate,
        tools,
        report,
    )?;

    // The on-disk link set becomes the generation's exact truth (the
    // flip's emit already did this; re-emitting is idempotent and
    // withdraws the deactivation re-links).
    emit(store, gen)?;

    // Applied state = what the manager was last TOLD (see the helper).
    write_reconciled_state(input, &plan, report)?;

    if !report.activated.is_empty() || !report.restarted.is_empty() {
        check_linger(tools, pod_name, report);
    }
    Ok(())
}

/// Record the per-pod applied state after a presented reconcile: what
/// the manager was last TOLD. A unit whose bus steps ran (or that
/// needed no step) records `applied: true`; one whose steps were
/// skipped records `applied: false`, so the next run with tools
/// re-plans it instead of trusting a converged-looking state — the
/// state must never lie converged.
fn write_reconciled_state(
    input: &ReconcileInput,
    plan: &ReconcilePlan,
    report: &ServiceReconcileReport,
) -> miette::Result<()> {
    let planned: std::collections::BTreeSet<&str> = plan
        .activate
        .iter()
        .chain(plan.restart.iter())
        .chain(plan.deactivate.iter())
        .map(String::as_str)
        .collect();
    let ran: std::collections::BTreeSet<String> = report
        .activated
        .iter()
        .chain(report.restarted.iter())
        .chain(report.deactivated.iter())
        .cloned()
        .collect();
    let state = AppliedState {
        units: input
            .units
            .iter()
            .map(|u| {
                let applied = !planned.contains(u.name.as_str()) || ran.contains(&u.name);
                (
                    u.name.clone(),
                    AppliedUnit {
                        hash: u.hash.clone(),
                        enabled: u.enabled,
                        applied,
                    },
                )
            })
            .collect(),
    };
    write_applied_state(input.dir, &state)
}

// ── Cross-pod endpoint collisions (ADR-0032 Decision 9) ──

/// The endpoint flags a unit's resolved args are scanned for, in both
/// `--flag value` and `--flag=value` shapes. Endpoint-ish recorded
/// option values (port / socket / data dir keys, ADR-0032 Decision 9)
/// join the claim set separately — see [`endpoint_option_family`].
const ENDPOINT_FLAGS: [&str; 3] = ["--port", "--socket", "--socket-path"];

/// Extract the (flag, value) endpoint pairs from resolved args (pure).
/// A bare flag with no following value contributes nothing.
fn extract_endpoints(args: &[String]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (i, arg) in args.iter().enumerate() {
        for flag in ENDPOINT_FLAGS {
            if arg == flag {
                // `--flag value`: a following flag token (or empty) is a
                // missing value, not an endpoint — skip, never misread.
                if let Some(value) = args.get(i + 1) {
                    if !value.is_empty() && !value.starts_with("--") {
                        out.push((flag.to_string(), value.clone()));
                    }
                }
            } else if let Some(value) = arg.strip_prefix(&format!("{flag}=")) {
                if !value.is_empty() {
                    out.push((flag.to_string(), value.to_string()));
                }
            }
        }
    }
    out
}

/// One enabled endpoint claim found in the read-only cross-pod scan.
struct EndpointClaim {
    pod: String,
    svc: String,
    key: String,
    value: String,
}

/// The enabled endpoint claims of ONE pod: its active generation's
/// recorded units, args scanned for endpoint flags and recorded options
/// for endpoint-ish keys. A pod with no store, no active generation, or
/// no recorded services contributes nothing — missing means no claims,
/// never an error.
fn pod_endpoint_claims(pod_dir: &std::path::Path) -> miette::Result<Vec<EndpointClaim>> {
    let store = RuntimeStore::new(pod_dir.to_path_buf());
    let Some(gen) = store.active_generation()? else {
        return Ok(Vec::new());
    };
    let Some(file) = read_units_file(&store, gen.n)? else {
        return Ok(Vec::new());
    };
    let pod = pod_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    // Comparison-time expansion (issue #107): the record keeps option
    // specifiers unexpanded, so two pods legally sharing the canonical
    // `data_dir = "%h/.local/share/<pkg>/%p"` template must not compare
    // as identical. The scan expands with the same semantics `record`
    // used — home = $HOME, pod = the directory name, `${ref}` against
    // the unit's own recorded options — and fails closed on an
    // unresolvable value: recorded values are never compared raw.
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let current = store.root().join(crate::farm::CURRENT_LINK);
    let ctx = ResolveCtx {
        pod: &pod,
        home: &home,
        extensions: current.join("extensions").to_string_lossy().into_owned(),
        gen_env: BTreeMap::new(), // expansion-only: env/loader-libs are render-time inputs
        loader_libs: Vec::new(),
        current: current.to_string_lossy().into_owned(),
        // Expansion-only context (the endpoint scan): the envfile path
        // is a render-time input and never participates in `${ref}`
        // expansion.
        secrets_envfile: None,
    };
    let mut claims = Vec::new();
    for unit in file.units {
        if !unit.enabled {
            continue;
        }
        for (key, value) in extract_endpoints(&unit.args) {
            claims.push(EndpointClaim {
                pod: pod.clone(),
                svc: unit.name.clone(),
                key,
                value,
            });
        }
        // Decision 9 also names data dirs, which need not appear in any
        // arg: endpoint-ish recorded option values join the claim set,
        // expanded (see above — issue #107).
        for (key, value) in &unit.options {
            if let (Some(family), Some(text)) = (endpoint_option_family(key), option_text(value)) {
                if text.is_empty() {
                    continue;
                }
                let mut resolving = Vec::new();
                let expanded = expand_specifiers(
                    &unit.name,
                    &format!("options.{key}"),
                    &text,
                    &unit.options,
                    &ctx,
                    &mut resolving,
                )?;
                claims.push(EndpointClaim {
                    pod: pod.clone(),
                    svc: unit.name.clone(),
                    key: family.to_string(),
                    value: expanded,
                });
            }
        }
    }
    Ok(claims)
}

/// The Decision 9 collision check: a read-only scan of every pod's
/// active generation under the same pod root, comparing ENABLED units'
/// resolved endpoints. Two enabled services in different pods resolving
/// the same (flag, value) pair is a hard error named in full —
/// comparison, not a registry: nothing is persisted across pods.
fn check_endpoint_collisions(root: &std::path::Path) -> miette::Result<()> {
    let mut claims = Vec::new();
    let entries = std::fs::read_dir(root)
        .map_err(|e| miette::miette!("scanning pod root {}: {e}", root.display()))?;
    for entry in entries {
        let path = entry
            .map_err(|e| miette::miette!("scanning pod root {}: {e}", root.display()))?
            .path();
        if path.is_dir() {
            claims.extend(pod_endpoint_claims(&path)?);
        }
    }
    for (i, a) in claims.iter().enumerate() {
        for b in &claims[i + 1..] {
            // The arg form (`--socket-path`) and the option form
            // (`socket_path`) are the same endpoint vocabulary —
            // normalize both before comparing.
            if a.pod != b.pod
                && endpoint_compare_key(&a.key) == endpoint_compare_key(&b.key)
                && a.value == b.value
            {
                miette::bail!(
                    "endpoint collision: pod '{}' service '{}' and pod '{}' service '{}' \
                     both run enabled with {} {} — two pods cannot share one endpoint; \
                     the generation flip already happened, so fix the collision \
                     (different ports/sockets, or keep one disabled — one provider \
                     pod, consumers with enabled = false — ADR-0032 Decision 9) and \
                     re-sync: the re-run converges",
                    a.pod,
                    a.svc,
                    b.pod,
                    b.svc,
                    a.key,
                    a.value
                );
            }
        }
    }
    Ok(())
}

/// Normalize an endpoint key for cross-shape comparison: the arg form
/// (`--socket-path`) and the recorded option family (`socket`) must
/// compare equal — strip flag dashes, fold to snake case, drop a
/// `_path` suffix.
fn endpoint_compare_key(key: &str) -> String {
    let norm = key
        .trim_start_matches('-')
        .to_ascii_lowercase()
        .replace('-', "_");
    match norm.strip_suffix("_path") {
        Some(stem) => stem.to_string(),
        None => norm,
    }
}

/// The endpoint-ish option families the recorded options are scanned
/// for (ADR-0032 Decision 9's vocabulary: port, socket path, data dir).
/// Token match on the normalized key, so `http_port` / `unix_socket` /
/// `data_dir` qualify while `transport` (which merely CONTAINS "port")
/// does not.
fn endpoint_option_family(key: &str) -> Option<&'static str> {
    let normalized = key.to_ascii_lowercase().replace('-', "_");
    let tokens: Vec<&str> = normalized.split('_').collect();
    let has = |t: &str| tokens.contains(&t);
    if has("port") {
        Some("port")
    } else if has("socket") {
        Some("socket")
    } else if has("datadir") || (has("data") && (has("dir") || has("directory") || has("path"))) {
        Some("data_dir")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::farm::ClaimLayer;
    use crate::runtime::InstalledPackage;
    use crate::snap::{ServiceDaemon, ServiceDecl};

    fn store_fixture(dir: &std::path::Path) -> RuntimeStore {
        // The documented pod layout `<data-home>/shuttle/pods/<pod>`:
        // pod_name derives from the root's last component, so a nested
        // fixture root keeps every write inside the test's tempdir.
        RuntimeStore::new(dir.join("shuttle/pods/pilot"))
    }

    fn decl(command: &str) -> ServiceDecl {
        ServiceDecl {
            command: command.into(),
            daemon: ServiceDaemon::Simple,
            args: vec![],
            options: BTreeMap::new(),
            after: vec![],
            environment: BTreeMap::new(),
            backend_options: BTreeMap::new(),
        }
    }

    fn pkg_with_services(
        name: &str,
        sha3: &str,
        services: Vec<(&str, ServiceDecl)>,
    ) -> InstalledPackage {
        InstalledPackage {
            name: name.to_string(),
            version: "1.0".into(),
            revision: 1,
            sha3_384: sha3.to_string(),
            files: vec![],
            units: vec![],
            layer: ClaimLayer::Own,
            apps: BTreeMap::new(),
            requires: Vec::new(),
            launchers: BTreeMap::new(),
            assembly: BTreeMap::new(),
            confined: None,
            app_confined: BTreeMap::new(),
            desktops: BTreeMap::new(),
            fonts: BTreeMap::new(),
            services: services
                .into_iter()
                .map(|(n, d)| (n.to_string(), d))
                .collect(),
            service_bins: BTreeMap::new(),
            meta_digest: None,
        }
    }

    fn gen_with(n: u64, pkgs: Vec<InstalledPackage>) -> Generation {
        let packages = pkgs.into_iter().map(|p| (p.name.clone(), p)).collect();
        Generation {
            n,
            base_version: "24.04".into(),
            packages,
            created_epoch: 0,
            boot_entry: None,
        }
    }

    fn home() -> String {
        std::env::var("HOME").unwrap_or_else(|_| ".".into())
    }

    fn units_of(store: &RuntimeStore, n: u64) -> Vec<ServiceUnit> {
        let body = std::fs::read(units_path(store, n)).unwrap();
        let file: UnitsFile = serde_json::from_slice(&body).unwrap();
        file.units
    }

    fn unit_dir(tmp: &tempfile::TempDir) -> std::path::PathBuf {
        let dir = tmp.path().join("config-home/systemd/user");
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn record_renders_full_unit_and_emits_the_link() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        let mut d = decl("bin/valkey-server");
        d.args = vec![
            "--port".into(),
            "${port}".into(),
            "--dir".into(),
            "%h/data/%p".into(),
            "--loadmodule".into(),
            "${extensions}/valkey-search.so".into(),
        ];
        d.options = [
            ("enabled".to_string(), serde_json::json!(true)),
            ("port".to_string(), serde_json::json!(7002)),
        ]
        .into_iter()
        .collect();
        d.environment.insert("QUIET".into(), "yes".into());
        let gen = gen_with(
            1,
            vec![pkg_with_services(
                "valkey",
                &"a".repeat(96),
                vec![("valkey", d)],
            )],
        );

        // The generation's recorded env plus a staged lib dir, as the
        // emit presents them before `record` runs.
        std::fs::create_dir_all(store.generation_dir(1)).unwrap();
        crate::farm::write_generation_env(
            &store,
            1,
            &[("EDITOR".to_string(), "vi".to_string())]
                .into_iter()
                .collect(),
        )
        .unwrap();
        std::fs::create_dir_all(
            store
                .generation_dir(1)
                .join("extensions/valkey/usr/usr/lib"),
        )
        .unwrap();

        record_in(&store, &gen, &BTreeMap::new(), "pilot", None).unwrap();

        let units = units_of(&store, 1);
        assert_eq!(units.len(), 1);
        let unit = &units[0];
        assert_eq!(unit.name, "valkey");
        assert!(unit.enabled);
        let current = store.root().join("current").to_string_lossy().into_owned();
        assert_eq!(unit.exec, format!("{current}/valkey"));

        let dir = unit_dir(&tmp);
        emit_in(&store, &gen, &dir, "pilot").unwrap();
        // The wipe must never consume the re-render source.
        assert_eq!(
            units_of(&store, 1).len(),
            1,
            "units.json survives its own emit"
        );
        let artifact = store
            .generation_dir(1)
            .join(SERVICES_DIR)
            .join("shuttle-pod-pilot-valkey.service");
        let text = std::fs::read_to_string(&artifact).unwrap();
        assert!(text.starts_with("[Unit]\n"));
        assert!(text.contains("Description=shuttle pod 'pilot' service 'valkey'\n"));
        assert!(text.contains("Type=simple\n"));
        assert!(text.contains(&format!(
            "ExecStart='{current}/valkey' '--port' '7002' '--dir' '{}/data/pilot' '--loadmodule' '{current}/extensions/valkey-search.so'\n",
            home()
        )));
        assert!(text.contains("Environment=\"QUIET=yes\"\n"));
        assert!(text.contains("Environment=\"EDITOR=vi\"\n"));
        assert!(text.contains(&format!(
            "Environment=\"LD_LIBRARY_PATH={current}/../extensions/valkey/usr/usr/lib\"\n"
        )));
        assert!(text.contains("Restart=on-failure\n"));
        assert!(text.contains("RestartSec=5\n"));
        assert!(text.contains("[Install]\nWantedBy=default.target\n"));
        // The enabled service's user link points at the generation artifact.
        let link = dir.join("shuttle-pod-pilot-valkey.service");
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            artifact,
            "the user link must target the generation's artifact"
        );
    }

    #[test]
    fn record_bakes_the_secrets_envfile_line_only_when_the_pod_declares_secrets() {
        // ADR-0042 D3/D7 (issue #184): secret-bearing units reference the
        // pod's 0600 runtime envfile by its MANDATORY path (no `-`
        // prefix — a missing file fails the start loud). A secret-less
        // pod gains no line at all.
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        let gen = gen_with(
            1,
            vec![pkg_with_services(
                "valkey",
                &"a".repeat(96),
                vec![("valkey", decl("bin/valkey-server"))],
            )],
        );
        std::fs::create_dir_all(store.generation_dir(1)).unwrap();

        let envfile = "/run/user/1000/shuttle/secrets/pilot/abc123.env";
        record_in(&store, &gen, &BTreeMap::new(), "pilot", Some(envfile)).unwrap();
        let unit = &units_of(&store, 1)[0];
        let expected = format!("EnvironmentFile=\"{envfile}\"\n");
        assert!(
            unit.text.contains(&expected),
            "the mandatory EnvironmentFile line must render verbatim:\n{}",
            unit.text
        );
        assert!(
            !unit.text.contains("EnvironmentFile=-"),
            "no `-` prefix: silent start-without-secrets is D7-forbidden\n{}",
            unit.text
        );
        // The path rides the unit TEXT (so a reference change moves the
        // unit hash through the normal diff), and the unit hash stays
        // package-only — no envfile content digest is folded in.
        // Rendering is deterministic in the path: a second record with
        // the same envfile produces byte-identical text.
        record_in(&store, &gen, &BTreeMap::new(), "pilot", Some(envfile)).unwrap();
        let again = &units_of(&store, 1)[0];
        assert_eq!(
            again.text, unit.text,
            "render is deterministic in the envfile path"
        );

        // Secret-less pods: no line, nothing that could fail a start.
        record_in(&store, &gen, &BTreeMap::new(), "pilot", None).unwrap();
        let unit = &units_of(&store, 1)[0];
        assert!(
            !unit.text.contains("EnvironmentFile"),
            "secret-less units must not reference an envfile:\n{}",
            unit.text
        );
    }

    #[test]
    fn units_carry_farm_first_path() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        let gen = gen_with(
            1,
            vec![pkg_with_services(
                "stack",
                &"d".repeat(96),
                vec![("wigolo", decl("usr/bin/wigolo"))],
            )],
        );
        record_in(&store, &gen, &BTreeMap::new(), "pilot", None).unwrap();
        let unit = &units_of(&store, 1)[0];
        let exec_line = unit
            .text
            .lines()
            .find(|l| l.starts_with("ExecStart="))
            .unwrap();
        let full = exec_line
            .trim_start_matches("ExecStart=")
            .trim_matches('\'');
        let current = full.strip_suffix("/wigolo").unwrap();
        // Farm-first PATH seam: bare-interpreter launchers (wigolo execs
        // `node`) resolve against the generation root; systemd's default
        // PATH does not carry it. Baked shape of the bootstrap unit (t13 §5.4).
        assert!(
            unit.text
                .contains(&format!("Environment=\"PATH={current}:/usr/bin:/bin\"\n")),
            "{}",
            unit.text
        );
    }

    #[test]
    fn record_resolves_after_targets_by_kind() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        let mut db = decl("bin/db");
        db.daemon = ServiceDaemon::Forking;
        let mut api = decl("bin/api");
        api.after = vec!["db".into(), "network.target".into()];
        let gen = gen_with(
            1,
            vec![pkg_with_services(
                "stack",
                &"b".repeat(96),
                vec![("api", api), ("db", db)],
            )],
        );
        record_in(&store, &gen, &BTreeMap::new(), "pilot", None).unwrap();
        let units = units_of(&store, 1);
        let api = units.iter().find(|u| u.name == "api").unwrap();
        let db = units.iter().find(|u| u.name == "db").unwrap();
        // A sibling shuttle service renders namespaced; an unknown target
        // (advisory) renders raw; the daemon kind maps to Type=.
        assert!(api.text.contains("After=shuttle-pod-pilot-db.service\n"));
        assert!(api.text.contains("After=network.target.service\n"));
        assert_eq!(db.text.matches("Type=forking").count(), 1);
    }

    #[test]
    fn unknown_interpolation_ref_fails_the_record() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        let mut d = decl("bin/x");
        d.args = vec!["${nope}".into()];
        let gen = gen_with(
            1,
            vec![pkg_with_services("p", &"c".repeat(96), vec![("x", d)])],
        );
        let err = format!(
            "{}",
            record_in(&store, &gen, &BTreeMap::new(), "pilot", None).unwrap_err()
        );
        assert!(err.contains("unknown '${nope}'"), "{err}");
    }

    #[test]
    fn backend_options_passthrough_lands_last() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        let mut d = decl("bin/x");
        d.backend_options.insert(
            "systemd".into(),
            serde_json::json!({ "Nice": 5, "UMask": "0022", "MemoryMax": "1G" }),
        );
        let gen = gen_with(
            1,
            vec![pkg_with_services("p", &"d".repeat(96), vec![("x", d)])],
        );
        record_in(&store, &gen, &BTreeMap::new(), "pilot", None).unwrap();
        let text = &units_of(&store, 1)[0].text;
        let passthrough_start = text.find("MemoryMax=1G\n").unwrap();
        assert!(
            text.find("RestartSec=5\n").unwrap() < passthrough_start,
            "passthrough must come after the fixed [Service] lines"
        );
        assert!(
            passthrough_start < text.find("[Install]").unwrap(),
            "passthrough must come before [Install]"
        );

        // A non-scalar passthrough value is a named render error.
        let mut bad = decl("bin/x");
        bad.backend_options
            .insert("systemd".into(), serde_json::json!({ "OOMPolicy": ["a"] }));
        let gen_bad = gen_with(
            2,
            vec![pkg_with_services("p", &"d".repeat(96), vec![("x", bad)])],
        );
        let err = format!(
            "{}",
            record_in(&store, &gen_bad, &BTreeMap::new(), "pilot", None).unwrap_err()
        );
        assert!(
            err.contains("must be a string, number, or boolean"),
            "{err}"
        );

        // A non-table systemd block is a named render error.
        let mut not_table = decl("bin/x");
        not_table
            .backend_options
            .insert("systemd".into(), serde_json::json!("oops"));
        let gen_nt = gen_with(
            3,
            vec![pkg_with_services(
                "p",
                &"d".repeat(96),
                vec![("x", not_table)],
            )],
        );
        let err = format!(
            "{}",
            record_in(&store, &gen_nt, &BTreeMap::new(), "pilot", None).unwrap_err()
        );
        assert!(err.contains("must be a table"), "{err}");
    }

    #[test]
    fn enabled_false_writes_artifact_without_link() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        // No `enabled` option at all: the materialized default is false.
        let gen = gen_with(
            1,
            vec![pkg_with_services(
                "p",
                &"e".repeat(96),
                vec![("x", decl("bin/x"))],
            )],
        );
        record_in(&store, &gen, &BTreeMap::new(), "pilot", None).unwrap();
        assert!(!units_of(&store, 1)[0].enabled);
        let dir = unit_dir(&tmp);
        emit_in(&store, &gen, &dir, "pilot").unwrap();
        assert!(
            store
                .generation_dir(1)
                .join(SERVICES_DIR)
                .join("shuttle-pod-pilot-x.service")
                .exists(),
            "the artifact is written even when disabled"
        );
        assert!(!dir.join("shuttle-pod-pilot-x.service").exists());
    }

    #[test]
    fn re_emit_after_removal_withdraws_the_stale_link() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        let mut d = decl("bin/x");
        d.options.insert("enabled".into(), serde_json::json!(true));
        let gen = gen_with(
            1,
            vec![pkg_with_services("p", &"f".repeat(96), vec![("x", d)])],
        );
        record_in(&store, &gen, &BTreeMap::new(), "pilot", None).unwrap();
        let dir = unit_dir(&tmp);
        emit_in(&store, &gen, &dir, "pilot").unwrap();
        assert!(dir.join("shuttle-pod-pilot-x.service").exists());

        // A re-record that no longer declares the service: the empty
        // units file IS what `record` produces then. The next emit
        // withdraws the stale link.
        let empty = serde_json::to_vec(&UnitsFile::default()).unwrap();
        std::fs::write(units_path(&store, 1), &empty).unwrap();
        emit_in(&store, &gen, &dir, "pilot").unwrap();
        assert!(!dir.join("shuttle-pod-pilot-x.service").exists());
    }

    #[test]
    fn missing_units_file_is_a_clean_withdraw_only_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        let gen = gen_with(1, vec![pkg_with_services("p", &"0".repeat(96), vec![])]);
        let dir = unit_dir(&tmp);
        let stale = dir.join("shuttle-pod-pilot-old.service");
        std::fs::write(&stale, b"stale").unwrap();
        emit_in(&store, &gen, &dir, "pilot").unwrap();
        assert!(!stale.exists(), "the stale link is withdrawn");
        assert!(
            !store.generation_dir(1).join(SERVICES_DIR).exists(),
            "no surface is created for a service-less generation"
        );
    }

    #[test]
    fn units_file_is_byte_stable_across_re_records() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        let mut d = decl("bin/x");
        d.options.insert("enabled".into(), serde_json::json!(true));
        d.args = vec!["--dir".into(), "%h/d/%p".into()];
        let gen = gen_with(
            1,
            vec![pkg_with_services("p", &"1".repeat(96), vec![("x", d)])],
        );
        record_in(&store, &gen, &BTreeMap::new(), "pilot", None).unwrap();
        let first = std::fs::read(units_path(&store, 1)).unwrap();
        record_in(&store, &gen, &BTreeMap::new(), "pilot", None).unwrap();
        let second = std::fs::read(units_path(&store, 1)).unwrap();
        assert_eq!(first, second, "re-record must be byte-identical");
    }

    #[test]
    fn backend_override_grammar_is_total() {
        assert_eq!(
            backend_from_override("systemd").unwrap(),
            ServiceBackend::Systemd
        );
        assert_eq!(
            backend_from_override("launchd").unwrap(),
            ServiceBackend::Launchd
        );
        assert_eq!(
            backend_from_override("portable").unwrap(),
            ServiceBackend::Portable
        );
        let err = format!("{}", backend_from_override("bogus").unwrap_err());
        assert!(
            err.contains("SHUTTLE_SERVICE_BACKEND") && err.contains("systemd"),
            "{err}"
        );
    }

    // ── Reconcile diff classifier (pure; ticket #107) ──

    fn unit(enabled: bool, hash: &str) -> ServiceUnit {
        ServiceUnit {
            name: "svc".into(),
            pkg: "p".into(),
            layer: ClaimLayer::Own,
            daemon: ServiceDaemon::Simple,
            enabled,
            exec: "/x/current/svc".into(),
            args: vec![],
            options: BTreeMap::new(),
            environment: BTreeMap::new(),
            after: vec![],
            text: String::new(),
            hash: hash.into(),
        }
    }

    fn applied(enabled: bool, hash: &str) -> AppliedUnit {
        AppliedUnit {
            hash: hash.into(),
            enabled,
            applied: true,
        }
    }

    #[test]
    fn unapplied_entries_replan_instead_of_diffing_clean() {
        use UnitAction::*;
        // An entry whose bus steps were skipped (systemctl missing) is
        // not a registration: re-plan from the live-link state, and
        // converge with the idempotent enable --now rather than a
        // bounce (the artifact already matches units.json).
        assert_eq!(
            classify_unit(
                Some(&AppliedUnit {
                    applied: false,
                    ..applied(true, "h")
                }),
                true,
                true,
                &unit(true, "h")
            ),
            Some(Activate),
            "skipped-run entry with a live link re-activates (enable --now), never diffs clean"
        );
        assert_eq!(
            classify_unit(
                Some(&AppliedUnit {
                    applied: false,
                    ..applied(true, "h")
                }),
                false,
                true,
                &unit(true, "h")
            ),
            Some(Activate),
            "skipped-run entry without a link activates"
        );
        assert_eq!(
            classify_unit(
                Some(&AppliedUnit {
                    applied: false,
                    ..applied(true, "h")
                }),
                true,
                true,
                &unit(false, "h")
            ),
            Some(Deactivate),
            "skipped-run disabled unit with a live link still withdraws"
        );
    }

    #[test]
    fn classifier_routes_every_state_times_unit_cell() {
        use UnitAction::*;
        // Applied entry present: enablement transitions win, then hash.
        assert_eq!(
            classify_unit(Some(&applied(false, "h")), false, true, &unit(true, "h")),
            Some(Activate),
            "newly-enabled activates"
        );
        assert_eq!(
            classify_unit(Some(&applied(true, "h")), true, true, &unit(false, "h")),
            Some(Deactivate),
            "newly-disabled deactivates"
        );
        assert_eq!(
            classify_unit(Some(&applied(true, "old")), true, true, &unit(true, "new")),
            Some(Restart),
            "hash move while enabled restarts (binary-only upgrade included)"
        );
        assert_eq!(
            classify_unit(Some(&applied(true, "h")), true, true, &unit(true, "h")),
            None,
            "unchanged enabled unit is a no-op"
        );
        assert_eq!(
            classify_unit(
                Some(&applied(false, "old")),
                false,
                true,
                &unit(false, "new")
            ),
            None,
            "hash move while dormant needs no bus action"
        );

        // Readable record, entry missing: a NEW unit — enabled
        // activates (link or not; the flip's emit may already have
        // placed it), disabled stays dormant (Decision 7).
        assert_eq!(
            classify_unit(None, false, true, &unit(true, "h")),
            Some(Activate),
            "new unit (no link) activates"
        );
        assert_eq!(
            classify_unit(None, true, true, &unit(true, "h")),
            Some(Activate),
            "new unit (link already placed by the emit) activates"
        );
        assert_eq!(
            classify_unit(None, true, true, &unit(false, "h")),
            None,
            "new disabled unit stays dormant"
        );

        // Record missing/corrupt: a live link is an unknown running
        // contract — conservative restart; without a link it is fresh.
        assert_eq!(
            classify_unit(None, true, false, &unit(true, "h")),
            Some(Restart),
            "missing state record + live link is conservatively CHANGED"
        );
        assert_eq!(
            classify_unit(None, false, false, &unit(true, "h")),
            Some(Activate),
            "missing state record, no link: fresh activation"
        );
        assert_eq!(
            classify_unit(None, true, false, &unit(false, "h")),
            Some(Deactivate),
            "unknown live registration on a now-disabled unit withdraws"
        );
        assert_eq!(
            classify_unit(None, false, false, &unit(false, "h")),
            None,
            "missing record, disabled, no link: nothing to do"
        );
    }

    #[test]
    fn endpoint_extractor_reads_both_arg_shapes() {
        let args: Vec<String> = ["--port", "6379", "--port=6380", "--socket", "/tmp/s.sock"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            extract_endpoints(&args),
            vec![
                ("--port".to_string(), "6379".to_string()),
                ("--port".to_string(), "6380".to_string()),
                ("--socket".to_string(), "/tmp/s.sock".to_string()),
            ]
        );
        // Exact flags only: a flag sharing a prefix is not an endpoint,
        // and a bare flag with no value contributes nothing.
        let tricky: Vec<String> = ["--portable", "--socket-path=/x", "--port"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            extract_endpoints(&tricky),
            vec![("--socket-path".to_string(), "/x".to_string())]
        );
    }

    #[test]
    fn endpoint_option_families_match_decision_9_vocabulary() {
        // Token match: port/socket/data-dir keys qualify; a key that
        // merely CONTAINS "port" ("transport") does not.
        assert_eq!(endpoint_option_family("port"), Some("port"));
        assert_eq!(endpoint_option_family("http_port"), Some("port"));
        assert_eq!(endpoint_option_family("listen-port"), Some("port"));
        assert_eq!(endpoint_option_family("transport"), None);
        assert_eq!(endpoint_option_family("socket"), Some("socket"));
        assert_eq!(endpoint_option_family("unix_socket"), Some("socket"));
        assert_eq!(endpoint_option_family("socket_path"), Some("socket"));
        assert_eq!(endpoint_option_family("data_dir"), Some("data_dir"));
        assert_eq!(endpoint_option_family("datadir"), Some("data_dir"));
        assert_eq!(endpoint_option_family("data-path"), Some("data_dir"));
        assert_eq!(endpoint_option_family("workspace"), None);
        assert_eq!(endpoint_option_family("log_dir"), None);
        // Cross-shape comparison: arg flag and option family collide.
        assert_eq!(endpoint_compare_key("--port"), endpoint_compare_key("port"));
        assert_eq!(
            endpoint_compare_key("--socket-path"),
            endpoint_compare_key("socket_path")
        );
        assert_ne!(
            endpoint_compare_key("--port"),
            endpoint_compare_key("socket")
        );
    }

    /// Seed a minimal pod dir whose active generation records `units`
    /// (manifest + units.json only — the scan reads nothing else).
    fn seed_scan_pod(root: &std::path::Path, name: &str, units: &[ServiceUnit]) {
        let pod = root.join(name);
        let gen_dir = pod.join("generations/1");
        std::fs::create_dir_all(gen_dir.join(SERVICES_DIR)).unwrap();
        std::fs::write(
            gen_dir.join("manifest.json"),
            serde_json::json!({
                "n": 1, "base_version": "24.04", "packages": {}, "created_epoch": 0
            })
            .to_string(),
        )
        .unwrap();
        std::os::unix::fs::symlink("generations/1", pod.join("active")).unwrap();
        std::fs::write(
            gen_dir.join(SERVICES_DIR).join(UNITS_FILE),
            serde_json::to_vec(&UnitsFile {
                units: units.to_vec(),
            })
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn endpoint_scan_reads_option_values_across_shapes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        // Decision 9 names data dirs: two pods sharing a data_dir
        // option value (invisible to the arg scan) collide.
        let mut dir_unit = unit(true, "h");
        dir_unit.name = "valkey".into();
        dir_unit
            .options
            .insert("data_dir".into(), serde_json::json!("%h/.local/share/x"));
        seed_scan_pod(root, "alpha", &[dir_unit.clone()]);
        seed_scan_pod(root, "beta", &[dir_unit]);
        let err = check_endpoint_collisions(root).unwrap_err().to_string();
        assert!(
            err.contains("alpha") && err.contains("beta") && err.contains("data_dir"),
            "{err}"
        );

        // Cross-shape: an arg `--port 6379` and an option port = 6379
        // are the same endpoint.
        let root2 = root.join("shapes");
        std::fs::create_dir_all(&root2).unwrap();
        let mut arg_unit = unit(true, "h");
        arg_unit.name = "svc".into();
        arg_unit.args = vec!["--port".into(), "6379".into()];
        let mut opt_unit = unit(true, "h");
        opt_unit.name = "svc".into();
        opt_unit
            .options
            .insert("port".into(), serde_json::json!(6379));
        seed_scan_pod(&root2, "alpha", &[arg_unit]);
        seed_scan_pod(&root2, "beta", &[opt_unit]);
        assert!(check_endpoint_collisions(&root2).is_err());

        // Different values never collide, and disabled units are
        // invisible to the scan (Decision 9 + Decision 7).
        let root3 = root.join("clean");
        std::fs::create_dir_all(&root3).unwrap();
        let mut a = unit(true, "h");
        a.options.insert("port".into(), serde_json::json!(6379));
        let mut b = unit(true, "h");
        b.options.insert("port".into(), serde_json::json!(6380));
        let mut c = unit(false, "h");
        c.options.insert("port".into(), serde_json::json!(6379));
        seed_scan_pod(&root3, "alpha", &[a]);
        seed_scan_pod(&root3, "beta", &[b, c]);
        check_endpoint_collisions(&root3).unwrap();
    }

    #[test]
    fn endpoint_scan_compares_resolved_option_values() {
        // Issue #107: recorded options keep specifiers unexpanded, so
        // the scan must expand at comparison time — raw text never
        // compares.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        // (1) The canonical per-pod template: identical raws carrying
        // %h/%p resolve to per-pod paths — NO collision, sync succeeds.
        let mut a = unit(true, "h");
        a.name = "valkey".into();
        a.options.insert(
            "data_dir".into(),
            serde_json::json!("%h/.local/share/shuttle/valkey/%p"),
        );
        seed_scan_pod(root, "alpha", &[a.clone()]);
        seed_scan_pod(root, "beta", &[a]);
        check_endpoint_collisions(root)
            .expect("identical raw templates with %h/%p must resolve to distinct per-pod dirs");

        // (2) Different raws resolving to the same path DO collide —
        // expansion must create detection, not only remove the false
        // positive. `${ref}` resolves in the scan scope too: alpha's
        // value references the `base` option.
        let root2 = root.join("resolved");
        std::fs::create_dir_all(&root2).unwrap();
        let mut refd = unit(true, "h");
        refd.name = "valkey".into();
        refd.options
            .insert("base".into(), serde_json::json!("%h/data"));
        refd.options
            .insert("data_dir".into(), serde_json::json!("${base}/db"));
        let mut literal = unit(true, "h");
        literal.name = "valkey".into();
        literal.options.insert(
            "data_dir".into(),
            serde_json::json!(format!("{}/data/db", home())),
        );
        seed_scan_pod(&root2, "alpha", &[refd]);
        seed_scan_pod(&root2, "beta", &[literal]);
        let err = check_endpoint_collisions(&root2).unwrap_err().to_string();
        assert!(
            err.contains("alpha") && err.contains("beta") && err.contains("data_dir"),
            "same resolved data_dir must collide, got: {err}"
        );

        // (3) Arg-form claims are unchanged: args are recorded already
        // resolved, and identical literal args still collide.
        let root3 = root.join("args");
        std::fs::create_dir_all(&root3).unwrap();
        let mut x = unit(true, "h");
        x.name = "svc".into();
        x.args = vec!["--socket-path".into(), "/run/svc.sock".into()];
        seed_scan_pod(&root3, "alpha", &[x.clone()]);
        seed_scan_pod(&root3, "beta", &[x]);
        assert!(
            check_endpoint_collisions(&root3).is_err(),
            "arg-form collisions must keep hard-erroring"
        );
    }

    #[test]
    fn linger_probe_rides_the_runtime_tools_seam() {
        // No loginctl on the seam → silent (SHUTTLE_POD_TOOLS=absent).
        let mut report = ServiceReconcileReport::default();
        check_linger(
            &crate::runtime::RuntimeTools::default(),
            "pilot",
            &mut report,
        );
        assert!(!report.linger_warned, "absent loginctl must stay silent");

        // A loginctl handed to the seam directly (no PATH involvement)
        // answering Linger=no → the warning.
        let tmp = tempfile::tempdir().unwrap();
        let loginctl = tmp.path().join("loginctl");
        std::fs::write(&loginctl, "#!/bin/sh\necho Linger=no\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&loginctl, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let tools = crate::runtime::RuntimeTools {
            loginctl: Some(loginctl),
            ..Default::default()
        };
        let mut report = ServiceReconcileReport::default();
        check_linger(&tools, "pilot", &mut report);
        assert!(report.linger_warned, "Linger=no must warn through the seam");
    }

    #[test]
    fn artifact_rewrite_is_crash_safe_and_prunes_stale_files() {
        // N12: the rewrite must never remove the recorded units file —
        // write-then-rename keeps it present at every instant, and the
        // final prune clears what the previous record left behind.
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        let mut d = decl("bin/x");
        d.options.insert("enabled".into(), serde_json::json!(true));
        let gen = gen_with(
            1,
            vec![pkg_with_services("p", &"2".repeat(96), vec![("x", d)])],
        );
        record_in(&store, &gen, &BTreeMap::new(), "pilot", None).unwrap();
        let dir = unit_dir(&tmp);
        emit_in(&store, &gen, &dir, "pilot").unwrap();

        // Leftovers an interrupted pass could leave: a stale artifact
        // for a withdrawn service and an orphaned temp file.
        let svc_dir = store.generation_dir(1).join(SERVICES_DIR);
        std::fs::write(svc_dir.join("shuttle-pod-pilot-gone.service"), "stale").unwrap();
        std::fs::write(svc_dir.join(format!(".{UNITS_FILE}.tmp")), "junk").unwrap();

        emit_in(&store, &gen, &dir, "pilot").unwrap();
        assert!(
            units_path(&store, 1).exists(),
            "units.json survives its own rewrite"
        );
        assert_eq!(units_of(&store, 1).len(), 1);
        assert!(svc_dir.join("shuttle-pod-pilot-x.service").exists());
        assert!(!svc_dir.join("shuttle-pod-pilot-gone.service").exists());
        assert!(
            !svc_dir.join(format!(".{UNITS_FILE}.tmp")).exists(),
            "the temp file must not outlive a successful emit"
        );
    }
}
