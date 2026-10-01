//! Build orchestration (#313): output resolution, input pinning, the
//! dependency scheduler, and the farm plumbing — moved verbatim from the
//! binary entry so the library owns the orchestration and the binary is
//! a thin match over the CLI enum (ADR-0051 sequencing, #313 → #316/#317).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::cache::PackageCache;
use crate::lock::{LockFile, SourceLockEntry};
use crate::snap::{PackageInput, SourceSpec};

// ── Package name resolution ──
// If file doesn't exist on disk, try resolving as a package name from
// local pkgs/ or from initialized input sources.

pub(crate) fn resolve_file(file: &str) -> miette::Result<String> {
    if Path::new(file).exists() {
        return Ok(file.to_string());
    }
    match crate::pkg_source::resolve_pkg(file) {
        crate::pkg_source::PkgResult::File(path) => Ok(path),
        crate::pkg_source::PkgResult::Found { path, content } => {
            eprintln!("  ℹ using package '{}' ({})", file, path);
            // Materialize into a fresh private temp dir (never the shared,
            // predictable $TMPDIR): the definition path's parent becomes the
            // eval/check resolver's allowlisted root, so it must be this
            // invocation's private directory only — never /tmp.
            let tmp = crate::pkg_source::materialize_embedded(&content)?;
            Ok(tmp.to_string_lossy().to_string())
        }
        crate::pkg_source::PkgResult::NotFound => Ok(file.to_string()),
    }
}

/// Evaluate a file path or resolved package source, returning snap outputs.
pub(crate) fn evaluate_file_or_embedded(file: &str) -> miette::Result<crate::lua::Outputs> {
    crate::lua::evaluate_file(file)
}

// ── Build command ──

/// Parse a size string like "500M" or "2G" into bytes.
fn parse_size(input: &str) -> Option<u64> {
    let input = input.trim();
    let (num, mult) = if let Some(n) = input.strip_suffix('G').or_else(|| input.strip_suffix('g')) {
        (n.parse::<u64>().ok()?, 1_000_000_000)
    } else if let Some(n) = input.strip_suffix('M').or_else(|| input.strip_suffix('m')) {
        (n.parse::<u64>().ok()?, 1_000_000)
    } else if let Some(n) = input.strip_suffix('K').or_else(|| input.strip_suffix('k')) {
        (n.parse::<u64>().ok()?, 1_000)
    } else {
        (input.parse::<u64>().ok()?, 1)
    };
    Some(num * mult)
}

/// Resolve a build's evaluated outputs under the #297 rules — shared by
/// [`cmd_build`] and the burst auto-count ([`wrapped_build_pending_jobs`],
/// #304) so sizing and building cannot drift: the config file's own eval
/// (its declared inputs) when it exists, a failing eval TERMINAL — the
/// fallback below exists only to resolve a package NAME (a nonexistent
/// positional) through the default input, and its plain eval never
/// validates the workers surface. Returns (outputs, workers config, file
/// label for diagnostics — resolved only in the fallback branch).
pub(crate) fn resolve_build_outputs(
    file: &str,
    update: Option<&str>,
    offline: bool,
    lockfile_path: &str,
) -> miette::Result<(crate::lua::Outputs, crate::lua::WorkersConfig, String)> {
    if Path::new(file).exists() {
        let eval = crate::lua::evaluate_file_with_inputs(file)
            .map_err(|e| miette::miette!("evaluating '{file}' failed: {e:#}"))?;
        let lockfile = prepare_inputs(&eval.global_inputs, lockfile_path, update, offline)?;
        crate::pkg_source::init_global_inputs_with(&eval.global_inputs, &lockfile.inputs, offline)?;
        Ok((eval.outputs, eval.workers, file.to_string()))
    } else {
        // No config file — use the default input and resolve the
        // positional as a package name. This is the ONLY fallback
        // (#297): the plain eval carries no workers surface, so the
        // inert default applies (ADR-0040 Decision 3).
        let default_inputs = default_input_map();
        let lockfile = prepare_inputs(&default_inputs, lockfile_path, update, offline)?;
        crate::pkg_source::init_global_inputs_with(&default_inputs, &lockfile.inputs, offline)?;
        let file = resolve_file(file)?;
        let all_outputs = evaluate_file_or_embedded(&file)?;
        Ok((all_outputs, crate::lua::WorkersConfig::default(), file))
    }
}

// Moved to nau-chart::pkg_source with the input vocabulary it names
// (issue #326). Re-exported so every
// `crate::build_orch::default_input_map` path keeps resolving.
pub use nau_chart::pkg_source::default_input_map;

/// Handle `--update` and first-build pin recording for package inputs,
/// saving the lockfile when it changed. Returns the lockfile to resolve
/// inputs against.
fn prepare_inputs(
    inputs: &HashMap<String, PackageInput>,
    lockfile_path: &str,
    update: Option<&str>,
    offline: bool,
) -> miette::Result<LockFile> {
    let lock_path = Path::new(lockfile_path);
    let mut lockfile = LockFile::load(lock_path)?.unwrap_or_else(|| LockFile {
        version: 1,
        sources: HashMap::new(),
        snaps: HashMap::new(),
        inputs: HashMap::new(),
        packages: HashMap::new(),
        build_deps: HashMap::new(),
    });

    let mut changed = false;
    if let Some(name) = update {
        // --update <input> refreshes one pin; bare --update refreshes all.
        let names: Vec<&str> = if name.is_empty() {
            Vec::new()
        } else {
            vec![name]
        };
        let updates = crate::pkg_source::update_input_pins(inputs, &names, &mut lockfile)?;
        for u in &updates {
            crate::output::status(pin_update_line(u));
        }
        changed |= !updates.is_empty();
    } else if !offline {
        // Record-once: pin inputs missing from the lockfile (first build).
        let n = crate::pkg_source::ensure_input_pins(inputs, &mut lockfile)?;
        changed |= n > 0;
    }

    if changed {
        lockfile.save(lock_path)?;
        crate::output::ok(format!("lockfile updated: {lockfile_path}"));
    }
    Ok(lockfile)
}

/// True when every arch `dep` will be built for is already cached under its
/// closure key. Replaces the old hardcoded `"amd64"` lookup, which could
/// serve a stale amd64 artifact for an aarch64 build of the same source.
fn dep_fully_cached(
    cache: &crate::cache::PackageCache,
    closure: &crate::cache::BuildClosure,
    dep_meta: &crate::snap::SnapMeta,
    cli_archs: &[String],
) -> bool {
    crate::snap::resolve_archs(dep_meta, cli_archs)
        .iter()
        .all(|a| cache.lookup(dep_meta, a, closure).is_some())
}

/// True when `given` names the same stage directory as the
/// nau-owned default (`./stage/`): by canonical path when both
/// exist (the live lock-holder's wipe window), else by components with
/// `.` separators dropped — so `./stage`, `stage`, and `./stage/` all
/// match even before the directory exists.
fn names_default_stage(given: &Path) -> bool {
    fn norm(p: &Path) -> Vec<std::path::Component<'_>> {
        p.components()
            .filter(|c| !matches!(c, std::path::Component::CurDir))
            .collect()
    }
    let default = Path::new("./stage/");
    if let (Ok(a), Ok(b)) = (given.canonicalize(), default.canonicalize()) {
        return a == b;
    }
    norm(given) == norm(default)
}

/// Resolve the `--stage` CLI flag into (path, policy) and enforce the
/// explicit-stage precondition: a user-chosen directory that already has
/// contents is refused up front — never wiped. The default `./stage/` is
/// additionally pinned by a cross-process advisory lock
/// ([`crate::snap::StageLock`], gate-pod gap 6): two concurrent builds
/// must not silently share it, so the second build refuses loudly and is
/// pointed at `--stage`. The lock is returned to the caller, which holds
/// it for the whole build; an explicit `--stage` is user-owned and never
/// locked.
fn resolve_stage(
    stage: Option<String>,
) -> miette::Result<(
    std::path::PathBuf,
    crate::snap::StagePolicy,
    Option<crate::snap::StageLock>,
)> {
    match stage {
        Some(path) => {
            // Council review: a spelling of the default stage must not
            // pose as a user-owned explicit stage — it would bypass the
            // StageLock the default carries and pass
            // check_explicit_stage during the lock-holder's wipe
            // window. Refuse loudly instead.
            if names_default_stage(Path::new(&path)) {
                miette::bail!(
                    "'{path}' is the default stage ('./stage/') — omit --stage \
                     to build there (pinned by the cross-process stage lock), or \
                     pass a different directory as --stage"
                );
            }
            let policy = crate::snap::StagePolicy::Explicit;
            crate::snap::check_explicit_stage(Path::new(&path))?;
            Ok((std::path::PathBuf::from(path), policy, None))
        }
        None => {
            let stage = std::path::PathBuf::from("./stage/");
            let lock = crate::snap::StageLock::acquire(&stage)?;
            Ok((stage, crate::snap::StagePolicy::Default, Some(lock)))
        }
    }
}

/// Inner build logic after outputs are resolved.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_build(
    all_outputs: crate::lua::Outputs,
    file: String,
    stage: Option<String>,
    output: String,
    arch: Vec<String>,
    output_name: Option<String>,
    source_date_epoch: Option<String>,
    lockfile_path: String,
    all: bool,
    cache: Option<String>,
    cache_max_size: Option<String>,
    target: Option<String>,
    json: bool,
    workers: crate::lua::WorkersConfig,
) -> miette::Result<()> {
    if let Some(ref epoch) = source_date_epoch {
        std::env::set_var("SOURCE_DATE_EPOCH", epoch);
    }

    let lock_path = Path::new(&lockfile_path);
    let mut lockfile = load_lockfile_or_default(lock_path)?;

    // Stage policy: an explicitly passed --stage belongs to the user — it
    // must be empty to start and is never wiped. The default ./stage/ is
    // nau-managed scratch, wiped before every build phase (snap.rs).
    // `_stage_lock` pins the default stage against concurrent builds for
    // this whole invocation (gate-pod gap 6): it must stay bound for the
    // rest of the function — dropping it releases the flock.
    let (stage_path, stage_policy, _stage_lock) = resolve_stage(stage)?;
    let stage_dir = std::path::Path::new(&stage_path);
    let output_dir = std::path::Path::new(&output);

    let pkg_cache = init_pkg_cache(all, cache, cache_max_size, json);

    let iter = select_outputs(&all_outputs, &output_name, &file, target.as_ref(), json)?;

    // If --all, resolve and build transitive dependencies first
    if all {
        let all_deps = collect_dep_graph(&iter);
        build_all_deps(
            &all_deps,
            target.as_ref(),
            pkg_cache.as_ref(),
            &arch,
            output_dir,
            &lockfile,
            json,
            &workers,
            stage_dir,
            stage_policy,
        )?;
    }

    let all_source_info = build_outputs(
        &iter,
        &arch,
        stage_dir,
        stage_policy,
        output_dir,
        pkg_cache.as_ref(),
        &lockfile,
        json,
    )?;

    persist_new_sources(
        &mut lockfile,
        lock_path,
        &all_source_info,
        &lockfile_path,
        json,
    )?;

    // Pin build-time-only dependencies into the lockfile (ADR-0018 Decision
    // 4, issue #22): the lockfile IS the build_deps pin record.
    persist_build_deps_pins(&mut lockfile, lock_path, &iter, &lockfile_path)?;

    Ok(())
}

/// Load the lockfile at `lock_path`, falling back to an empty v1 lockfile
/// when it does not exist yet.
pub(crate) fn load_lockfile_or_default(lock_path: &Path) -> miette::Result<LockFile> {
    Ok(LockFile::load(lock_path)?.unwrap_or_else(|| LockFile {
        version: 1,
        sources: HashMap::new(),
        snaps: HashMap::new(),
        inputs: HashMap::new(),
        packages: HashMap::new(),
        build_deps: HashMap::new(),
    }))
}

/// Initialize the binary cache when --cache/--cache-max-size was given or
/// --all is set; `None` means the build runs uncached.
pub(crate) fn init_pkg_cache(
    all: bool,
    cache: Option<String>,
    cache_max_size: Option<String>,
    json: bool,
) -> Option<crate::cache::PackageCache> {
    if !(all || cache.is_some() || cache_max_size.is_some()) {
        return None;
    }

    let mut pc = crate::cache::PackageCache::new(cache.map(std::path::PathBuf::from));
    if let Some(ref size_str) = cache_max_size {
        if let Some(bytes) = parse_size(size_str) {
            pc = pc.with_max_size(bytes);
            if !json {
                crate::output::info(format!("max cache size: {}", size_str));
            }
        } else if !json {
            crate::output::warn(format!("invalid cache size: {}", size_str));
        }
    }
    Some(pc)
}

/// Select the outputs to build: the --output-name pick when given, else
/// every output in the file. Applies --target to each selected meta
/// (announced once in text mode).
pub(crate) fn select_outputs<'a>(
    all_outputs: &'a crate::lua::Outputs,
    output_name: &'a Option<String>,
    file: &str,
    target: Option<&String>,
    json: bool,
) -> miette::Result<Vec<(&'a String, crate::snap::SnapMeta)>> {
    let iter: Vec<(&String, crate::snap::SnapMeta)> = match output_name {
        Some(name) => {
            let mut meta = all_outputs
                .get(name)
                .ok_or_else(|| miette::miette!("output '{}' not found in {}", name, file))?
                .clone();
            if let Some(t) = target {
                meta.target = Some(t.clone());
                if !json {
                    crate::output::info(format!("target: {t}"));
                }
            }
            vec![(name, meta)]
        }
        None => {
            let mut vec: Vec<(&String, crate::snap::SnapMeta)> = Vec::new();
            for (name, meta_ref) in all_outputs {
                let mut meta = meta_ref.clone();
                if let Some(t) = target {
                    meta.target = Some(t.clone());
                }
                vec.push((name, meta));
            }
            // `Outputs` is a HashMap: without a stable sort, multi-output
            // definitions build in nondeterministic order run to run.
            vec.sort_by_key(|(a, _)| *a);
            if let Some(t) = target {
                if !json {
                    crate::output::info(format!("target: {t}"));
                }
            }
            vec
        }
    };
    Ok(iter)
}

/// Collect the unique dependency names of every selected output, in
/// first-seen order. Seeds are the build-time dependency union
/// (`requires` ∪ `build_deps`) — both kinds get built (ADR-0018).
pub(crate) fn collect_dep_graph(
    iter: &[(&String, crate::snap::SnapMeta)],
) -> Vec<crate::deps::DepNode> {
    let mut nodes: Vec<crate::deps::DepNode> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (_name, meta) in iter {
        let seeds = crate::deps::build_dep_seeds(meta);
        if !seeds.is_empty() {
            if let Ok(deps) = crate::deps::resolve_deps(&seeds, true) {
                for node in deps {
                    if seen.insert(node.name.clone()) {
                        nodes.push(node);
                    }
                }
            }
        }
    }
    nodes
}

/// Resolve `meta`'s build-time dependency closure (`requires` ∪
/// `build_deps`, transitively), ensure every member's built payload is
/// available, and materialize the merged `/usr`-like build prefix
/// (ADR-0018 Decision 2, issue #17). Returns `None` when the package runs
/// no build or declares neither list — nothing to bind into the sandbox.
///
/// Unknown dependency names reject exactly like unknown `requires` names:
/// the resolver's "package 'x' not found" error propagates.
///
/// `quiet` suppresses the progress line (parallel dep builds, issue #55 —
/// the scheduler prints attributable lines instead).
#[allow(clippy::too_many_arguments)]
fn ensure_build_prefix(
    meta: &crate::snap::SnapMeta,
    arch: &str,
    output_dir: &Path,
    pkg_cache: Option<&PackageCache>,
    lockfile: &LockFile,
    json: bool,
    quiet: bool,
    building: &mut Vec<String>,
    run_stage: &Path,
    run_stage_policy: crate::snap::StagePolicy,
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
    let closure_names = crate::deps::resolve_dep_names(&seeds, true)?;
    let mut payloads = Vec::new();
    for name in closure_names {
        let dep_meta = crate::deps::load_meta(&name)?;
        let snap = ensure_dep_payload(
            &name,
            &dep_meta,
            arch,
            output_dir,
            pkg_cache,
            lockfile,
            json,
            quiet,
            building,
            run_stage,
            run_stage_policy,
        )?;
        payloads.push(crate::build_prefix::Payload { pkg: name, snap });
    }
    let merged = crate::build_prefix::materialize_merged_prefix(&payloads)?;
    if !json && !quiet && !payloads.is_empty() {
        let names: Vec<&str> = payloads.iter().map(|p| p.pkg.as_str()).collect();
        crate::output::status(format!(
            "build prefix: merged {} payload(s) — {}",
            payloads.len(),
            names.join(", ")
        ));
    }
    Ok(Some(merged))
}

/// Ensure one dependency's built payload is available for the merged build
/// prefix: the output dir first (a previous build or `--all` may have
/// produced it), then the binary cache, else build it now — giving the
/// dependency its own merged prefix first, because its build may need its
/// own build-time deps (ADR-0018 applies to every source build).
///
/// `building` is the in-progress stack for cycle detection: a circular
/// requires/build_deps chain cannot be materialized and fails with a clear
/// chain instead of recursing forever.
#[allow(clippy::too_many_arguments)]
fn ensure_dep_payload(
    name: &str,
    dep_meta: &crate::snap::SnapMeta,
    arch: &str,
    output_dir: &Path,
    pkg_cache: Option<&PackageCache>,
    lockfile: &LockFile,
    json: bool,
    quiet: bool,
    building: &mut Vec<String>,
    run_stage: &Path,
    run_stage_policy: crate::snap::StagePolicy,
) -> miette::Result<PathBuf> {
    let filename = format!("{}_{}_{}.snap", name, dep_meta.version, arch);
    let in_output = output_dir.join(&filename);
    if in_output.exists() {
        return Ok(in_output);
    }

    // Closure key for the cache lookup/store (same computation the --all
    // dep path uses).
    let closure = pkg_cache.map(|_| crate::coordinator::build_closure(dep_meta, lockfile));
    if let (Some(cache), Some(closure)) = (pkg_cache, closure.as_ref()) {
        if let Some(cached) = cache.lookup(dep_meta, arch, closure) {
            return Ok(cached);
        }
    }

    if building.iter().any(|n| n == name) {
        miette::bail!(
            "circular dependency while building '{name}': {} → {name}",
            building.join(" → ")
        );
    }
    building.push(name.to_string());

    let dep_prefix = ensure_build_prefix(
        dep_meta,
        arch,
        output_dir,
        pkg_cache,
        lockfile,
        json,
        quiet,
        building,
        run_stage,
        run_stage_policy,
    )?;

    crate::snap::check_cross_build(arch, dep_meta.target.as_deref())?;
    if !json && !quiet {
        crate::output::status(format!("building dependency {name} ({arch})..."));
    }
    // #310: stage-only deps pack the run's resolved stage; the rest keep
    // the private scratch they always had.
    let stage = resolve_dep_stage(dep_meta, run_stage)?;
    let scan_listings = match &dep_prefix {
        Some(p) => crate::leak_scan::listings_for_build(dep_meta, p)?,
        None => crate::leak_scan::PayloadListings::default(),
    };

    let result = crate::snap::build_snap(
        dep_meta,
        stage.path(),
        output_dir,
        arch,
        stage.policy(run_stage_policy),
        // Dependency builds have no pod store and no interpreted closure.
        None,
        None,
        dep_prefix.as_ref().map(|t| t.path()),
        Some(&scan_listings),
        // Not a drift-observation point.
        false,
    )?;
    if !json && !quiet {
        crate::output::ok(&result.snap_filename);
    }
    if let (Some(cache), Some(closure)) = (pkg_cache, closure.as_ref()) {
        let _store_lock = CACHE_STORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = cache.store(dep_meta, &result, output_dir, closure) {
            crate::output::warn(format!("cache store failed: {e}"));
        }
    }

    building.pop();
    Ok(output_dir.join(&result.snap_filename))
}

/// Per-package parallel build job context (issue #55): everything one
/// ready-node build borrows from the orchestrator. Fields are read-only
/// for the whole phase; the scheduler runs one `run` per node.
struct DepJobCtx<'a> {
    metas: &'a BTreeMap<String, crate::snap::SnapMeta>,
    closures: &'a HashMap<String, Option<crate::cache::BuildClosure>>,
    cli_archs: &'a [String],
    output_dir: &'a Path,
    pkg_cache: Option<&'a crate::cache::PackageCache>,
    lockfile: &'a LockFile,
    json: bool,
    total: usize,
    dispatch: &'a AtomicUsize,
    /// The run's resolved stage (#310): stage-only deps pack it; the
    /// farm plan carries it so remote stage-only dispatches ship the
    /// content.
    run_stage: &'a Path,
    run_stage_policy: crate::snap::StagePolicy,
    /// Executor name stamped into the scheduler prefixes (ADR-0040
    /// Decision 4): `local` until the SSH executor integrates.
    executor: &'a str,
}

impl DepJobCtx<'_> {
    /// Build one scheduled package: attributable start/finish lines here,
    /// quiet build inside, error prefixed per line for the final report.
    fn run(&self, name: &str) -> Result<(), String> {
        let meta = self.metas.get(name).expect("scheduled node was loaded");
        let archs = crate::snap::resolve_archs(meta, self.cli_archs);
        let dep_closure = self.closures[name].as_ref();
        let slot = self.dispatch.fetch_add(1, Ordering::SeqCst) + 1;
        if !self.json {
            eprintln!(
                "▶ [{} {slot}/{}] {name} ({})",
                self.executor,
                self.total,
                archs.join(", ")
            );
        }
        match build_dep_archs(
            name,
            meta,
            &archs,
            self.output_dir,
            self.pkg_cache,
            dep_closure,
            self.lockfile,
            self.json,
            true,
            self.run_stage,
            self.run_stage_policy,
        ) {
            Ok(()) => {
                if !self.json {
                    eprintln!("✓ [{} {slot}/{}] {name}", self.executor, self.total);
                }
                Ok(())
            }
            Err(e) => Err(prefix_error_lines(&format!("{e:#}"), name)),
        }
    }
}

/// Load every node's meta up front, in topological order, applying
/// `--target`. A node whose meta cannot load is skipped with a warning,
/// as the sequential loop did.
fn load_dep_metas(
    dep_nodes: &[crate::deps::DepNode],
    effective_target: Option<&String>,
) -> BTreeMap<String, crate::snap::SnapMeta> {
    let mut metas = BTreeMap::new();
    for node in dep_nodes {
        match crate::deps::load_meta(&node.name) {
            Ok(mut m) => {
                // Apply --target to deps as well
                if let Some(t) = effective_target {
                    m.target = Some(t.clone());
                }
                metas.insert(node.name.clone(), m);
            }
            Err(e) => {
                crate::output::warn(format!("skipping dependency '{}': {}", node.name, e));
            }
        }
    }
    metas
}

/// Closure key per node (source + parts + target + requires closure):
/// computed up front on the orchestrator thread — `build_closure`
/// re-resolves the dep closure through the isolate worker, and evals stay
/// sequential. Both the cache checks and the per-dep cache store use it.
fn precompute_dep_closures(
    metas: &BTreeMap<String, crate::snap::SnapMeta>,
    pkg_cache: Option<&crate::cache::PackageCache>,
    lockfile: &LockFile,
) -> HashMap<String, Option<crate::cache::BuildClosure>> {
    metas
        .iter()
        .map(|(name, meta)| {
            (
                name.clone(),
                pkg_cache.map(|_| crate::coordinator::build_closure(meta, lockfile)),
            )
        })
        .collect()
}

/// Names whose every resolved arch is already cached under their closure
/// key: complete before scheduling starts, releasing dependents at once.
/// (The check reads only the dep's own closure key, so checking here
/// equals checking just before its build — nothing else writes its
/// entries.) `quiet` silences the "(cached)" lines — the burst's sizing
/// (#304) must not emit build progress; the build passes its `json` flag,
/// which is exactly this switch.
fn cached_dep_names(
    metas: &BTreeMap<String, crate::snap::SnapMeta>,
    closures: &HashMap<String, Option<crate::cache::BuildClosure>>,
    pkg_cache: Option<&crate::cache::PackageCache>,
    cli_archs: &[String],
    quiet: bool,
) -> HashSet<String> {
    let mut cached = HashSet::new();
    for (name, meta) in metas {
        if let (Some(cache), Some(closure)) = (pkg_cache, closures[name].as_ref()) {
            if dep_fully_cached(cache, closure, meta, cli_archs) {
                cached.insert(name.clone());
                if !quiet {
                    crate::output::ok(format!("{} (cached)", name));
                }
            }
        }
    }
    cached
}

/// The [`dep_pending`] result: metas by name, their precomputed closure
/// keys, and the fully-cached names.
type DepPending = (
    BTreeMap<String, crate::snap::SnapMeta>,
    HashMap<String, Option<crate::cache::BuildClosure>>,
    HashSet<String>,
);

/// The pending computation shared by `build_all_deps` (the build path)
/// and the burst auto-count ([`pending_dep_jobs`], #304): dep metas
/// loaded with `--target` applied, closure keys precomputed, and the
/// fully-cached names subtracted. Sized by the burst; scheduled by the
/// build — one computation, no drift.
pub(crate) fn dep_pending(
    dep_nodes: &[crate::deps::DepNode],
    effective_target: Option<&String>,
    pkg_cache: Option<&crate::cache::PackageCache>,
    cli_archs: &[String],
    lockfile: &LockFile,
    quiet: bool,
) -> DepPending {
    let metas = load_dep_metas(dep_nodes, effective_target);
    let closures = precompute_dep_closures(&metas, pkg_cache, lockfile);
    let pre_done = cached_dep_names(&metas, &closures, pkg_cache, cli_archs, quiet);
    (metas, closures, pre_done)
}

/// Resolve and build every transitive dependency of the selected outputs
/// (--all mode), consulting the binary cache per dep when one is active.
///
/// Parallel across packages (issue #55, ADR-0022 Decision 3): the graph
/// from `deps.rs` is scheduled by [`crate::build_sched`] — every READY
/// node builds concurrently up to the pool budget,
/// [`crate::build_sched::pool_budget`] of the `workers` config
/// (ADR-0040 Decision 4; no `workers` table = the fixed three), and
/// dependents wake as their last dependency completes. Jobs dispatch
/// through the local executor seam. Build isolation is unchanged: each
/// package still builds in its own tempdir stage inside its own bwrap
/// sandbox (`env_clear` + explicit PATH, ADR-0004) with its own leak scan.
/// The Lua-eval isolate worker (issue #76 stderr cap + wall deadline) is
/// never run concurrently — metas and closures are resolved below, on the
/// orchestrator thread, before scheduling.
///
/// Failure semantics change on purpose (issue #55): a failed package fails
/// the run (nonzero) and its dependents never start — the sequential loop
/// used to warn and keep building garbage.
#[allow(clippy::too_many_arguments)]
fn build_all_deps(
    dep_nodes: &[crate::deps::DepNode],
    effective_target: Option<&String>,
    pkg_cache: Option<&crate::cache::PackageCache>,
    cli_archs: &[String],
    output_dir: &Path,
    lockfile: &LockFile,
    json: bool,
    workers: &crate::lua::WorkersConfig,
    run_stage: &Path,
    run_stage_policy: crate::snap::StagePolicy,
) -> miette::Result<()> {
    if dep_nodes.is_empty() {
        return Ok(());
    }
    let (metas, closures, pre_done) = dep_pending(
        dep_nodes,
        effective_target,
        pkg_cache,
        cli_archs,
        lockfile,
        json,
    );
    if metas.is_empty() {
        return Ok(());
    }

    // Scheduling graph: declared deps of each loaded node. The scheduler
    // drops self-edges (issue #33 self-host marker) and edges to names
    // outside the closure, exactly like `topological_sort`.
    let graph: BTreeMap<String, Vec<String>> = metas
        .iter()
        .map(|(name, meta)| {
            (
                name.clone(),
                meta.requires
                    .iter()
                    .chain(&meta.build_deps)
                    .cloned()
                    .collect(),
            )
        })
        .collect();

    let to_build = metas.len() - pre_done.len();
    if to_build == 0 {
        return Ok(());
    }
    let max_workers = crate::build_sched::pool_budget(workers);
    if !json {
        eprintln!(
            "── Building {to_build} dependencies (up to {} in parallel) ──",
            max_workers.min(to_build),
        );
    }

    // Scoped output discipline for the parallel phase (issue #55): worker
    // builds hold their progress output; `DepJobCtx::run` prints the
    // attributable per-package lines, and build-child stderr is buffered
    // per package instead of streaming into other packages' output. Both
    // flags are set once around the whole phase — the orchestrator thread
    // blocks inside `run_ready_set` — and restored before returning.
    crate::output::set_quiet_build(true);
    crate::snap::set_buffer_child_stderr(true);
    let dispatch = AtomicUsize::new(0);

    // The build invocation IS the coordinator (ADR-0040 Decision 4):
    // with a declared `workers` table the same ready set schedules
    // across the local slots and one SSH channel per worker. No
    // `workers` table keeps today's single-executor path, byte for byte.
    let scheduled = if workers.workers.is_empty() {
        let ctx = DepJobCtx {
            metas: &metas,
            closures: &closures,
            cli_archs,
            output_dir,
            pkg_cache,
            lockfile,
            json,
            total: to_build,
            dispatch: &dispatch,
            run_stage,
            run_stage_policy,
            executor: "local",
        };
        let executor = crate::build_sched::LocalExecutor::new(|name| ctx.run(name));
        crate::build_sched::run_ready_set_with_executor(&graph, &pre_done, max_workers, &executor)
            .map(|()| crate::build_sched::FarmOutcome {
                result: Ok(()),
                workers_lost: Vec::new(),
            })
            .unwrap_or_else(|failed| crate::build_sched::FarmOutcome {
                result: Err(failed),
                workers_lost: Vec::new(),
            })
    } else {
        let ctx = DepJobCtx {
            metas: &metas,
            closures: &closures,
            cli_archs,
            output_dir,
            pkg_cache,
            lockfile,
            json,
            total: to_build,
            dispatch: &dispatch,
            run_stage,
            run_stage_policy,
            executor: "local",
        };
        run_farm(&ctx, &graph, &pre_done, workers)
            .unwrap_or_else(|e| refused_run(&graph, &format!("{e:#}")))
    };
    crate::snap::set_buffer_child_stderr(false);
    crate::output::set_quiet_build(false);

    match scheduled.result {
        Ok(()) => {
            if !scheduled.workers_lost.is_empty() {
                crate::output::warn(format!(
                    "worker(s) lost during the run (affected jobs re-dispatched and \
                     completed): {} — the escape hatch is removing the worker from the \
                     `workers` table, not retrying",
                    scheduled.workers_lost.join(", ")
                ));
            }
            Ok(())
        }
        Err(failed) => Err(report_failed_builds(&failed, &scheduled.workers_lost)),
    }
}

/// Prefix every line of a failed package's error with the package name, so
/// the buffered build output stays attributable in the final report.
fn prefix_error_lines(err: &str, name: &str) -> String {
    let prefix = format!("[{name}] ");
    err.lines()
        .map(|line| format!("{prefix}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render the scheduler's failed/skipped sets as the run's error: the run
/// exits nonzero, naming what failed and what was never started because of
/// it. The farm path adds the workers lost along the way — every failure
/// names its worker, and the summary names every worker the run lost.
fn report_failed_builds(
    failed: &crate::build_sched::FailedBuilds,
    workers_lost: &[String],
) -> miette::Error {
    let names: Vec<String> = failed.failed.iter().map(|(n, _)| n.clone()).collect();
    let mut msg = format!(
        "{} package build(s) failed: {}",
        failed.failed.len(),
        names.join(", ")
    );
    if !workers_lost.is_empty() {
        msg.push_str(&format!(
            "\nworkers lost during the run: {}",
            workers_lost.join(", ")
        ));
    }
    if !failed.skipped.is_empty() {
        msg.push_str(&format!(
            "\nskipped (failed or unschedulable dependency): {}",
            failed.skipped.join(", ")
        ));
    }
    for (name, err) in &failed.failed {
        msg.push_str(&format!("\n--- {name} ---\n{err}"));
    }
    miette::miette!("{}", msg)
}

/// Assemble the farm (local slots + one channel per worker), preflight
/// every worker (a config error refuses the run before any build
/// starts, named by worker and probe — the escape hatch is removing
/// the worker from config), and schedule the ready set across it.
fn run_farm(
    ctx: &DepJobCtx<'_>,
    graph: &BTreeMap<String, Vec<String>>,
    pre_done: &HashSet<String>,
    workers: &crate::lua::WorkersConfig,
) -> miette::Result<crate::build_sched::FarmOutcome> {
    // Preflight first, sequentially, before anything dispatches: a
    // refused worker (arch mismatch, unpinned, unreachable, protocol
    // drift, sandbox) is a config error that kills the run before an
    // hours-long build starts. The refusal names the worker and the
    // failed probe. The entry's declared arch rides the check, so a
    // declared-vs-reported mismatch refuses here rather than mid-run,
    // per dispatch, after other work has gone out (#193 review F1).
    let executors: Vec<crate::ssh_exec::SshExecutor<crate::command::RealRunner>> = workers
        .workers
        .iter()
        .map(|w| crate::ssh_exec::SshExecutor::new(w, crate::command::RealRunner))
        .collect::<miette::Result<_>>()?;
    if let Err(e) = crate::coordinator::preflight_farm_workers(&executors) {
        let text = format!("{e:#}");
        return Ok(refused_run(graph, &text));
    }

    let plans = match crate::coordinator::precompute_farm_plans(
        ctx.metas,
        ctx.cli_archs,
        ctx.lockfile,
        ctx.output_dir,
        ctx.pkg_cache,
        Some(ctx.run_stage),
    ) {
        Ok(x) => x,
        Err(e) => {
            // A precompute failure is a pre-run refusal: nothing
            // dispatched, everything unstarted, reason named.
            return Ok(refused_run(graph, &format!("{e:#}")));
        }
    };

    let epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.parse::<i64>().ok());
    let crate::coordinator::FarmPlans {
        plans,
        dep_metas,
        dep_closures,
        caps,
        local_held,
    } = plans;
    let source = std::sync::Arc::new(crate::coordinator::FarmSource {
        plans,
        dep_metas,
        dep_closures,
        lockfile: ctx.lockfile,
        output_dir: ctx.output_dir,
        pkg_cache: ctx.pkg_cache,
        json: ctx.json,
        epoch,
        runner: crate::command::RealRunner,
    });

    let local = crate::build_sched::Slotted {
        // #309: the local member joins holder consideration with the
        // coordinator's own resolvable set — locally-held nodes get the
        // preference and the reservation instead of the racy fallback.
        exec: crate::build_sched::LocalExecutor::with_held(|name| ctx.run(name), local_held),
        slots: workers.local_jobs as usize,
        display: "local".into(),
    };

    let remote: Vec<crate::build_sched::RemoteExecutor<crate::command::RealRunner, _>> = executors
        .into_iter()
        .zip(&workers.workers)
        .map(|(exec, w)| {
            crate::build_sched::RemoteExecutor::new(
                exec,
                std::sync::Arc::clone(&source),
                w.jobs as usize,
                ctx.total,
            )
        })
        .collect();

    let mut farm: Vec<crate::build_sched::FarmExecutor<'_>> =
        vec![crate::build_sched::FarmExecutor {
            job: &local,
            kind: crate::build_sched::ExecutorKind::Local,
        }];
    for (re, w) in remote.iter().zip(&workers.workers) {
        farm.push(crate::build_sched::FarmExecutor {
            job: re,
            kind: crate::build_sched::ExecutorKind::Worker {
                declared_arch: w.arch.clone(),
            },
        });
    }

    // The banner needs the assembled pool: the blind clause names
    // store-unknown worker members (#307 — fail-open placement must be
    // visible, not silent).
    if !ctx.json {
        let roster: Vec<String> = workers
            .workers
            .iter()
            .map(|w| {
                let arch = w
                    .arch
                    .as_deref()
                    .map(|a| format!(", {a}"))
                    .unwrap_or_default();
                format!(
                    "{} ({} job{}){arch}",
                    w.address,
                    w.jobs,
                    if w.jobs == 1 { "" } else { "s" }
                )
            })
            .collect();
        crate::output::status(format!(
            "farm: {} worker(s): {} — placement by arch, then store preference, then ready-set order{}",
            workers.workers.len(),
            roster.join(", "),
            crate::build_sched::placement_blind_clause(&farm)
        ));
    }

    Ok(crate::build_sched::run_ready_set_farm(
        graph, pre_done, &farm, &caps,
    ))
}

/// A pre-run refusal: the run fails before anything dispatched, every
/// node unstarted, the reason named.
fn refused_run(
    graph: &BTreeMap<String, Vec<String>>,
    reason: &str,
) -> crate::build_sched::FarmOutcome {
    crate::build_sched::FarmOutcome {
        result: Err(crate::build_sched::FailedBuilds {
            failed: vec![("(coordinator preflight)".to_string(), reason.to_string())],
            skipped: graph.keys().cloned().collect(),
        }),
        workers_lost: Vec::new(),
    }
}

/// Serializes pool-cache stores during the parallel dep-build phase (issue
/// #55): `store` prunes the shared cache directory when a max size is set,
/// and concurrent prunes would race directory mutations. Lookups stay
/// lock-free (read-only).
static CACHE_STORE_LOCK: Mutex<()> = Mutex::new(());

/// Build one dependency across its resolved archs, storing each artifact in
/// the binary cache when one is active. Each arch's build gets the merged
/// build prefix of its own build-time deps (ADR-0018 applies to every
/// source build, dependencies included).
///
/// `quiet` suppresses the per-package progress lines (the parallel
/// scheduler prints attributable ones, issue #55). A failed arch fails the
/// package: under the parallel scheduler a failed package's dependents
/// never start, so warning-and-continuing would build them against a
/// missing payload.
#[allow(clippy::too_many_arguments)]
fn build_dep_archs(
    dep_name: &str,
    dep_meta: &crate::snap::SnapMeta,
    dep_archs: &[String],
    output_dir: &Path,
    pkg_cache: Option<&crate::cache::PackageCache>,
    dep_closure: Option<&crate::cache::BuildClosure>,
    lockfile: &LockFile,
    json: bool,
    quiet: bool,
    run_stage: &Path,
    run_stage_policy: crate::snap::StagePolicy,
) -> miette::Result<()> {
    for a in dep_archs {
        crate::snap::check_cross_build(a, dep_meta.target.as_deref())?;
        if !json && !quiet {
            crate::output::status(format!("building {} ({})...", dep_name, a));
        }
        // #310: stage-only deps pack the run's resolved stage; the rest
        // keep the private scratch they always had.
        let dep_stage = resolve_dep_stage(dep_meta, run_stage)?;

        let mut building: Vec<String> = vec![dep_name.to_string()];
        let build_prefix = ensure_build_prefix(
            dep_meta,
            a,
            output_dir,
            pkg_cache,
            lockfile,
            json,
            quiet,
            &mut building,
            run_stage,
            run_stage_policy,
        )?;

        let scan_listings = match &build_prefix {
            Some(p) => crate::leak_scan::listings_for_build(dep_meta, p)?,
            None => crate::leak_scan::PayloadListings::default(),
        };

        match crate::snap::build_snap(
            dep_meta,
            dep_stage.path(),
            output_dir,
            a,
            dep_stage.policy(run_stage_policy),
            None,
            // Plain recursive builds have no pod dependency closure.
            None,
            build_prefix.as_ref().map(|p| p.path()),
            Some(&scan_listings),
            // Not a drift-observation point.
            false,
        ) {
            Ok(result) => {
                if !json && !quiet {
                    crate::output::ok(&result.snap_filename);
                }
                if let (Some(cache), Some(closure)) = (pkg_cache, dep_closure) {
                    let _store_lock = CACHE_STORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                    if let Err(e) = cache.store(dep_meta, &result, output_dir, closure) {
                        crate::output::warn(format!("cache store failed: {}", e));
                    }
                }
            }
            Err(e) => {
                return Err(miette::miette!("arch {a}: {e}"));
            }
        }
    }
    Ok(())
}

/// The stage a dep build packs into (#310): a stage-only recipe packs
/// the run's resolved stage — `run_build` never populates that stage,
/// so its content IS the recipe's declaration — while anything with a
/// build phase keeps its own private scratch: wiping the shared stage
/// would destroy the user's pre-staged content, and dep builds run
/// concurrently (#55).
enum DepStage<'a> {
    Shared(&'a Path),
    Private(tempfile::TempDir),
}

impl DepStage<'_> {
    fn path(&self) -> &Path {
        match self {
            DepStage::Shared(p) => p,
            DepStage::Private(t) => t.path(),
        }
    }

    /// The shared stage rides the run's own policy (the same resolution
    /// the parent build uses); a private stage is nau-owned scratch.
    fn policy(&self, run_policy: crate::snap::StagePolicy) -> crate::snap::StagePolicy {
        match self {
            DepStage::Shared(_) => run_policy,
            DepStage::Private(_) => crate::snap::StagePolicy::Default,
        }
    }
}

/// Which stage one dependency build packs into (#310): the run's
/// resolved stage for a stage-only recipe, a fresh private tempdir
/// otherwise (the shape every dep build had before #310 — the tempdir
/// guards the user's staged content and the parallel phase).
fn resolve_dep_stage<'a>(
    dep_meta: &crate::snap::SnapMeta,
    run_stage: &'a Path,
) -> miette::Result<DepStage<'a>> {
    if crate::coordinator::is_stage_only(dep_meta) {
        Ok(DepStage::Shared(run_stage))
    } else {
        Ok(DepStage::Private(tempfile::tempdir().map_err(|e| {
            miette::miette!("failed to create temp stage: {}", e)
        })?))
    }
}

/// Build every selected output across its resolved archs, collecting the
/// source infos recorded during the builds (for lockfile pinning).
#[allow(clippy::too_many_arguments)]
fn build_outputs(
    iter: &[(&String, crate::snap::SnapMeta)],
    cli_archs: &[String],
    stage_dir: &Path,
    stage_policy: crate::snap::StagePolicy,
    output_dir: &Path,
    pkg_cache: Option<&PackageCache>,
    lockfile: &LockFile,
    json: bool,
) -> miette::Result<Vec<crate::snap::SourceInfo>> {
    let mut all_source_info: Vec<crate::snap::SourceInfo> = Vec::new();

    for (name, meta) in iter {
        let archs = crate::snap::resolve_archs(meta, cli_archs);
        if !json {
            // adopt-info snaps show their adopted-at-build identity here,
            // never the "0" placeholder.
            eprintln!("Building {} ({})...", name, meta.display_version());
        }

        for a in &archs {
            for info in build_one_arch(
                name,
                meta,
                a,
                stage_dir,
                stage_policy,
                output_dir,
                pkg_cache,
                lockfile,
                json,
            )? {
                all_source_info.push(info);
            }
        }
    }

    Ok(all_source_info)
}

/// Build a single output for one arch. Returns the source infos captured
/// by the build (one per materialized source), for the caller's lockfile
/// update.
#[allow(clippy::too_many_arguments)]
fn build_one_arch(
    name: &str,
    meta: &crate::snap::SnapMeta,
    arch: &str,
    stage_dir: &Path,
    stage_policy: crate::snap::StagePolicy,
    output_dir: &Path,
    pkg_cache: Option<&PackageCache>,
    lockfile: &LockFile,
    json: bool,
) -> miette::Result<Vec<crate::snap::SourceInfo>> {
    crate::snap::check_cross_build(arch, meta.target.as_deref())?;
    if !json {
        crate::output::status(format!("{}/{}:", name, arch));
    }

    if let Some(SourceSpec::Unverified(ref url)) = meta.source {
        if lockfile.lookup_source(url).is_some() {
            crate::output::info(format!("using lockfile hash for {url}"));
        }
    }

    // Merged build prefix (ADR-0018, issue #17): the payloads of this
    // package's `requires` + `build_deps`, built-or-fetched and merged,
    // bound read-only into the build sandbox.
    let mut building: Vec<String> = vec![name.to_string()];
    let build_prefix = ensure_build_prefix(
        meta,
        arch,
        output_dir,
        pkg_cache,
        lockfile,
        json,
        // Top-level output builds are sequential — full output.
        false,
        &mut building,
        stage_dir,
        stage_policy,
    )?;

    // Post-build leak-scan resolution data (ADR-0018 Decision 3, issue
    // #22): every build runs the scan; when no prefix was materialized
    // there are no payloads, so the listings are empty and the scan just
    // reports zero build-only refs.
    let scan_listings = match &build_prefix {
        Some(p) => crate::leak_scan::listings_for_build(meta, p)?,
        None => crate::leak_scan::PayloadListings::default(),
    };

    let result = crate::snap::build_snap(
        meta,
        stage_dir,
        output_dir,
        arch,
        stage_policy,
        None,
        None,
        build_prefix.as_ref().map(|p| p.path()),
        Some(&scan_listings),
        // Not a drift-observation point.
        false,
    )?;
    if !json {
        crate::output::ok(&result.snap_filename);
    } else {
        crate::output::record_build_result(crate::output::BuildResultJson {
            name: meta.name.clone(),
            // The version the build actually resolved to (extracted for
            // adopt-info snaps — never the declared placeholder).
            version: result.version.clone(),
            arch: arch.to_string(),
            filename: result.snap_filename.clone(),
            sha256: result.source_infos.first().map(|s| s.sha256.clone()),
            // Multi-source builds (issue #41) report every pinned source;
            // single-source builds keep the flat `sha256` field only.
            sources: (!result.source_infos.is_empty()).then(|| {
                result
                    .source_infos
                    .iter()
                    .map(|i| crate::output::SourcePinJson {
                        url: i.url.clone(),
                        sha256: i.sha256.clone(),
                    })
                    .collect()
            }),
            executor: "local".into(),
            worker: None,
        });
    }

    Ok(result.source_infos)
}

/// Pin newly observed source hashes into the lockfile (saving it when
/// anything changed) and report each source in text mode.
fn persist_new_sources(
    lockfile: &mut LockFile,
    lock_path: &Path,
    source_info: &[crate::snap::SourceInfo],
    lockfile_path: &str,
    json: bool,
) -> miette::Result<()> {
    let mut changed = false;
    for info in source_info {
        if !lockfile.sources.contains_key(&info.url) {
            lockfile.sources.insert(
                info.url.clone(),
                SourceLockEntry {
                    sha256: info.sha256.clone(),
                },
            );
            changed = true;
        }
    }

    if changed {
        lockfile.save(lock_path)?;
        crate::output::ok(format!("lockfile updated: {}", lockfile_path));
    }

    if !source_info.is_empty() && !json {
        for info in source_info {
            let status = if lockfile.sources.contains_key(&info.url) {
                "pinned"
            } else {
                "recorded"
            };
            crate::output::status(format!("source {status}: {:16} {}", info.sha256, info.url));
        }
    }

    Ok(())
}

/// Pin build-time-only dependencies (`build_deps`) into the lockfile
/// (ADR-0018 Decision 4, issue #22). Each declared build_dep is recorded
/// with the resolved version (lockfile pin wins; else declared version) —
/// the same resolution the binary-cache closure uses — so a changed build
/// dependency is recorded and reproducible. The lockfile IS the pin record
/// (ADR-0017 Decision 5).
fn persist_build_deps_pins(
    lockfile: &mut LockFile,
    lock_path: &Path,
    iter: &[(&String, crate::snap::SnapMeta)],
    lockfile_path: &str,
) -> miette::Result<()> {
    let mut changed = false;
    for (_name, meta) in iter {
        for dep in &meta.build_deps {
            if lockfile.lookup_build_dep(dep).is_some() {
                continue;
            }
            let member = crate::coordinator::requires_member(dep, lockfile);
            lockfile.record_build_dep(
                dep,
                &crate::lock::BuildDepPin {
                    pin: member.pin.clone(),
                    hash: member.hash.clone(),
                },
            );
            changed = true;
        }
    }

    if changed {
        lockfile.save(lock_path)?;
        crate::output::ok(format!("lockfile updated: {lockfile_path}"));
    }
    Ok(())
}

// Moved to nau-chart::pkg_source beside InputPinUpdate (issue #326).
// Re-exported so crate::build_orch::pin_update_line keeps resolving.
pub use nau_chart::pkg_source::pin_update_line;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_names_default_stage_matches_spellings() {
        // Any spelling of the default — existing or not — must match:
        // a lock-holder's wipe window is exactly the existing case.
        assert!(names_default_stage(Path::new("./stage")));
        assert!(names_default_stage(Path::new("./stage/")));
        assert!(names_default_stage(Path::new("stage")));
        assert!(names_default_stage(Path::new("stage/.")));
        // Sibling names stay user-owned explicit stages.
        assert!(!names_default_stage(Path::new("./stage2")));
        assert!(!names_default_stage(Path::new("staging")));
        assert!(!names_default_stage(Path::new("/tmp/stage")));
    }

    #[test]
    fn test_resolve_stage_refuses_default_stage_spelling() {
        let err = resolve_stage(Some("./stage".to_string())).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("default stage"),
            "conflict with the default must be loud: {msg}"
        );
        assert!(
            msg.contains("--stage"),
            "error must point at the explicit-stage escape: {msg}"
        );

        // A distinct directory is still a fine explicit stage.
        let dir = tempfile::tempdir().unwrap();
        let other = dir.path().join("stage2");
        let (path, policy, lock) =
            resolve_stage(Some(other.to_string_lossy().into_owned())).unwrap();
        assert_eq!(path, other);
        assert_eq!(policy, crate::snap::StagePolicy::Explicit);
        assert!(lock.is_none(), "an explicit stage is never locked");
    }

    #[test]
    fn test_resolve_stage_explicit_takes_no_lock() {
        let dir = tempfile::tempdir().unwrap();
        let stage = dir.path().join("stg");
        std::fs::create_dir_all(&stage).unwrap();

        let (path, policy, lock) =
            resolve_stage(Some(stage.to_string_lossy().into_owned())).unwrap();
        assert_eq!(policy, crate::snap::StagePolicy::Explicit);
        assert_eq!(path, stage);
        // An explicit --stage is user-owned: no cross-process lock, and no
        // lock file appears next to it.
        assert!(lock.is_none());
        assert!(!dir.path().join("stg.lock").exists());
    }

    #[test]
    fn test_resolve_stage_default_pins_against_concurrent_build() {
        // Runs against the repo's ./stage/ (the real default): the lock
        // file it creates is gitignored. Only this test touches it.
        let (path, policy, lock) = resolve_stage(None).unwrap();
        assert_eq!(policy, crate::snap::StagePolicy::Default);
        assert_eq!(path, std::path::Path::new("./stage/"));
        assert!(lock.is_some(), "default stage must be pinned by a lock");

        // A second concurrent default-stage build refuses loudly instead
        // of silently sharing the stage (gate-pod gap 6).
        let err = resolve_stage(None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("held by another nau build"),
            "conflict must be loud: {msg}"
        );
        assert!(
            msg.contains("--stage"),
            "conflict must point at the escape hatch: {msg}"
        );

        // Release on drop: the next build proceeds.
        drop(lock);
        let (_p, _pol, again) = resolve_stage(None).unwrap();
        assert!(again.is_some());
    }

    // ── #310: stage-only deps pack the run's resolved stage ──

    fn dep_fixture_meta(name: &str) -> crate::snap::SnapMeta {
        crate::snap::SnapMeta {
            name: name.into(),
            version: "1.0".into(),
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
            apps: HashMap::new(),
            services: BTreeMap::new(),
            deps: None,
            floating: false,
            definition_dir: None,
        }
    }

    fn tool_on_path(tool: &str) -> bool {
        std::process::Command::new("which")
            .arg(tool)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// The stage SELECTION: a stage-only recipe packs the run's stage
    /// (its content IS the declaration); anything with a build phase
    /// keeps a private scratch — the shared stage must never be a
    /// build's wipe target.
    #[test]
    fn resolve_dep_stage_shares_the_run_stage_only_for_stage_only_deps() {
        let run = tempfile::tempdir().unwrap();
        match resolve_dep_stage(&dep_fixture_meta("meta-dep"), run.path()).unwrap() {
            DepStage::Shared(p) => assert_eq!(p, run.path()),
            DepStage::Private(_) => panic!("a stage-only dep must pack the run stage"),
        }
        let mut built = dep_fixture_meta("built-dep");
        built.build = Some("true".into());
        match resolve_dep_stage(&built, run.path()).unwrap() {
            DepStage::Private(t) => assert_ne!(t.path(), run.path()),
            DepStage::Shared(_) => panic!("a build-bearing dep must keep its private scratch"),
        }
    }

    /// The whole local dep leg: a stage-only dep builds a snap carrying
    /// the pre-staged content (the #310 bug built a meta-only shell),
    /// and the shared stage survives the build untouched.
    #[test]
    fn stage_only_dep_build_packs_the_run_stage_content() {
        if !tool_on_path("mksquashfs") {
            eprintln!("skipping: mksquashfs unavailable");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let run_stage = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(run_stage.path().join("usr/share")).unwrap();
        std::fs::write(
            run_stage.path().join("usr/share/dep-payload.txt"),
            b"declared content\n",
        )
        .unwrap();
        let output_dir = tmp.path().join("out");
        std::fs::create_dir_all(&output_dir).unwrap();

        build_dep_archs(
            "stage-dep",
            &dep_fixture_meta("stage-dep"),
            &["amd64".to_string()],
            &output_dir,
            None,
            None,
            &LockFile::empty(),
            false,
            true,
            run_stage.path(),
            crate::snap::StagePolicy::Default,
        )
        .expect("the stage-only dep builds");

        let snap = output_dir.join("stage-dep_1.0_amd64.snap");
        assert!(
            snap.is_file(),
            "the dep snap exists in {}",
            output_dir.display()
        );

        // The declared content rides the snap — a payload, not a shell.
        // The extraction spawns through the tools seam (#101 AC-1):
        // resolution IS the availability check (provisioned set,
        // NAU_TOOL_ override, PATH fallback), so a miss skips the check.
        let unsquashfs = match crate::tools::resolve(crate::tools::ToolName::Unsquashfs) {
            Ok(
                crate::tools::ResolvedTool::Provisioned { path, .. }
                | crate::tools::ResolvedTool::Path { path, .. },
            ) => path,
            Err(_) => {
                eprintln!("skipping content check: unsquashfs unavailable");
                return;
            }
        };
        let extract = tempfile::tempdir().unwrap();
        let status = std::process::Command::new(&unsquashfs)
            .args(["-f", "-d"])
            .arg(extract.path())
            .arg(&snap)
            .status()
            .unwrap();
        assert!(status.success(), "unsquashfs failed");
        let carried = std::fs::read(extract.path().join("usr/share/dep-payload.txt"))
            .expect("the staged payload is inside the snap");
        assert_eq!(carried, b"declared content\n");

        // The collision guard holds: the shared stage was read, never
        // wiped or consumed.
        assert_eq!(
            std::fs::read(run_stage.path().join("usr/share/dep-payload.txt")).unwrap(),
            b"declared content\n",
        );
    }
}
