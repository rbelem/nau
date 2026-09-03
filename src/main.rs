use std::collections::HashMap;
use std::path::Path;

use clap::Parser;
use shuttle::cache::PackageCache;
use shuttle::cli::{CacheCommand, Cli, Command, IndexCommand};
use shuttle::image::ImageDeclaration;
use shuttle::index::{IndexEntry, PackageIndex, StoreRef};
use shuttle::lock::{LockFile, SourceLockEntry};
use shuttle::snap::{PackageInput, SourceSpec};

fn main() -> miette::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Build {
            file,
            stage,
            output,
            arch,
            output_name,
            source_date_epoch,
            lockfile: lockfile_path,
            order,
            all,
            cache,
            cache_max_size,
            target,
            update,
            offline,
            json,
        } => {
            shuttle::output::set_mode(json);
            // If --file is default and doesn't exist, try output_name as package name
            let file = if file == "shuttle.lua" && !Path::new("shuttle.lua").exists() {
                if let Some(ref name) = output_name {
                    resolve_file(name)?
                } else {
                    file
                }
            } else {
                resolve_file(&file)?
            };
            // If file came from embedded resolution, the positional arg was
            // used as the package name, not as an output filter.
            let output_name = if file.starts_with("embedded://") {
                None
            } else {
                output_name
            };
            if order {
                let r = cmd_order(&file, &output_name, json);
                shuttle::output::flush_json("order");
                return r;
            }
            let r = cmd_build(
                file,
                stage,
                output,
                arch,
                output_name,
                source_date_epoch,
                lockfile_path,
                all,
                cache,
                cache_max_size,
                target,
                update,
                offline,
                json,
            );
            shuttle::output::flush_json("build");
            r
        }

        Command::Image {
            file,
            output,
            arch,
            channel,
            cache,
            cache_max_size,
            output_name,
            source_date_epoch,
            lockfile: lockfile_path,
            json,
        } => {
            shuttle::output::set_mode(json);
            let r = cmd_image(
                file,
                output,
                arch,
                channel,
                cache,
                cache_max_size,
                output_name,
                source_date_epoch,
                lockfile_path,
                json,
            );
            shuttle::output::flush_json("image");
            r
        }

        Command::Deps {
            package,
            recursive,
            tree,
            flat,
            json,
        } => {
            shuttle::output::set_mode(json);
            let r = cmd_deps(package, recursive, tree, flat, json);
            shuttle::output::flush_json("deps");
            r
        }

        Command::Search { query, json } => {
            shuttle::output::set_mode(json);
            cmd_search(&query, json);
            Ok(())
        }

        Command::Index(sub) => cmd_index(sub),

        Command::Doctor => cmd_doctor(),

        Command::Check { file, json } => {
            shuttle::output::set_mode(json);
            cmd_check(&file, json)
        }

        Command::Lock {
            file,
            lockfile,
            json,
        } => {
            shuttle::output::set_mode(json);
            cmd_lock(file, lockfile)
        }

        Command::Eval {
            file,
            output,
            output_name,
            arch,
            channel,
            lockfile: lockfile_path,
            offline,
            json,
        } => {
            shuttle::output::set_mode(json);
            cmd_eval(
                file,
                output,
                output_name,
                arch,
                channel,
                lockfile_path,
                offline,
            )
        }

        Command::Completion { shell } => cmd_completion(shell),

        Command::Cache(sub) => cmd_cache(sub),

        Command::EvalWorker => shuttle::isolate::worker_main(),

        Command::CheckWorker => shuttle::isolate::check_worker_main(),
    }
}

// ── Package name resolution ──
// If file doesn't exist on disk, try resolving as a package name from
// local pkgs/ or from initialized input sources.

fn resolve_file(file: &str) -> miette::Result<String> {
    if Path::new(file).exists() {
        return Ok(file.to_string());
    }
    match shuttle::pkg_source::resolve_pkg(file) {
        shuttle::pkg_source::PkgResult::File(path) => Ok(path),
        shuttle::pkg_source::PkgResult::Found { path, content } => {
            eprintln!("  ℹ using package '{}' ({})", file, path);
            // Materialize into a fresh private temp dir (never the shared,
            // predictable $TMPDIR): the definition path's parent becomes the
            // eval/check resolver's allowlisted root, so it must be this
            // invocation's private directory only — never /tmp.
            let tmp = shuttle::pkg_source::materialize_embedded(&content)?;
            Ok(tmp.to_string_lossy().to_string())
        }
        shuttle::pkg_source::PkgResult::NotFound => Ok(file.to_string()),
    }
}

/// Evaluate a file path or resolved package source, returning snap outputs.
fn evaluate_file_or_embedded(file: &str) -> miette::Result<shuttle::lua::Outputs> {
    shuttle::lua::evaluate_file(file)
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

#[allow(clippy::too_many_arguments)]
fn cmd_build(
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
    update: Option<String>,
    offline: bool,
    json: bool,
) -> miette::Result<()> {
    if update.is_some() && offline {
        return Err(miette::miette!(
            "--update needs network access and cannot be combined with --offline"
        ));
    }

    // Initialize package source inputs
    // 1. If the config file exists, extract its global inputs first
    // 2. Otherwise fall back to the default input (github:rbelem/shuttle/main)
    let original_file = file.clone();
    let file_exists = Path::new(&original_file).exists();

    // Strategy 1: eval the config file directly (uses its declared inputs).
    // If it fails we keep the error: the fallback below may re-evaluate the
    // same source (resolve_file returns the same existing path), and when
    // that second attempt also fails, the real diagnostic is the first one —
    // discarding it turned a hostile busy-loop file into a silent 2×5s eval
    // that reported only the fallback's error.
    let mut direct_eval_error: Option<String> = None;
    if file_exists {
        // Extract global inputs from the config file and use those
        match shuttle::lua::evaluate_file_with_inputs(&original_file) {
            Ok(eval) => {
                let lockfile = prepare_inputs(
                    &eval.global_inputs,
                    &lockfile_path,
                    update.as_deref(),
                    offline,
                )?;
                shuttle::pkg_source::init_global_inputs_with(
                    &eval.global_inputs,
                    &lockfile.inputs,
                    offline,
                )?;
                // We already have the outputs — use them directly
                let all_outputs = eval.outputs;
                return run_build(
                    all_outputs,
                    file, // unresolved — run_build handles it
                    stage,
                    output,
                    arch,
                    output_name,
                    source_date_epoch,
                    lockfile_path,
                    all,
                    cache,
                    cache_max_size,
                    target,
                    json,
                );
            }
            Err(e) => {
                direct_eval_error = Some(format!("{e:#}"));
            }
        }
    }

    // No config file or it failed — use default input and resolve by name
    let default_inputs = default_input_map();
    let lockfile = prepare_inputs(&default_inputs, &lockfile_path, update.as_deref(), offline)?;
    shuttle::pkg_source::init_global_inputs_with(&default_inputs, &lockfile.inputs, offline)?;
    let file = resolve_file(&file)?;
    let all_outputs = evaluate_file_or_embedded(&file).map_err(|e| match &direct_eval_error {
        Some(first) => miette::miette!(
            "evaluating '{}' failed: {first}; fallback resolution of '{}' also failed: {e:#}",
            original_file,
            file
        ),
        None => e,
    })?;

    run_build(
        all_outputs,
        file,
        stage,
        output,
        arch,
        output_name,
        source_date_epoch,
        lockfile_path,
        all,
        cache,
        cache_max_size,
        target,
        json,
    )
}

/// The default input map used when no config file is present.
fn default_input_map() -> HashMap<String, PackageInput> {
    let mut m = HashMap::new();
    m.insert(
        shuttle::pkg_source::DEFAULT_INPUT_NAME.to_string(),
        PackageInput {
            url: shuttle::pkg_source::DEFAULT_INPUT_URL.to_string(),
        },
    );
    m
}

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
    });

    let mut changed = false;
    if let Some(name) = update {
        // --update <input> refreshes one pin; bare --update refreshes all.
        let names: Vec<&str> = if name.is_empty() {
            Vec::new()
        } else {
            vec![name]
        };
        let updates = shuttle::pkg_source::update_input_pins(inputs, &names, &mut lockfile)?;
        for u in &updates {
            shuttle::output::status(pin_update_line(u));
        }
        changed |= !updates.is_empty();
    } else if !offline {
        // Record-once: pin inputs missing from the lockfile (first build).
        let n = shuttle::pkg_source::ensure_input_pins(inputs, &mut lockfile)?;
        changed |= n > 0;
    }

    if changed {
        lockfile.save(lock_path)?;
        shuttle::output::ok(format!("lockfile updated: {lockfile_path}"));
    }
    Ok(lockfile)
}

/// Build the canonical build-input closure for a snap: source identity +
/// parts spec + cross-compilation target + resolved requires closure
/// (gap-analysis §4.3). Computed once per snap per build, after requires
/// resolution; every cache lookup/store uses the key derived from it.
///
/// Requires resolution uses lockfile pins when present (no I/O); unpinned
/// deps are resolved from already-initialized local input caches — this
/// never fetches. With `--offline` an unfetchable input fails earlier, in
/// `init_global_inputs_with`, exactly as before this existed.
fn build_closure(
    meta: &shuttle::snap::SnapMeta,
    lockfile: &LockFile,
) -> shuttle::cache::BuildClosure {
    let mut names: Vec<String> = if meta.requires.is_empty() {
        Vec::new()
    } else {
        shuttle::deps::resolve_dep_names(&meta.requires, true).unwrap_or_default()
    };
    names.sort();
    names.dedup();
    let requires = names
        .iter()
        .map(|name| requires_member(name, lockfile))
        .collect();
    shuttle::cache::BuildClosure::for_meta(meta, requires)
}

/// Resolve one requires-closure member. A lockfile pin (revision +
/// sha3-384) wins — pure data, safe offline. Otherwise the dep's declared
/// version pins it with `hash: None`: an unpinned store dep is only
/// version-pinned, so content changes behind the version cannot invalidate
/// the cache key (known limitation; `shuttle lock` and image builds record
/// snap pins that close this gap).
fn requires_member(name: &str, lockfile: &LockFile) -> shuttle::cache::RequiresMember {
    if let Some(member) = shuttle::cache::pinned_member(name, lockfile) {
        return member;
    }
    let pin = shuttle::deps::load_meta(name).ok().map(|meta| meta.version);
    shuttle::cache::RequiresMember {
        name: name.to_string(),
        pin,
        hash: None,
    }
}

/// True when every arch `dep` will be built for is already cached under its
/// closure key. Replaces the old hardcoded `"amd64"` lookup, which could
/// serve a stale amd64 artifact for an aarch64 build of the same source.
fn dep_fully_cached(
    cache: &shuttle::cache::PackageCache,
    closure: &shuttle::cache::BuildClosure,
    dep_meta: &shuttle::snap::SnapMeta,
    cli_archs: &[String],
) -> bool {
    shuttle::snap::resolve_archs(dep_meta, cli_archs)
        .iter()
        .all(|a| cache.lookup(dep_meta, a, closure).is_some())
}

/// Resolve the `--stage` CLI flag into (path, policy) and enforce the
/// explicit-stage precondition: a user-chosen directory that already has
/// contents is refused up front — never wiped.
fn resolve_stage(
    stage: Option<String>,
) -> miette::Result<(std::path::PathBuf, shuttle::snap::StagePolicy)> {
    match stage {
        Some(path) => {
            let policy = shuttle::snap::StagePolicy::Explicit;
            shuttle::snap::check_explicit_stage(Path::new(&path))?;
            Ok((std::path::PathBuf::from(path), policy))
        }
        None => Ok((
            std::path::PathBuf::from("./stage/"),
            shuttle::snap::StagePolicy::Default,
        )),
    }
}

/// Inner build logic after outputs are resolved.
#[allow(clippy::too_many_arguments)]
fn run_build(
    all_outputs: shuttle::lua::Outputs,
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
) -> miette::Result<()> {
    if let Some(ref epoch) = source_date_epoch {
        std::env::set_var("SOURCE_DATE_EPOCH", epoch);
    }

    let lock_path = Path::new(&lockfile_path);
    let mut lockfile = load_lockfile_or_default(lock_path)?;

    // Stage policy: an explicitly passed --stage belongs to the user — it
    // must be empty to start and is never wiped. The default ./stage/ is
    // shuttle-managed scratch, wiped before every build phase (snap.rs).
    let (stage_path, stage_policy) = resolve_stage(stage)?;
    let stage_dir = std::path::Path::new(&stage_path);
    let output_dir = std::path::Path::new(&output);

    let pkg_cache = init_pkg_cache(all, cache, cache_max_size, json);

    let iter = select_outputs(&all_outputs, &output_name, &file, target.as_ref(), json)?;

    // If --all, resolve and build transitive dependencies first
    if all {
        let all_deps = collect_dep_names(&iter);
        build_all_deps(
            &all_deps,
            target.as_ref(),
            pkg_cache.as_ref(),
            &arch,
            output_dir,
            &lockfile,
            json,
        )?;
    }

    let all_source_info = build_outputs(
        &iter,
        &arch,
        stage_dir,
        stage_policy,
        output_dir,
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

    Ok(())
}

/// Load the lockfile at `lock_path`, falling back to an empty v1 lockfile
/// when it does not exist yet.
fn load_lockfile_or_default(lock_path: &Path) -> miette::Result<LockFile> {
    Ok(LockFile::load(lock_path)?.unwrap_or_else(|| LockFile {
        version: 1,
        sources: HashMap::new(),
        snaps: HashMap::new(),
        inputs: HashMap::new(),
    }))
}

/// Initialize the binary cache when --cache/--cache-max-size was given or
/// --all is set; `None` means the build runs uncached.
fn init_pkg_cache(
    all: bool,
    cache: Option<String>,
    cache_max_size: Option<String>,
    json: bool,
) -> Option<shuttle::cache::PackageCache> {
    if !(all || cache.is_some() || cache_max_size.is_some()) {
        return None;
    }

    let mut pc = shuttle::cache::PackageCache::new(cache.map(std::path::PathBuf::from));
    if let Some(ref size_str) = cache_max_size {
        if let Some(bytes) = parse_size(size_str) {
            pc = pc.with_max_size(bytes);
            if !json {
                shuttle::output::info(format!("max cache size: {}", size_str));
            }
        } else if !json {
            shuttle::output::warn(format!("invalid cache size: {}", size_str));
        }
    }
    Some(pc)
}

/// Select the outputs to build: the --output-name pick when given, else
/// every output in the file. Applies --target to each selected meta
/// (announced once in text mode).
fn select_outputs<'a>(
    all_outputs: &'a shuttle::lua::Outputs,
    output_name: &'a Option<String>,
    file: &str,
    target: Option<&String>,
    json: bool,
) -> miette::Result<Vec<(&'a String, shuttle::snap::SnapMeta)>> {
    let iter: Vec<(&String, shuttle::snap::SnapMeta)> = match output_name {
        Some(name) => {
            let mut meta = all_outputs
                .get(name)
                .ok_or_else(|| miette::miette!("output '{}' not found in {}", name, file))?
                .clone();
            if let Some(t) = target {
                meta.target = Some(t.clone());
                if !json {
                    shuttle::output::info(format!("target: {t}"));
                }
            }
            vec![(name, meta)]
        }
        None => {
            let mut vec: Vec<(&String, shuttle::snap::SnapMeta)> = Vec::new();
            for (name, meta_ref) in all_outputs {
                let mut meta = meta_ref.clone();
                if let Some(t) = target {
                    meta.target = Some(t.clone());
                }
                vec.push((name, meta));
            }
            if let Some(t) = target {
                if !json {
                    shuttle::output::info(format!("target: {t}"));
                }
            }
            vec
        }
    };
    Ok(iter)
}

/// Collect the unique dependency names of every selected output, in
/// first-seen order.
fn collect_dep_names(iter: &[(&String, shuttle::snap::SnapMeta)]) -> Vec<String> {
    let mut all_deps: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (_name, meta) in iter {
        if !meta.requires.is_empty() {
            if let Ok(deps) = shuttle::deps::resolve_dep_names(&meta.requires, true) {
                for dep in &deps {
                    if seen.insert(dep.clone()) {
                        all_deps.push(dep.clone());
                    }
                }
            }
        }
    }
    all_deps
}

/// Resolve and build every transitive dependency of the selected outputs
/// (--all mode), consulting the binary cache per dep when one is active.
#[allow(clippy::too_many_arguments)]
fn build_all_deps(
    dep_names: &[String],
    effective_target: Option<&String>,
    pkg_cache: Option<&shuttle::cache::PackageCache>,
    cli_archs: &[String],
    output_dir: &Path,
    lockfile: &LockFile,
    json: bool,
) -> miette::Result<()> {
    if dep_names.is_empty() {
        return Ok(());
    }
    if !json {
        eprintln!("── Building {} dependencies ──", dep_names.len());
    }
    for dep_name in dep_names {
        let mut dep_meta = match shuttle::deps::load_meta(dep_name) {
            Ok(m) => m,
            Err(e) => {
                shuttle::output::warn(format!("skipping dependency '{}': {}", dep_name, e));
                continue;
            }
        };

        // Apply --target to deps as well
        if let Some(t) = effective_target {
            dep_meta.target = Some(t.clone());
        }

        // Closure key for this dep: source + parts + target + requires
        // closure, built once per dep; both the lookup and the store below
        // use it.
        let dep_closure = pkg_cache.map(|_| build_closure(&dep_meta, lockfile));

        // Check cache first: skip the dep only when every resolved arch is
        // cached under its closure key.
        if let (Some(cache), Some(closure)) = (pkg_cache, dep_closure.as_ref()) {
            if dep_fully_cached(cache, closure, &dep_meta, cli_archs) {
                if !json {
                    shuttle::output::ok(format!("{} (cached)", dep_name));
                }
                continue;
            }
        }

        let dep_archs = shuttle::snap::resolve_archs(&dep_meta, cli_archs);
        build_dep_archs(
            dep_name,
            &dep_meta,
            &dep_archs,
            output_dir,
            pkg_cache,
            dep_closure.as_ref(),
            json,
        )?;
    }
    Ok(())
}

/// Build one dependency across its resolved archs, storing each artifact in
/// the binary cache when one is active.
fn build_dep_archs(
    dep_name: &str,
    dep_meta: &shuttle::snap::SnapMeta,
    dep_archs: &[String],
    output_dir: &Path,
    pkg_cache: Option<&shuttle::cache::PackageCache>,
    dep_closure: Option<&shuttle::cache::BuildClosure>,
    json: bool,
) -> miette::Result<()> {
    for a in dep_archs {
        shuttle::snap::check_cross_build(a, dep_meta.target.as_deref())?;
        if !json {
            shuttle::output::status(format!("building {} ({})...", dep_name, a));
        }
        let dep_stage = tempfile::tempdir()
            .map_err(|e| miette::miette!("failed to create temp stage: {}", e))?;

        match shuttle::snap::build_snap(
            dep_meta,
            dep_stage.path(),
            output_dir,
            a,
            shuttle::snap::StagePolicy::Default,
        ) {
            Ok(result) => {
                if !json {
                    shuttle::output::ok(&result.snap_filename);
                }
                if let (Some(cache), Some(closure)) = (pkg_cache, dep_closure) {
                    if let Err(e) = cache.store(dep_meta, &result, output_dir, closure) {
                        shuttle::output::warn(format!("cache store failed: {}", e));
                    }
                }
            }
            Err(e) => {
                shuttle::output::warn(format!("build failed for '{}': {}", dep_name, e));
            }
        }
    }
    Ok(())
}

/// Build every selected output across its resolved archs, collecting the
/// source infos recorded during the builds (for lockfile pinning).
fn build_outputs(
    iter: &[(&String, shuttle::snap::SnapMeta)],
    cli_archs: &[String],
    stage_dir: &Path,
    stage_policy: shuttle::snap::StagePolicy,
    output_dir: &Path,
    lockfile: &LockFile,
    json: bool,
) -> miette::Result<Vec<shuttle::snap::SourceInfo>> {
    let mut all_source_info: Vec<shuttle::snap::SourceInfo> = Vec::new();

    for (name, meta) in iter {
        let archs = shuttle::snap::resolve_archs(meta, cli_archs);
        if !json {
            // adopt-info snaps show their adopted-at-build identity here,
            // never the "0" placeholder.
            eprintln!("Building {} ({})...", name, meta.display_version());
        }

        for a in &archs {
            if let Some(info) = build_one_arch(
                name,
                meta,
                a,
                stage_dir,
                stage_policy,
                output_dir,
                lockfile,
                json,
            )? {
                all_source_info.push(info);
            }
        }
    }

    Ok(all_source_info)
}

/// Build a single output for one arch. Returns the source info captured by
/// the build, if any, for the caller's lockfile update.
#[allow(clippy::too_many_arguments)]
fn build_one_arch(
    name: &str,
    meta: &shuttle::snap::SnapMeta,
    arch: &str,
    stage_dir: &Path,
    stage_policy: shuttle::snap::StagePolicy,
    output_dir: &Path,
    lockfile: &LockFile,
    json: bool,
) -> miette::Result<Option<shuttle::snap::SourceInfo>> {
    shuttle::snap::check_cross_build(arch, meta.target.as_deref())?;
    if !json {
        shuttle::output::status(format!("{}/{}:", name, arch));
    }

    if let Some(SourceSpec::Unverified(ref url)) = meta.source {
        if lockfile.lookup_source(url).is_some() {
            shuttle::output::info(format!("using lockfile hash for {url}"));
        }
    }

    let result = shuttle::snap::build_snap(meta, stage_dir, output_dir, arch, stage_policy)?;
    if !json {
        shuttle::output::ok(&result.snap_filename);
    } else {
        shuttle::output::record_build_result(shuttle::output::BuildResultJson {
            name: meta.name.clone(),
            // The version the build actually resolved to (extracted for
            // adopt-info snaps — never the declared placeholder).
            version: result.version.clone(),
            arch: arch.to_string(),
            filename: result.snap_filename.clone(),
            sha256: result.source_info.as_ref().map(|s| s.sha256.clone()),
        });
    }

    Ok(result.source_info)
}

/// Pin newly observed source hashes into the lockfile (saving it when
/// anything changed) and report each source in text mode.
fn persist_new_sources(
    lockfile: &mut LockFile,
    lock_path: &Path,
    source_info: &[shuttle::snap::SourceInfo],
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
        shuttle::output::ok(format!("lockfile updated: {}", lockfile_path));
    }

    if !source_info.is_empty() && !json {
        for info in source_info {
            let status = if lockfile.sources.contains_key(&info.url) {
                "pinned"
            } else {
                "recorded"
            };
            shuttle::output::status(format!("source {status}: {:16} {}", info.sha256, info.url));
        }
    }

    Ok(())
}

// ── Order command (--order flag) ──

fn cmd_order(file: &str, output_name: &Option<String>, json: bool) -> miette::Result<()> {
    // Initialize global inputs (default if no config)
    shuttle::pkg_source::init_global_inputs(&HashMap::new())?;
    let file = resolve_file(file)?;
    let all_outputs = evaluate_file_or_embedded(&file)?;

    let iter: Vec<&shuttle::snap::SnapMeta> = match output_name {
        Some(name) => {
            let meta = all_outputs
                .get(name)
                .ok_or_else(|| miette::miette!("output '{}' not found in {}", name, file))?;
            vec![meta]
        }
        None => all_outputs.values().collect(),
    };

    for meta in &iter {
        if json {
            report_order_json(meta);
        } else {
            report_order_human(meta);
        }
    }

    Ok(())
}

/// JSON-mode order report for one output.
fn report_order_json(meta: &shuttle::snap::SnapMeta) {
    if meta.requires.is_empty() {
        return;
    }
    let seen: std::collections::HashSet<&str> = meta.requires.iter().map(|s| s.as_str()).collect();
    if let Ok(order) = shuttle::deps::resolve_dep_names(&meta.requires, true) {
        for dep in &order {
            let kind = if seen.contains(dep.as_str()) {
                "direct"
            } else {
                "transitive"
            };
            shuttle::output::record_order_result(shuttle::output::OrderResultJson {
                name: dep.clone(),
                kind: kind.to_string(),
            });
        }
    }
}

/// Text-mode order report for one output.
fn report_order_human(meta: &shuttle::snap::SnapMeta) {
    eprintln!("Package: {} {}", meta.name, meta.version);

    if meta.requires.is_empty() {
        eprintln!("  No dependencies");
        return;
    }

    eprintln!("  Direct requires:");
    for dep in &meta.requires {
        eprintln!("    - {}", dep);
    }

    eprintln!("  Resolved build order (transitive):");
    match shuttle::deps::resolve_dep_names(&meta.requires, true) {
        Ok(order) => {
            let seen: std::collections::HashSet<&str> =
                meta.requires.iter().map(|s| s.as_str()).collect();
            for dep in &order {
                let marker = if seen.contains(dep.as_str()) {
                    "direct"
                } else {
                    "transitive"
                };
                eprintln!("    {:4} {}", marker, dep);
            }
        }
        Err(e) => {
            eprintln!("    ⚠ could not resolve: {}", e);
        }
    }
}

// ── Deps command ──

fn cmd_deps(
    package: String,
    recursive: bool,
    tree: bool,
    flat: bool,
    json: bool,
) -> miette::Result<()> {
    shuttle::pkg_source::init_global_inputs(&HashMap::new())?;
    let names = vec![package.clone()];
    let nodes = shuttle::deps::resolve_deps(&names, recursive)?;

    if nodes.is_empty() {
        if json {
            return Ok(());
        }
        eprintln!("No dependencies found for '{}'", package);
        return Ok(());
    }

    if json {
        report_deps_json(&nodes);
    } else {
        report_deps_human(&package, &nodes, tree, recursive, flat)?;
    }

    Ok(())
}

/// JSON-mode dependency report.
fn report_deps_json(nodes: &[shuttle::deps::DepNode]) {
    let seen: std::collections::HashSet<&str> = nodes
        .iter()
        .flat_map(|n| &n.requires)
        .map(|s| s.as_str())
        .collect();
    for node in nodes {
        let kind = if seen.contains(node.name.as_str()) {
            "direct"
        } else {
            "transitive"
        };
        shuttle::output::record_dep_result(shuttle::output::DepResultJson {
            name: node.name.clone(),
            requires: node.requires.clone(),
            kind: kind.to_string(),
        });
    }
}

/// Text-mode dependency report (tree / flat / direct-requires views).
fn report_deps_human(
    package: &str,
    nodes: &[shuttle::deps::DepNode],
    tree: bool,
    recursive: bool,
    flat: bool,
) -> miette::Result<()> {
    if tree && recursive {
        eprintln!("Dependency tree for '{}':", package);
        let names = vec![package.to_string()];
        let tree_str = shuttle::deps::format_tree(&names, true)?;
        eprintln!("{}", tree_str);
    } else if flat {
        let names_only: Vec<String> = nodes.iter().map(|n| n.name.clone()).collect();
        eprintln!("Build order for '{}':", package);
        for (i, name) in names_only.iter().enumerate() {
            eprintln!("  {}. {}", i + 1, name);
        }
    } else if let Some(pkg) = nodes.first() {
        eprintln!("{} v1.0: {}", package, pkg.name);
        if pkg.requires.is_empty() {
            eprintln!("  No dependencies");
        } else {
            eprintln!("  Requires:");
            for dep in &pkg.requires {
                eprintln!("    - {}", dep);
            }
            if recursive {
                eprintln!("  (use --tree or --flat for full transitive resolution)");
            }
        }
    }

    Ok(())
}

// ── Image command ──

#[allow(clippy::too_many_arguments)]
fn cmd_image(
    file: String,
    output: String,
    arch: String,
    channel: String,
    cache: Option<String>,
    _cache_max_size: Option<String>,
    output_name: Option<String>,
    source_date_epoch: Option<String>,
    lockfile_path: String,
    json: bool,
) -> miette::Result<()> {
    shuttle::pkg_source::init_global_inputs(&HashMap::new())?;
    let file = resolve_file(&file)?;

    if let Some(ref epoch) = source_date_epoch {
        std::env::set_var("SOURCE_DATE_EPOCH", epoch);
    }
    std::env::set_var("SHUTTLE_ARCH", &arch);

    let lock_path = Path::new(&lockfile_path);
    let mut lockfile = load_lockfile_or_default(lock_path)?;

    let images = resolve_images(&file)?;
    let output_dir = Path::new(&output);
    let cache_dir = image_cache_dir(cache.as_deref());
    let iter = select_images(&images, &output_name, &file)?;

    // Every selected image records lockfile pins as it builds.
    let lock_changed = !iter.is_empty();
    build_images(
        &iter,
        output_dir,
        &cache_dir,
        &channel,
        &arch,
        &mut lockfile,
        json,
    )?;

    if lock_changed {
        lockfile.save(lock_path)?;
        shuttle::output::ok(format!("lockfile updated: {}", lockfile_path));
    }

    Ok(())
}

/// Load the image declarations for `file`. Embedded packages are single
/// snaps, not images — reported and treated as "no images".
fn resolve_images(file: &str) -> miette::Result<HashMap<String, ImageDeclaration>> {
    if let Some(_embedded) = file.strip_prefix("embedded://") {
        // Embedded packages are single snaps, not images — return empty
        if !shuttle::output::is_json() {
            shuttle::output::warn(format!("'{}' is a package, not an image", file));
        }
        Ok(std::collections::HashMap::new())
    } else {
        shuttle::lua::evaluate_images_file(file)
    }
}

/// Resolve the image cache directory: the --cache override, else the
/// default under $HOME.
fn image_cache_dir(cache: Option<&str>) -> std::path::PathBuf {
    cache.map_or_else(
        || {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            Path::new(&home).join(".cache/shuttle/snaps")
        },
        |c| Path::new(c).to_path_buf(),
    )
}

/// Select the images to build: the --output-name pick when given, else
/// every declared image.
fn select_images<'a>(
    images: &'a HashMap<String, ImageDeclaration>,
    output_name: &'a Option<String>,
    file: &str,
) -> miette::Result<Vec<(&'a String, &'a ImageDeclaration)>> {
    match output_name {
        Some(name) => {
            let img = images
                .get(name)
                .ok_or_else(|| miette::miette!("image '{}' not found in {}", name, file))?;
            Ok(vec![(name, img)])
        }
        None => Ok(images.iter().collect()),
    }
}

/// Build every selected image, mutating the lockfile as pins are recorded.
fn build_images(
    iter: &[(&String, &ImageDeclaration)],
    output_dir: &Path,
    cache_dir: &Path,
    channel: &str,
    arch: &str,
    lockfile: &mut LockFile,
    json: bool,
) -> miette::Result<()> {
    for (name, image_decl) in iter {
        if !json {
            eprintln!("Building image: {} ({})...", name, image_decl.version);
        }

        build_one_image(
            name, image_decl, output_dir, cache_dir, channel, arch, lockfile, json,
        )?;
    }
    Ok(())
}

/// Build one image (disk image when a disk size is declared, else a plain
/// image) and report the result.
#[allow(clippy::too_many_arguments)]
fn build_one_image(
    name: &str,
    image_decl: &ImageDeclaration,
    output_dir: &Path,
    cache_dir: &Path,
    channel: &str,
    arch: &str,
    lockfile: &mut LockFile,
    json: bool,
) -> miette::Result<()> {
    let result = if image_decl.disk.is_some() {
        shuttle::image::build_disk_image(
            image_decl, output_dir, cache_dir, channel, arch, lockfile,
        )?
    } else {
        shuttle::image::build_image(image_decl, output_dir, cache_dir, channel, arch, lockfile)?
    };

    let fname = result
        .file_name()
        .unwrap_or(result.as_ref())
        .to_string_lossy()
        .to_string();

    if json {
        shuttle::output::record_build_result(shuttle::output::BuildResultJson {
            name: name.to_string(),
            version: image_decl.version.clone(),
            arch: arch.to_string(),
            filename: fname,
            sha256: None,
        });
    } else {
        shuttle::output::ok(&fname);
    }
    Ok(())
}

// ── Doctor command ──

fn cmd_doctor() -> miette::Result<()> {
    let checks = shuttle::doctor::run_all();
    shuttle::doctor::print_report(&checks);
    if !shuttle::doctor::all_ok(&checks) {
        std::process::exit(1);
    }
    Ok(())
}

// ── Check command ──

/// `shuttle check`: run one definition through the analyzer gate first
/// (ADR-0010 Decision 2 — `--!strict` type checking in the bounded
/// `__check-worker` subprocess, fail-closed on timeout with a single
/// `analysis timed out` diagnostic; fast fail with spanned diagnostics
/// before any eval work), then the existing bounded subprocess eval +
/// Rust-side schema validation (Decisions 3-5). Deterministic, no build, no
/// store access — the AI feedback-loop entry point. Exits 1 when the
/// definition has any problem.
fn cmd_check(file: &str, json: bool) -> miette::Result<()> {
    // Stage 1 — analyzer gate. A definition that does not type-check never
    // reaches the eval stage.
    let analyzer_diagnostics = shuttle::analysis::check_definition_file(file);
    let mut diagnostics: Vec<shuttle::lua::CheckDiagnostic> = analyzer_diagnostics
        .into_iter()
        .map(|d| shuttle::lua::CheckDiagnostic::from_analyzer(file, d))
        .collect();

    // Stage 2 — bounded subprocess eval + Rust-side validation (unchanged
    // path; the analyzer is check-only). `None` when stage 1 failed fast.
    let checked = if diagnostics.is_empty() {
        Some(shuttle::lua::check_file_with_inputs(file))
    } else {
        None
    };

    if let Some(checked) = &checked {
        diagnostics.extend(checked.diagnostics.clone());
        // A hard eval failure is a diagnostic too, so both output modes carry
        // the complete problem list in one shape.
        if let Some(err) = &checked.error {
            diagnostics.push(shuttle::lua::CheckDiagnostic {
                label: file.to_string(),
                key: None,
                expected: None,
                actual: None,
                message: err.clone(),
                span: None,
            });
        }
    }
    let ok = checked.as_ref().is_some_and(|c| c.error.is_none()) && diagnostics.is_empty();

    let outputs: Vec<(String, String)> = checked
        .as_ref()
        .map(|c| {
            let mut pairs: Vec<(String, String)> = c
                .outputs
                .iter()
                // adopt-info outputs have no version until build time — the
                // placeholder must never read as a declared version.
                .map(|(name, meta)| (name.clone(), meta.display_version().to_string()))
                .collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            pairs
        })
        .unwrap_or_default();

    if json {
        let names: Vec<String> = outputs.iter().map(|(n, _)| n.clone()).collect();
        report_check_json(file, &names, &diagnostics);
    } else if ok {
        report_check_ok(&outputs);
    } else {
        for d in &diagnostics {
            report_check_diagnostic(d);
        }
    }

    if !ok {
        std::process::exit(1);
    }
    Ok(())
}

/// `--json` report: every diagnostic is self-contained — one optional nested
/// `"span"` object (per-diagnostic span fields, not a top-level `"spans"`
/// array).
fn report_check_json(
    file: &str,
    outputs: &[String],
    diagnostics: &[shuttle::lua::CheckDiagnostic],
) {
    let diags: Vec<serde_json::Value> = diagnostics
        .iter()
        .map(|d| {
            serde_json::json!({
                "label": d.label,
                "key": d.key,
                "expected": d.expected,
                "actual": d.actual,
                "message": d.message,
                "span": d.span.as_ref().map(|s| serde_json::json!({
                    "begin_line": s.begin_line,
                    "begin_col": s.begin_col,
                    "end_line": s.end_line,
                    "end_col": s.end_col,
                })),
            })
        })
        .collect();
    let report = serde_json::json!({
        "file": file,
        "ok": diagnostics.is_empty(),
        "outputs": outputs,
        "diagnostics": diags,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
    );
}

/// Success message for `shuttle check` — each output shown with its
/// version so the declared identity is visible, not just the name.
fn check_ok_message(outputs: &[(String, String)]) -> String {
    let list = if outputs.is_empty() {
        String::new()
    } else {
        let items: Vec<String> = outputs
            .iter()
            .map(|(name, version)| format!("{name} {version}"))
            .collect();
        format!(": {}", items.join(", "))
    };
    format!("ok: {} output(s){list}", outputs.len())
}

fn report_check_ok(outputs: &[(String, String)]) {
    shuttle::output::ok(check_ok_message(outputs));
}

fn report_check_diagnostic(d: &shuttle::lua::CheckDiagnostic) {
    match (&d.key, &d.span) {
        // Keyed diagnostics with a located declaration site show both: the
        // file:line:col prefix (grep-friendly, matches the analyzer arm)
        // plus the output key in brackets.
        (Some(key), Some(s)) => shuttle::output::err(format!(
            "{}:{}:{}: [{key}] {}",
            d.label, s.begin_line, s.begin_col, d.message
        )),
        (Some(key), None) => shuttle::output::err(format!("{}[{key}]: {}", d.label, d.message)),
        // Analyzer diagnostics print with their 1-based begin span.
        (None, Some(s)) => shuttle::output::err(format!(
            "{}:{}:{}: {}",
            d.label, s.begin_line, s.begin_col, d.message
        )),
        (None, None) => shuttle::output::err(&d.message),
    }
}

// ── Lock command ──

/// Human-readable old→new line for one refreshed input pin.
fn pin_update_line(u: &shuttle::pkg_source::InputPinUpdate) -> String {
    let short = |s: &Option<String>| s.as_deref().map(|r| r.get(..7).unwrap_or(r).to_string());
    if u.local {
        return format!("{}: local (unlocked)", u.name);
    }
    match (short(&u.old), short(&u.new)) {
        (Some(old), Some(new)) if old != new => format!("{}: {} -> {}", u.name, old, new),
        (Some(rev), _) => format!("{}: {} (unchanged)", u.name, rev),
        (None, Some(new)) => format!("{}: new pin {}", u.name, new),
        (None, None) => format!("{}: no revision resolved", u.name),
    }
}

/// `shuttle lock`: resolve/refresh all input pins without building.
fn cmd_lock(file: String, lockfile_path: String) -> miette::Result<()> {
    let inputs = if Path::new(&file).exists() {
        match shuttle::lua::evaluate_file_with_inputs(&file) {
            Ok(eval) if !eval.global_inputs.is_empty() => eval.global_inputs,
            Ok(_) => {
                shuttle::output::info(format!("no inputs declared in '{file}', using default"));
                default_input_map()
            }
            Err(e) => {
                return Err(miette::miette!("failed to read inputs from '{file}': {e}"));
            }
        }
    } else {
        shuttle::output::info(format!("no config at '{file}', using default input"));
        default_input_map()
    };

    let lock_path = Path::new(&lockfile_path);
    let mut lockfile = LockFile::load(lock_path)?.unwrap_or_else(|| LockFile {
        version: 1,
        sources: HashMap::new(),
        snaps: HashMap::new(),
        inputs: HashMap::new(),
    });

    // Empty names = refresh every declared input. All pins are resolved
    // before any is applied: a failed refresh never half-updates the lock.
    let updates = shuttle::pkg_source::update_input_pins(&inputs, &[], &mut lockfile)?;

    for u in &updates {
        shuttle::output::status(pin_update_line(u));
    }
    for (name, entry) in &lockfile.inputs {
        if entry.local {
            shuttle::output::status(format!("{name}: local (unlocked)"));
        } else if let Some(rev) = &entry.revision {
            shuttle::output::status(format!("{name}: pinned to {}", rev.get(..7).unwrap_or(rev)));
        }
    }

    lockfile.save(lock_path)?;

    if shuttle::output::is_json() {
        let mut pins: Vec<shuttle::output::LockPinJson> = lockfile
            .inputs
            .iter()
            .map(|(name, e)| shuttle::output::LockPinJson {
                name: name.clone(),
                local: e.local,
                revision: e.revision.clone(),
                sha256: e.sha256.clone(),
            })
            .collect();
        pins.sort_by(|a, b| a.name.cmp(&b.name));
        let out = shuttle::output::LockOutputJson {
            command: "lock".to_string(),
            lockfile: lockfile_path.clone(),
            updated: updates.len(),
            pins,
        };
        let json = serde_json::to_string_pretty(&out)
            .map_err(|e| miette::miette!("failed to serialize lock output: {e}"))?;
        println!("{json}");
    } else {
        shuttle::output::ok(format!(
            "{} input(s) locked -> {lockfile_path}",
            updates.len()
        ));
    }
    Ok(())
}

// ── Eval command ──

/// `shuttle eval`: evaluate a definition and emit the image manifest IR
/// (Phase 23, cross-distro-synthesis §5). No build, no store writes.
///
/// Resolution is data-only — definition pins, the Phase 16 lockfile, and
/// pre-resolved package-index pins — so a fully pinned project evals
/// offline and the result is a deterministic function of the definition +
/// lockfile. `--offline` additionally forbids fetching uncached package
/// inputs (named fail-closed error, same as build). Unresolvable pins and
/// missing lock entries fail closed: no partial manifest is ever written.
#[allow(clippy::too_many_arguments)]
fn cmd_eval(
    file: String,
    output: Option<String>,
    output_name: Option<String>,
    arch: String,
    channel: String,
    lockfile_path: String,
    offline: bool,
) -> miette::Result<()> {
    let file = resolve_file(&file)?;
    // Image resolution (index pins are per-arch) and the DSL's `arch`
    // global both key off this.
    std::env::set_var("SHUTTLE_ARCH", &arch);

    let lock_path = Path::new(&lockfile_path);
    let mut lockfile = load_lockfile_or_default(lock_path)?;

    // Definition eval: snap outputs + global inputs, through the bounded
    // subprocess worker.
    let eval = shuttle::lua::evaluate_file_with_inputs(&file)?;

    // Materialize declared package inputs through their Phase 16 pins.
    // Online: record missing pins first (record-once, like build). Offline:
    // uncached/pinned inputs fail with the named "--offline prevents
    // fetching" error. The lockfile is only saved after materialization
    // succeeds, so a failed eval records nothing.
    let mut pins_recorded = false;
    if !eval.global_inputs.is_empty() {
        if !offline {
            let n = shuttle::pkg_source::ensure_input_pins(&eval.global_inputs, &mut lockfile)?;
            pins_recorded |= n > 0;
        }
        shuttle::pkg_source::init_global_inputs_with(
            &eval.global_inputs,
            &lockfile.inputs,
            offline,
        )?;
        if pins_recorded {
            lockfile.save(lock_path)?;
        }
    }

    // Image declarations (a second bounded eval of the same file, sharing
    // the worker output table with the snap outputs).
    let images = resolve_images(&file)?;

    let manifest = shuttle::manifest::build_manifest(
        &eval.outputs,
        &images,
        &eval.global_inputs,
        &lockfile,
        &arch,
        &channel,
        output_name.as_deref(),
    )?;

    match output {
        Some(ref out_path) => {
            manifest.write_atomic(Path::new(out_path))?;
            if !shuttle::output::is_json() {
                shuttle::output::ok(format!(
                    "manifest -> {out_path} ({} output(s), {} image(s))",
                    manifest.outputs.len(),
                    manifest.images.len()
                ));
            }
        }
        None => {
            let json = manifest.to_json()?;
            // to_json ends with a newline; print without adding another so
            // stdout bytes == file bytes.
            print!("{json}");
        }
    }
    Ok(())
}

// ── Index command ──

// ── Cache command ──

fn cmd_cache(sub: CacheCommand) -> miette::Result<()> {
    match sub {
        CacheCommand::Info { cache } => {
            cache_info(PackageCache::new(cache.map(std::path::PathBuf::from)))
        }
        CacheCommand::Clear { cache, force } => cache_clear(
            PackageCache::new(cache.map(std::path::PathBuf::from)),
            force,
        ),
        CacheCommand::Prune { days, cache, force } => cache_prune(
            days,
            PackageCache::new(cache.map(std::path::PathBuf::from)),
            force,
        ),
    }
}

/// `shuttle cache info`: print cache statistics.
fn cache_info(cache: PackageCache) -> miette::Result<()> {
    let info = cache.info()?;
    eprintln!("Cache directory: {}", info.root.display());
    eprintln!("Unique source entries: {}", info.entries);
    eprintln!("Cached packages: {}", info.packages);
    eprintln!(
        "Disk usage: {}",
        if info.size_bytes > 1_000_000_000 {
            format!("{:.1} GB", info.size_bytes as f64 / 1_000_000_000.0)
        } else if info.size_bytes > 1_000_000 {
            format!("{:.1} MB", info.size_bytes as f64 / 1_000_000.0)
        } else {
            format!("{} bytes", info.size_bytes)
        }
    );
    Ok(())
}

/// `shuttle cache clear`: remove all cached packages, guarded by `--force`.
fn cache_clear(cache: PackageCache, force: bool) -> miette::Result<()> {
    let info = cache.info()?;
    if info.entries == 0 {
        eprintln!("Cache is already empty at {}", info.root.display());
        return Ok(());
    }
    if !force {
        eprintln!(
            "This will remove {} cached packages ({} entries, {:.1} MB).",
            info.packages,
            info.entries,
            info.size_bytes as f64 / 1_000_000.0
        );
        eprintln!("Use --force to confirm.");
        return Ok(());
    }
    cache.clear()?;
    shuttle::output::ok("cache cleared");
    Ok(())
}

/// `shuttle cache prune`: remove cache entries not accessed in `days`,
/// guarded by `--force`.
fn cache_prune(days: u64, cache: PackageCache, force: bool) -> miette::Result<()> {
    if !force {
        eprintln!(
            "This will remove cache entries not accessed in {} days.",
            days
        );
        eprintln!("Use --force to confirm.");
        return Ok(());
    }
    let removed = cache.prune(days)?;
    if removed > 0 {
        shuttle::output::ok(format!(
            "pruned {} cache entr{}",
            removed,
            if removed == 1 { "y" } else { "ies" }
        ));
    } else {
        eprintln!("Nothing to prune.");
    }
    Ok(())
}

// ── Search command ──

/// Fuzzy match score between query and target (0 = no match, higher = better).
///
/// Scoring:
/// - Exact match: 100
/// - Prefix match: 90
/// - Subsequence match: proportional to consecutive/total matched, minus gap penalty
fn fuzzy_score(query: &str, target: &str) -> u32 {
    let q = query.to_lowercase();
    let t = target.to_lowercase();

    if q.is_empty() || t.is_empty() {
        return 0;
    }

    if t == q {
        return 100;
    }
    if t.starts_with(&q) {
        return 90;
    }
    if t.contains(&q) {
        return 80;
    }

    // Subsequence matching: characters of query appear in order in target
    let q_chars: Vec<char> = q.chars().collect();
    let t_chars: Vec<char> = t.chars().collect();
    let mut qi = 0;
    let mut prev_match: Option<usize> = None;
    let mut consecutive = 0u32;
    let mut max_consecutive = 0u32;
    let mut gaps = 0u32;

    for (ti, tc) in t_chars.iter().enumerate() {
        if qi < q_chars.len() && *tc == q_chars[qi] {
            if let Some(prev) = prev_match {
                if ti == prev + 1 {
                    consecutive += 1;
                } else {
                    gaps += (ti - prev - 1) as u32;
                    consecutive = 0;
                }
            } else {
                consecutive = 1;
            }
            max_consecutive = max_consecutive.max(consecutive);
            prev_match = Some(ti);
            qi += 1;
        }
    }

    if qi < q_chars.len() {
        return 0; // not all query chars matched
    }

    let base = 60u32;
    let consec_bonus = (max_consecutive.saturating_sub(1)) * 5;
    let gap_penalty = gaps.min(20);
    base + consec_bonus - gap_penalty
}

fn cmd_search(query: &str, json: bool) {
    // Ensure global inputs are initialized for iter_packages
    let _ = shuttle::pkg_source::init_global_inputs(&HashMap::new());

    let candidates = shuttle::pkg_source::iter_packages();
    let mut scored: Vec<(u32, String)> = Vec::new();

    // Score all candidates
    for name in &candidates {
        let score = fuzzy_score(query, name);
        if score > 0 {
            scored.push((score, name.clone()));
        }
    }

    // Sort: highest score first, then alphabetically
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));

    if json {
        let results: Vec<&str> = scored.iter().map(|(_, n)| n.as_str()).collect();
        println!(
            "{}",
            serde_json::json!({
                "command": "search",
                "query": query,
                "results": results
            })
        );
    } else {
        eprintln!("Packages matching '{}':", query);
        if scored.is_empty() {
            eprintln!("  (no matches)");
        } else {
            for (_, name) in &scored {
                eprintln!("  {}", name);
            }
            eprintln!("  {} package(s) found", scored.len());
        }
    }
}

// ── Completion command ──

fn cmd_completion(shell: clap_complete::Shell) -> miette::Result<()> {
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
    Ok(())
}

// ── Index command ──

fn cmd_index(sub: IndexCommand) -> miette::Result<()> {
    match sub {
        IndexCommand::Update { file } => {
            index_update(&file);
            Ok(())
        }
        IndexCommand::List { index } => index_list(&index),
        IndexCommand::Add {
            name,
            summary,
            store_name,
            channel,
            alias,
            index,
        } => index_add(name, summary, store_name, channel, alias, index),
        IndexCommand::Resolve { index, channel } => index_resolve(&index, &channel),
    }
}

/// `shuttle index update`: refresh package inputs from the config file, or
/// the default input when the file is absent/unreadable/empty.
fn index_update(file: &str) {
    let inputs = if Path::new(file).exists() {
        match shuttle::lua::evaluate_file_with_inputs(file) {
            Ok(eval) => eval.global_inputs,
            Err(_) => {
                eprintln!("  could not read inputs from '{file}', using default");
                HashMap::new()
            }
        }
    } else {
        HashMap::new()
    };

    if inputs.is_empty() {
        let default = PackageInput {
            url: "github:rbelem/shuttle/main".into(),
        };
        eprintln!("  Updating default package index...");
        if let Err(e) = shuttle::pkg_source::refresh_input(&default) {
            eprintln!("  ✗ failed: {e}");
        } else {
            eprintln!("  ✓ default package index updated");
        }
    } else {
        for (name, input) in &inputs {
            eprintln!("  Updating input '{name}'...");
            match shuttle::pkg_source::refresh_input(input) {
                Ok(_) => eprintln!("  ✓ '{name}' updated"),
                Err(e) => eprintln!("  ✗ '{name}' failed: {e}"),
            }
        }
    }
}

/// `shuttle index list`: print every index entry with its kind and pin
/// count.
fn index_list(index: &str) -> miette::Result<()> {
    let path = Path::new(index);
    let idx = if path.exists() {
        PackageIndex::load(path)?
    } else {
        PackageIndex::load_or_default(path)?
    };

    eprintln!("Package index: {} entries", idx.snaps.len());
    eprintln!();
    for entry in &idx.snaps {
        let kind = if entry.store.is_some() {
            "store"
        } else if entry.source.is_some() {
            "source"
        } else {
            "unknown"
        };
        let pins = entry
            .pins
            .as_ref()
            .map(|p| p.len().to_string())
            .unwrap_or_else(|| "-".into());
        eprintln!("  {:<20} {}    pins: {}", entry.name, kind, pins);
    }
    Ok(())
}

/// `shuttle index add`: upsert a store-backed entry and save the index.
fn index_add(
    name: String,
    summary: Option<String>,
    store_name: Option<String>,
    channel: String,
    alias: Vec<String>,
    index: String,
) -> miette::Result<()> {
    let path = Path::new(&index);
    let mut idx = if path.exists() {
        PackageIndex::load(path)?
    } else {
        PackageIndex {
            version: 1,
            snaps: vec![],
        }
    };

    let entry = IndexEntry {
        name: name.clone(),
        summary,
        store: Some(StoreRef {
            name: store_name,
            channel,
        }),
        pins: None,
        source: None,
        build: None,
        apps: None,
        aliases: alias,
    };

    idx.upsert(entry);
    idx.save(path)?;
    shuttle::output::ok(format!("added '{}' to index", name));
    Ok(())
}

/// `shuttle index resolve`: query the Snap Store for every entry's pins and
/// save the updated index.
fn index_resolve(index: &str, channel: &str) -> miette::Result<()> {
    let path = Path::new(index);
    let mut idx = if path.exists() {
        PackageIndex::load(path)?
    } else {
        eprintln!("  index file not found at {}", index);
        return Ok(());
    };

    eprintln!("Resolving snap pins from store (channel: {channel})...");
    idx.resolve_all(channel)?;
    idx.save(path)?;
    shuttle::output::ok(format!("index updated: {}", index));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_ok_message_prints_identity() {
        let outputs = vec![
            ("bzip2".to_string(), "1.0.8".to_string()),
            ("hello".to_string(), "2.10".to_string()),
        ];
        assert_eq!(
            check_ok_message(&outputs),
            "ok: 2 output(s): bzip2 1.0.8, hello 2.10"
        );
        assert_eq!(check_ok_message(&[]), "ok: 0 output(s)");
    }
}
