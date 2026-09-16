use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use clap::Parser;
use shuttle::cache::PackageCache;
use shuttle::cli::{
    CacheCommand, Cli, Command, DepsCommand, IndexCommand, KeyCommand, PodCommand, RuntimeCommand,
};
use shuttle::image::ImageDeclaration;
use shuttle::index::{IndexEntry, PackageIndex, StoreRef};
use shuttle::lock::{LockFile, SourceLockEntry};
use shuttle::runtime::{changed_pins, PendingSnap, RuntimeStore, RuntimeTools, SignatureEnvelope};
use shuttle::snap::{PackageInput, SnapRef, SourceSpec};

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

        Command::Deps(sub) => match sub {
            DepsCommand::Show {
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
            DepsCommand::Fetch {
                name,
                root,
                latest,
                json,
            } => {
                shuttle::output::set_mode(json);
                let r = cmd_deps_fetch(name.as_deref(), root.as_deref(), latest);
                shuttle::output::flush_json("deps");
                r
            }
        },

        Command::Search { query, json } => {
            shuttle::output::set_mode(json);
            cmd_search(&query, json);
            Ok(())
        }

        Command::Index(sub) => cmd_index(sub),

        Command::Doctor { pod } => cmd_doctor(pod),

        Command::Check { file, json } => {
            shuttle::output::set_mode(json);
            cmd_check(&file, json)
        }

        Command::Lint {
            file,
            pod,
            channel,
            json,
        } => cmd_lint(file, pod, channel, json),

        Command::Audit {
            file,
            lockfile,
            update,
            json,
        } => cmd_audit(file, lockfile, update, json),

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

        Command::Key(sub) => cmd_key(sub),

        Command::Runtime(sub) => cmd_runtime(sub),

        Command::Pod { name, command } => cmd_pod(name.as_deref(), command),

        Command::Run {
            app,
            pod,
            root,
            app_args,
        } => cmd_run(pod.as_deref(), root.as_deref(), &app, &app_args),

        Command::Test {
            image,
            timeout,
            accel,
            log,
            require,
            firmware_dir,
            runs,
            expect_counter_seq,
            allow_no_completion,
            qemu_args,
            json,
        } => {
            shuttle::output::set_mode(json);
            cmd_test(
                image,
                timeout,
                accel,
                log,
                require,
                firmware_dir,
                runs,
                expect_counter_seq,
                allow_no_completion,
                qemu_args,
                json,
            )
        }

        Command::Push {
            reference,
            dir,
            snap,
            image,
            tag,
            username,
            password_stdin,
            insecure_http,
            mount_from,
            record,
            json,
        } => {
            shuttle::output::set_mode(json);
            cmd_push(
                &reference,
                &dir,
                &snap,
                &image,
                tag.as_deref(),
                username.as_deref(),
                password_stdin,
                insecure_http,
                mount_from.as_deref(),
                record.as_deref(),
            )
        }

        Command::Pull {
            reference,
            out_dir,
            username,
            password_stdin,
            insecure_http,
            expect,
            install,
            state_dir,
            json,
        } => {
            shuttle::output::set_mode(json);
            cmd_pull(
                &reference,
                out_dir,
                username.as_deref(),
                password_stdin,
                insecure_http,
                expect.as_deref(),
                install,
                state_dir,
            )
        }

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
            submodules: None,
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
    let seeds = shuttle::deps::build_dep_seeds(meta);
    let mut names: Vec<String> = if seeds.is_empty() {
        Vec::new()
    } else {
        shuttle::deps::resolve_dep_names(&seeds, true).unwrap_or_default()
    };
    names.sort();
    names.dedup();
    let requires = names
        .iter()
        .map(|name| requires_member(name, lockfile))
        .collect();
    // Build deps join the closure so a changed build_dep invalidates the
    // cache key (ADR-0018 Decision 4, issue #22).
    let mut dep_names = meta.build_deps.clone();
    dep_names.sort();
    dep_names.dedup();
    let build_deps = dep_names
        .iter()
        .map(|name| requires_member(name, lockfile))
        .collect();
    shuttle::cache::BuildClosure::for_meta(meta, requires, build_deps)
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
        let all_deps = collect_dep_graph(&iter);
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
fn load_lockfile_or_default(lock_path: &Path) -> miette::Result<LockFile> {
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
            // `Outputs` is a HashMap: without a stable sort, multi-output
            // definitions build in nondeterministic order run to run.
            vec.sort_by_key(|(a, _)| *a);
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
/// first-seen order. Seeds are the build-time dependency union
/// (`requires` ∪ `build_deps`) — both kinds get built (ADR-0018).
fn collect_dep_graph(iter: &[(&String, shuttle::snap::SnapMeta)]) -> Vec<shuttle::deps::DepNode> {
    let mut nodes: Vec<shuttle::deps::DepNode> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (_name, meta) in iter {
        let seeds = shuttle::deps::build_dep_seeds(meta);
        if !seeds.is_empty() {
            if let Ok(deps) = shuttle::deps::resolve_deps(&seeds, true) {
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
    meta: &shuttle::snap::SnapMeta,
    arch: &str,
    output_dir: &Path,
    pkg_cache: Option<&PackageCache>,
    lockfile: &LockFile,
    json: bool,
    quiet: bool,
    building: &mut Vec<String>,
) -> miette::Result<Option<shuttle::build_prefix::MergedPrefix>> {
    // Only source builds consume a build prefix — meta/store snaps and
    // fetch-only declarations never run a build command.
    if meta.build.is_none() && meta.parts.is_none() {
        return Ok(None);
    }
    let seeds = shuttle::deps::build_dep_seeds(meta);
    if seeds.is_empty() {
        return Ok(None);
    }
    let closure_names = shuttle::deps::resolve_dep_names(&seeds, true)?;
    let mut payloads = Vec::new();
    for name in closure_names {
        let dep_meta = shuttle::deps::load_meta(&name)?;
        let snap = ensure_dep_payload(
            &name, &dep_meta, arch, output_dir, pkg_cache, lockfile, json, quiet, building,
        )?;
        payloads.push(shuttle::build_prefix::Payload { pkg: name, snap });
    }
    let merged = shuttle::build_prefix::materialize_merged_prefix(&payloads)?;
    if !json && !quiet && !payloads.is_empty() {
        let names: Vec<&str> = payloads.iter().map(|p| p.pkg.as_str()).collect();
        shuttle::output::status(format!(
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
    dep_meta: &shuttle::snap::SnapMeta,
    arch: &str,
    output_dir: &Path,
    pkg_cache: Option<&PackageCache>,
    lockfile: &LockFile,
    json: bool,
    quiet: bool,
    building: &mut Vec<String>,
) -> miette::Result<PathBuf> {
    let filename = format!("{}_{}_{}.snap", name, dep_meta.version, arch);
    let in_output = output_dir.join(&filename);
    if in_output.exists() {
        return Ok(in_output);
    }

    // Closure key for the cache lookup/store (same computation the --all
    // dep path uses).
    let closure = pkg_cache.map(|_| build_closure(dep_meta, lockfile));
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
        dep_meta, arch, output_dir, pkg_cache, lockfile, json, quiet, building,
    )?;

    shuttle::snap::check_cross_build(arch, dep_meta.target.as_deref())?;
    if !json && !quiet {
        shuttle::output::status(format!("building dependency {name} ({arch})..."));
    }
    let stage = tempfile::tempdir()
        .map_err(|e| miette::miette!("failed to create temp stage for {name}: {e}"))?;
    let scan_listings = match &dep_prefix {
        Some(p) => shuttle::leak_scan::listings_for_build(dep_meta, p)?,
        None => shuttle::leak_scan::PayloadListings::default(),
    };

    let result = shuttle::snap::build_snap(
        dep_meta,
        stage.path(),
        output_dir,
        arch,
        shuttle::snap::StagePolicy::Default,
        // Dependency builds have no pod store and no interpreted closure.
        None,
        None,
        dep_prefix.as_ref().map(|t| t.path()),
        Some(&scan_listings),
    )?;
    if !json && !quiet {
        shuttle::output::ok(&result.snap_filename);
    }
    if let (Some(cache), Some(closure)) = (pkg_cache, closure.as_ref()) {
        let _store_lock = CACHE_STORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = cache.store(dep_meta, &result, output_dir, closure) {
            shuttle::output::warn(format!("cache store failed: {e}"));
        }
    }

    building.pop();
    Ok(output_dir.join(&result.snap_filename))
}

/// Per-package parallel build job context (issue #55): everything one
/// ready-node build borrows from the orchestrator. Fields are read-only
/// for the whole phase; the scheduler runs one `run` per node.
struct DepJobCtx<'a> {
    metas: &'a BTreeMap<String, shuttle::snap::SnapMeta>,
    closures: &'a HashMap<String, Option<shuttle::cache::BuildClosure>>,
    cli_archs: &'a [String],
    output_dir: &'a Path,
    pkg_cache: Option<&'a shuttle::cache::PackageCache>,
    lockfile: &'a LockFile,
    json: bool,
    total: usize,
    dispatch: &'a AtomicUsize,
}

impl DepJobCtx<'_> {
    /// Build one scheduled package: attributable start/finish lines here,
    /// quiet build inside, error prefixed per line for the final report.
    fn run(&self, name: &str) -> Result<(), String> {
        let meta = self.metas.get(name).expect("scheduled node was loaded");
        let archs = shuttle::snap::resolve_archs(meta, self.cli_archs);
        let dep_closure = self.closures[name].as_ref();
        let slot = self.dispatch.fetch_add(1, Ordering::SeqCst) + 1;
        if !self.json {
            eprintln!("▶ [{slot}/{}] {name} ({})", self.total, archs.join(", "));
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
        ) {
            Ok(()) => {
                if !self.json {
                    eprintln!("✓ [{slot}/{}] {name}", self.total);
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
    dep_nodes: &[shuttle::deps::DepNode],
    effective_target: Option<&String>,
) -> BTreeMap<String, shuttle::snap::SnapMeta> {
    let mut metas = BTreeMap::new();
    for node in dep_nodes {
        match shuttle::deps::load_meta(&node.name) {
            Ok(mut m) => {
                // Apply --target to deps as well
                if let Some(t) = effective_target {
                    m.target = Some(t.clone());
                }
                metas.insert(node.name.clone(), m);
            }
            Err(e) => {
                shuttle::output::warn(format!("skipping dependency '{}': {}", node.name, e));
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
    metas: &BTreeMap<String, shuttle::snap::SnapMeta>,
    pkg_cache: Option<&shuttle::cache::PackageCache>,
    lockfile: &LockFile,
) -> HashMap<String, Option<shuttle::cache::BuildClosure>> {
    metas
        .iter()
        .map(|(name, meta)| {
            (
                name.clone(),
                pkg_cache.map(|_| build_closure(meta, lockfile)),
            )
        })
        .collect()
}

/// Names whose every resolved arch is already cached under their closure
/// key: complete before scheduling starts, releasing dependents at once.
/// (The check reads only the dep's own closure key, so checking here
/// equals checking just before its build — nothing else writes its
/// entries.)
fn cached_dep_names(
    metas: &BTreeMap<String, shuttle::snap::SnapMeta>,
    closures: &HashMap<String, Option<shuttle::cache::BuildClosure>>,
    pkg_cache: Option<&shuttle::cache::PackageCache>,
    cli_archs: &[String],
    json: bool,
) -> HashSet<String> {
    let mut cached = HashSet::new();
    for (name, meta) in metas {
        if let (Some(cache), Some(closure)) = (pkg_cache, closures[name].as_ref()) {
            if dep_fully_cached(cache, closure, meta, cli_archs) {
                cached.insert(name.clone());
                if !json {
                    shuttle::output::ok(format!("{} (cached)", name));
                }
            }
        }
    }
    cached
}

/// Resolve and build every transitive dependency of the selected outputs
/// (--all mode), consulting the binary cache per dep when one is active.
///
/// Parallel across packages (issue #55, ADR-0022 Decision 3): the graph
/// from `deps.rs` is scheduled by [`shuttle::build_sched`] — every READY
/// node builds concurrently up to
/// [`shuttle::build_sched::MAX_PARALLEL_BUILD_WORKERS`], and dependents
/// wake as their last dependency completes. Build isolation is unchanged:
/// each package still builds in its own tempdir stage inside its own bwrap
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
    dep_nodes: &[shuttle::deps::DepNode],
    effective_target: Option<&String>,
    pkg_cache: Option<&shuttle::cache::PackageCache>,
    cli_archs: &[String],
    output_dir: &Path,
    lockfile: &LockFile,
    json: bool,
) -> miette::Result<()> {
    if dep_nodes.is_empty() {
        return Ok(());
    }
    let metas = load_dep_metas(dep_nodes, effective_target);
    if metas.is_empty() {
        return Ok(());
    }
    let closures = precompute_dep_closures(&metas, pkg_cache, lockfile);
    let pre_done = cached_dep_names(&metas, &closures, pkg_cache, cli_archs, json);

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
    if !json {
        eprintln!(
            "── Building {to_build} dependencies (up to {} in parallel) ──",
            shuttle::build_sched::MAX_PARALLEL_BUILD_WORKERS.min(to_build),
        );
    }

    // Scoped output discipline for the parallel phase (issue #55): worker
    // builds hold their progress output; `DepJobCtx::run` prints the
    // attributable per-package lines, and build-child stderr is buffered
    // per package instead of streaming into other packages' output. Both
    // flags are set once around the whole phase — the orchestrator thread
    // blocks inside `run_ready_set` — and restored before returning.
    shuttle::output::set_quiet_build(true);
    shuttle::snap::set_buffer_child_stderr(true);
    let dispatch = AtomicUsize::new(0);
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
    };
    let scheduled = shuttle::build_sched::run_ready_set(
        &graph,
        &pre_done,
        shuttle::build_sched::MAX_PARALLEL_BUILD_WORKERS,
        |name| ctx.run(name),
    );
    shuttle::snap::set_buffer_child_stderr(false);
    shuttle::output::set_quiet_build(false);

    match scheduled {
        Ok(()) => Ok(()),
        Err(failed) => Err(report_failed_builds(&failed)),
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
/// it.
fn report_failed_builds(failed: &shuttle::build_sched::FailedBuilds) -> miette::Error {
    let names: Vec<String> = failed.failed.iter().map(|(n, _)| n.clone()).collect();
    let mut msg = format!(
        "{} package build(s) failed: {}",
        failed.failed.len(),
        names.join(", ")
    );
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
    dep_meta: &shuttle::snap::SnapMeta,
    dep_archs: &[String],
    output_dir: &Path,
    pkg_cache: Option<&shuttle::cache::PackageCache>,
    dep_closure: Option<&shuttle::cache::BuildClosure>,
    lockfile: &LockFile,
    json: bool,
    quiet: bool,
) -> miette::Result<()> {
    for a in dep_archs {
        shuttle::snap::check_cross_build(a, dep_meta.target.as_deref())?;
        if !json && !quiet {
            shuttle::output::status(format!("building {} ({})...", dep_name, a));
        }
        let dep_stage = tempfile::tempdir()
            .map_err(|e| miette::miette!("failed to create temp stage: {}", e))?;

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
        )?;

        let scan_listings = match &build_prefix {
            Some(p) => shuttle::leak_scan::listings_for_build(dep_meta, p)?,
            None => shuttle::leak_scan::PayloadListings::default(),
        };

        match shuttle::snap::build_snap(
            dep_meta,
            dep_stage.path(),
            output_dir,
            a,
            shuttle::snap::StagePolicy::Default,
            None,
            // Plain recursive builds have no pod dependency closure.
            None,
            build_prefix.as_ref().map(|p| p.path()),
            Some(&scan_listings),
        ) {
            Ok(result) => {
                if !json && !quiet {
                    shuttle::output::ok(&result.snap_filename);
                }
                if let (Some(cache), Some(closure)) = (pkg_cache, dep_closure) {
                    let _store_lock = CACHE_STORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                    if let Err(e) = cache.store(dep_meta, &result, output_dir, closure) {
                        shuttle::output::warn(format!("cache store failed: {}", e));
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

/// Build every selected output across its resolved archs, collecting the
/// source infos recorded during the builds (for lockfile pinning).
#[allow(clippy::too_many_arguments)]
fn build_outputs(
    iter: &[(&String, shuttle::snap::SnapMeta)],
    cli_archs: &[String],
    stage_dir: &Path,
    stage_policy: shuttle::snap::StagePolicy,
    output_dir: &Path,
    pkg_cache: Option<&PackageCache>,
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
    meta: &shuttle::snap::SnapMeta,
    arch: &str,
    stage_dir: &Path,
    stage_policy: shuttle::snap::StagePolicy,
    output_dir: &Path,
    pkg_cache: Option<&PackageCache>,
    lockfile: &LockFile,
    json: bool,
) -> miette::Result<Vec<shuttle::snap::SourceInfo>> {
    shuttle::snap::check_cross_build(arch, meta.target.as_deref())?;
    if !json {
        shuttle::output::status(format!("{}/{}:", name, arch));
    }

    if let Some(SourceSpec::Unverified(ref url)) = meta.source {
        if lockfile.lookup_source(url).is_some() {
            shuttle::output::info(format!("using lockfile hash for {url}"));
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
    )?;

    // Post-build leak-scan resolution data (ADR-0018 Decision 3, issue
    // #22): every build runs the scan; when no prefix was materialized
    // there are no payloads, so the listings are empty and the scan just
    // reports zero build-only refs.
    let scan_listings = match &build_prefix {
        Some(p) => shuttle::leak_scan::listings_for_build(meta, p)?,
        None => shuttle::leak_scan::PayloadListings::default(),
    };

    let result = shuttle::snap::build_snap(
        meta,
        stage_dir,
        output_dir,
        arch,
        stage_policy,
        None,
        None,
        build_prefix.as_ref().map(|p| p.path()),
        Some(&scan_listings),
    )?;
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
            sha256: result.source_infos.first().map(|s| s.sha256.clone()),
            // Multi-source builds (issue #41) report every pinned source;
            // single-source builds keep the flat `sha256` field only.
            sources: (!result.source_infos.is_empty()).then(|| {
                result
                    .source_infos
                    .iter()
                    .map(|i| shuttle::output::SourcePinJson {
                        url: i.url.clone(),
                        sha256: i.sha256.clone(),
                    })
                    .collect()
            }),
        });
    }

    Ok(result.source_infos)
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

/// Pin build-time-only dependencies (`build_deps`) into the lockfile
/// (ADR-0018 Decision 4, issue #22). Each declared build_dep is recorded
/// with the resolved version (lockfile pin wins; else declared version) —
/// the same resolution the binary-cache closure uses — so a changed build
/// dependency is recorded and reproducible. The lockfile IS the pin record
/// (ADR-0017 Decision 5).
fn persist_build_deps_pins(
    lockfile: &mut LockFile,
    lock_path: &Path,
    iter: &[(&String, shuttle::snap::SnapMeta)],
    lockfile_path: &str,
) -> miette::Result<()> {
    let mut changed = false;
    for (_name, meta) in iter {
        for dep in &meta.build_deps {
            if lockfile.lookup_build_dep(dep).is_some() {
                continue;
            }
            let member = requires_member(dep, lockfile);
            lockfile.record_build_dep(
                dep,
                &shuttle::lock::BuildDepPin {
                    pin: member.pin.clone(),
                    hash: member.hash.clone(),
                },
            );
            changed = true;
        }
    }

    if changed {
        lockfile.save(lock_path)?;
        shuttle::output::ok(format!("lockfile updated: {lockfile_path}"));
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
        None => {
            // `Outputs` is a HashMap: sort for deterministic multi-output
            // report order run to run.
            let mut metas: Vec<(&String, &shuttle::snap::SnapMeta)> = all_outputs.iter().collect();
            metas.sort_by_key(|(name, _)| *name);
            metas.into_iter().map(|(_, meta)| meta).collect()
        }
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

/// JSON-mode order report for one output. Seeds resolution with the
/// build-time dependency union (`requires` ∪ `build_deps`).
fn report_order_json(meta: &shuttle::snap::SnapMeta) {
    let seeds = shuttle::deps::build_dep_seeds(meta);
    if seeds.is_empty() {
        return;
    }
    let seen: std::collections::HashSet<&str> = seeds.iter().map(|s| s.as_str()).collect();
    if let Ok(order) = shuttle::deps::resolve_dep_names(&seeds, true) {
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

    if meta.requires.is_empty() && meta.build_deps.is_empty() {
        eprintln!("  No dependencies");
        return;
    }

    eprintln!("  Direct requires:");
    for dep in &meta.requires {
        eprintln!("    - {}", dep);
    }

    if !meta.build_deps.is_empty() {
        eprintln!("  Direct build_deps:");
        for dep in &meta.build_deps {
            eprintln!("    - {}", dep);
        }
    }

    eprintln!("  Resolved build order (transitive):");
    let seeds = shuttle::deps::build_dep_seeds(meta);
    match shuttle::deps::resolve_dep_names(&seeds, true) {
        Ok(order) => {
            let seen: std::collections::HashSet<&str> = seeds.iter().map(|s| s.as_str()).collect();
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

/// `shuttle deps fetch` (ADR-0017, issue #13): force a dependency-closure
/// fetch for the pod's interpreted packages. Reports each fetched closure
/// (and whether content moved) plus locked packages left untouched.
fn cmd_deps_fetch(pod: Option<&str>, root: Option<&str>, latest: bool) -> miette::Result<()> {
    let pod_name = pod.unwrap_or(shuttle::pod::DEFAULT_POD);
    let root = shuttle::pod::pod_root(root);
    let report = shuttle::pod::fetch_pod_deps(&root, pod_name, latest)?;
    for entry in &report.fetched {
        if entry.changed {
            shuttle::output::ok(format!(
                "fetched dependency closure for '{}' ({:.12}…)",
                entry.name, entry.deps_hash
            ));
        } else {
            shuttle::output::info(format!(
                "dependency closure for '{}' re-fetched, content unchanged ({:.12}…)",
                entry.name, entry.deps_hash
            ));
        }
    }
    for name in &report.skipped {
        shuttle::output::info(format!(
            "skipped '{name}': locked and its closure pin is cached (use --latest to re-resolve)"
        ));
    }
    if report.fetched.is_empty() && report.skipped.is_empty() {
        shuttle::output::info(format!(
            "pod '{pod_name}' declares no dependency closures (deps = {{ npm = ... }} / pip)"
        ));
    }
    Ok(())
}

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
        .flat_map(|n| n.requires.iter().chain(&n.build_deps))
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
            build_deps: node.build_deps.clone(),
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
        if pkg.requires.is_empty() && pkg.build_deps.is_empty() {
            eprintln!("  No dependencies");
        } else {
            eprintln!("  Requires:");
            for dep in &pkg.requires {
                eprintln!("    - {}", dep);
            }
            if !pkg.build_deps.is_empty() {
                eprintln!("  Build deps:");
                for dep in &pkg.build_deps {
                    eprintln!("    - {}", dep);
                }
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
            sources: None,
        });
    } else {
        shuttle::output::ok(&fname);
    }
    Ok(())
}

// ── Doctor command ──

fn cmd_doctor(pod: bool) -> miette::Result<()> {
    let checks = if pod {
        shuttle::doctor::run_pod()
    } else {
        shuttle::doctor::run_all()
    };
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

    // ADR-0011 step (g): the confinement lint over the evaluated outputs
    // (Rust-side stage 2, never the Lua analyzer). WARNING severity — the
    // lint NEVER adds a failure mode: `ok` above is computed before it
    // runs, and its findings travel a separate channel (warn output /
    // `"lint"` JSON array), never the diagnostics list.
    let lint: Vec<shuttle::lint::LintWarning> = checked
        .as_ref()
        .filter(|c| c.error.is_none())
        .map(|c| shuttle::lint::confinement_lint(&c.outputs))
        .unwrap_or_default();
    for w in &lint {
        shuttle::output::warn(&w.message);
    }

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
        report_check_json(file, &names, &diagnostics, &lint);
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
/// array). `"lint"` carries the confinement lint warnings (step (g)) —
/// warnings, never failures; they never appear in `"diagnostics"`.
fn report_check_json(
    file: &str,
    outputs: &[String],
    diagnostics: &[shuttle::lua::CheckDiagnostic],
    lint: &[shuttle::lint::LintWarning],
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
    let lint_json: Vec<serde_json::Value> = lint
        .iter()
        .map(|w| {
            serde_json::json!({
                "key": w.key,
                "message": w.message,
            })
        })
        .collect();
    let report = serde_json::json!({
        "file": file,
        "ok": diagnostics.is_empty(),
        "outputs": outputs,
        "diagnostics": diags,
        "lint": lint_json,
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

// ── Lint command (issue #53) ──

/// Load the package index the same way the eval worker does
/// (`SHUTTLE_INDEX_PATH`, else `package-index.json` in the CWD).
fn lint_index() -> miette::Result<shuttle::index::PackageIndex> {
    let path = std::env::var("SHUTTLE_INDEX_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(shuttle::index::DEFAULT_INDEX));
    shuttle::index::PackageIndex::load_or_default(&path)
}

/// The declared stage directory of a definition file, when it exists:
/// `<definition dir>/stage` — the same default the build uses.
fn lint_stage_dir(file: &str) -> Option<std::path::PathBuf> {
    let dir = std::path::Path::new(file)
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let stage = dir.join("stage");
    stage.is_dir().then_some(stage)
}

/// One pod package's lint entry: resolved meta when the package resolves
/// from local inputs, `None` (warned later) when it does not.
fn lint_pod_package(spec_str: &str) -> shuttle::checks::PodPackageMeta {
    let Ok(spec) = shuttle::pod::parse_pod_package(spec_str) else {
        return shuttle::checks::PodPackageMeta {
            spec: spec_str.to_string(),
            name: spec_str.to_string(),
            meta: None,
        };
    };
    // Resolution is data-only over local inputs — never the network.
    let meta = shuttle::deps::load_meta(&spec.name).ok();
    shuttle::checks::PodPackageMeta {
        spec: spec_str.to_string(),
        name: spec.name,
        meta,
    }
}

/// Resolve a pod's declared packages to metas for the lint, offline: the
/// declaration comes from the pod state directory, each package
/// declaration from local inputs.
fn lint_pod(pod_name: &str) -> miette::Result<shuttle::checks::PodLintData> {
    let root = shuttle::pod::pod_root(None);
    let decl_path = shuttle::pod::pod_lua_path(&root, pod_name);
    if !decl_path.exists() {
        miette::bail!(
            "pod '{pod_name}' has no declaration at {} (read verbs do not initialize pods)",
            decl_path.display()
        );
    }
    let decl = shuttle::pod::evaluate_pod_file(&decl_path)?;
    let packages = decl
        .packages
        .iter()
        .map(|spec| lint_pod_package(spec))
        .collect();
    Ok(shuttle::checks::PodLintData {
        name: pod_name.to_string(),
        packages,
    })
}

/// One finding's human-readable line pair (message + fix hint).
fn lint_finding_lines(f: &shuttle::checks::Finding, label: &str) -> String {
    format!(
        "[{}] {label}: {} {}: {}\n           fix: {}",
        f.severity.as_str(),
        f.check,
        f.package,
        f.message,
        f.hint
    )
}

/// Human report: every finding on its channel, then a one-line summary.
fn report_lint_human(findings: &[shuttle::checks::Finding], label: &str) {
    for f in findings {
        let lines = lint_finding_lines(f, label);
        match f.severity {
            shuttle::checks::Severity::Error => shuttle::output::err(lines),
            shuttle::checks::Severity::Warn => shuttle::output::warn(lines),
        }
    }
    if findings.is_empty() {
        shuttle::output::ok("lint clean: 0 findings");
    } else {
        let errors = findings
            .iter()
            .filter(|f| f.severity == shuttle::checks::Severity::Error)
            .count();
        shuttle::output::status(format!(
            "lint: {errors} error(s), {} warning(s)",
            findings.len() - errors
        ));
    }
}

/// JSON report shape for `shuttle lint --json`.
fn report_lint_json(findings: &[shuttle::checks::Finding], label: &str) {
    let findings_json: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "check": f.check,
                "package": f.package,
                "severity": f.severity.as_str(),
                "message": f.message,
                "hint": f.hint,
            })
        })
        .collect();
    let errors = findings
        .iter()
        .filter(|f| f.severity == shuttle::checks::Severity::Error)
        .count();
    let report = serde_json::json!({
        "file": label,
        "ok": errors == 0,
        "errors": errors,
        "warnings": findings.len() - errors,
        "findings": findings_json,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
    );
}

/// `shuttle lint`: run the check battery over a definition file (or a
/// pod's packages) and report findings. Exit code 1 only on error findings.
fn cmd_lint(file: String, pod: Option<String>, channel: String, json: bool) -> miette::Result<()> {
    shuttle::output::set_mode(json);
    let index = lint_index()?;

    let (label, eval, pod_data) = if let Some(pod_name) = pod.as_deref() {
        let data = lint_pod(pod_name)?;
        let path = shuttle::pod::pod_lua_path(&shuttle::pod::pod_root(None), pod_name);
        (path.display().to_string(), None, Some(data))
    } else {
        let eval = shuttle::lua::lint_eval_file(&file)?;
        for d in &eval.diagnostics {
            shuttle::output::warn(d);
        }
        (file.clone(), Some(eval), None)
    };

    let empty_raw = BTreeMap::new();
    let empty_outputs = shuttle::lua::Outputs::new();
    let empty_images: std::collections::HashMap<String, shuttle::image::ImageDeclaration> =
        Default::default();
    let no_unparsed: Vec<String> = Vec::new();
    let stage_dir = eval.is_some().then(|| lint_stage_dir(&file)).flatten();
    let arch = std::env::var("SHUTTLE_ARCH").unwrap_or_else(|_| "amd64".into());

    let input = shuttle::checks::LintInput {
        file: std::path::Path::new(&label),
        arch: &arch,
        channel: &channel,
        outputs: eval.as_ref().map_or(&empty_outputs, |e| &e.outputs),
        images: eval.as_ref().map_or(&empty_images, |e| &e.images),
        raw: eval.as_ref().map_or(&empty_raw, |e| &e.raw),
        unparsed: eval.as_ref().map_or(&no_unparsed, |e| &e.unparsed),
        index: &index,
        pod: pod_data.as_ref(),
        stage_dir: stage_dir.as_deref(),
    };

    let findings = shuttle::checks::run_battery(&input);
    if json {
        report_lint_json(&findings, &label);
    } else {
        report_lint_human(&findings, &label);
    }

    if shuttle::checks::has_errors(&findings) {
        std::process::exit(1);
    }
    Ok(())
}

// ── Audit command (issue #52) ──

/// Human report: every finding on its channel, then summary lines
/// carrying the audit counters and the database state.
fn report_audit_human(report: &shuttle::audit::AuditReport, label: &str, cache_dir: &Path) {
    for f in &report.findings {
        let lines = lint_finding_lines(f, label);
        match f.severity {
            shuttle::checks::Severity::Error => shuttle::output::err(lines),
            shuttle::checks::Severity::Warn => shuttle::output::warn(lines),
        }
    }
    if report.findings.is_empty() {
        shuttle::output::ok("audit clean: 0 findings");
    } else {
        let errors = report
            .findings
            .iter()
            .filter(|f| f.severity == shuttle::checks::Severity::Error)
            .count();
        shuttle::output::status(format!(
            "audit: {} lockfile pin(s), {errors} error(s), {} warning(s)",
            report.targets,
            report.findings.len() - errors
        ));
    }
    if report.degraded {
        shuttle::output::warn(format!(
            "OSV database unreachable (offline?) — {} pin(s) left unaudited; run \
             `shuttle audit --update` when online (cache: {})",
            report.unaudited,
            cache_dir.display()
        ));
    }
}

/// JSON report: the `shuttle lint --json` shape (file/ok/errors/warnings/
/// findings) plus an additive `database` object for the audit counters.
fn report_audit_json(report: &shuttle::audit::AuditReport, label: &str) {
    let findings_json: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "check": f.check,
                "package": f.package,
                "severity": f.severity.as_str(),
                "message": f.message,
                "hint": f.hint,
            })
        })
        .collect();
    let errors = report
        .findings
        .iter()
        .filter(|f| f.severity == shuttle::checks::Severity::Error)
        .count();
    let out = serde_json::json!({
        "file": label,
        "ok": errors == 0,
        "errors": errors,
        "warnings": report.findings.len() - errors,
        "findings": findings_json,
        "database": {
            "degraded": report.degraded,
            "unaudited": report.unaudited,
        },
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".to_string())
    );
}

/// `shuttle audit`: check lockfile pins against the OSV vulnerability
/// database (issue #52). Exit code 1 only on confirmed (version-matched)
/// findings; offline/stale databases warn, never fail.
fn cmd_audit(
    file: Option<String>,
    lockfile: String,
    update: bool,
    json: bool,
) -> miette::Result<()> {
    shuttle::output::set_mode(json);
    let lock_path = Path::new(&lockfile);
    let Some(lock) = LockFile::load(lock_path)? else {
        miette::bail!(
            "no lockfile at '{lockfile}' — nothing to audit (build once to create it, \
             or pass --lockfile)"
        );
    };
    // An explicitly-given definition enriches the audit (declared
    // versions, output-key labels); a failing eval is a hard error.
    let raw = match &file {
        Some(f) => Some(shuttle::lua::lint_eval_file(f)?.raw),
        None => None,
    };

    let cfg = shuttle::audit::AuditConfig::from_env(update);
    let report = shuttle::audit::run_audit(&lock, raw.as_ref(), &cfg)?;

    if json {
        report_audit_json(&report, &lockfile);
    } else {
        report_audit_human(&report, &lockfile, &cfg.cache_dir);
    }

    if shuttle::checks::has_errors(&report.findings) {
        std::process::exit(1);
    }
    Ok(())
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
    let inputs = resolve_lock_inputs(&file)?;

    let lock_path = Path::new(&lockfile_path);
    let mut lockfile = LockFile::load(lock_path)?.unwrap_or_else(|| LockFile {
        version: 1,
        sources: HashMap::new(),
        snaps: HashMap::new(),
        inputs: HashMap::new(),
        packages: HashMap::new(),
        build_deps: HashMap::new(),
    });

    // Empty names = refresh every declared input. All pins are resolved
    // before any is applied: a failed refresh never half-updates the lock.
    let updates = shuttle::pkg_source::update_input_pins(&inputs, &[], &mut lockfile)?;

    report_lock_status(&updates, &lockfile);

    lockfile.save(lock_path)?;

    report_lock_output(&lockfile, &lockfile_path, updates.len())?;
    Ok(())
}

/// The inputs a `shuttle lock` run refreshes: the definition's global
/// inputs when the config exists and declares any, the default input
/// otherwise.
fn resolve_lock_inputs(file: &str) -> miette::Result<HashMap<String, PackageInput>> {
    let inputs = if Path::new(file).exists() {
        match shuttle::lua::evaluate_file_with_inputs(file) {
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
    Ok(inputs)
}

/// Status lines for a lock run: each refreshed pin (old→new), then every
/// pin currently recorded in the lockfile.
fn report_lock_status(updates: &[shuttle::pkg_source::InputPinUpdate], lockfile: &LockFile) {
    for u in updates {
        shuttle::output::status(pin_update_line(u));
    }
    for (name, entry) in &lockfile.inputs {
        if entry.local {
            shuttle::output::status(format!("{name}: local (unlocked)"));
        } else if let Some(rev) = &entry.revision {
            shuttle::output::status(format!("{name}: pinned to {}", rev.get(..7).unwrap_or(rev)));
        }
    }
}

/// JSON/human output tail for `shuttle lock` (the lockfile is already
/// saved by the time this runs).
fn report_lock_output(
    lockfile: &LockFile,
    lockfile_path: &str,
    updated: usize,
) -> miette::Result<()> {
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
            lockfile: lockfile_path.to_string(),
            updated,
            pins,
        };
        let json = serde_json::to_string_pretty(&out)
            .map_err(|e| miette::miette!("failed to serialize lock output: {e}"))?;
        println!("{json}");
    } else {
        shuttle::output::ok(format!("{} input(s) locked -> {lockfile_path}", updated));
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

    materialize_eval_input_pins(&eval.global_inputs, &mut lockfile, lock_path, offline)?;

    // Image declarations (a second bounded eval of the same file, sharing
    // the worker output table with the snap outputs).
    let images = resolve_images(&file)?;

    let mut manifest = shuttle::manifest::build_manifest(
        &eval.outputs,
        &images,
        &eval.global_inputs,
        &lockfile,
        &arch,
        &channel,
        output_name.as_deref(),
    )?;

    sign_eval_manifest(&mut manifest, &arch, &channel, offline);

    emit_eval_output(&manifest, output.as_deref())?;
    Ok(())
}

/// Materialize declared package inputs through their Phase 16 pins.
/// Online: record missing pins first (record-once, like build). Offline:
/// uncached/pinned inputs fail with the named "--offline prevents
/// fetching" error. The lockfile is only saved after materialization
/// succeeds, so a failed eval records nothing.
fn materialize_eval_input_pins(
    global_inputs: &HashMap<String, PackageInput>,
    lockfile: &mut LockFile,
    lock_path: &Path,
    offline: bool,
) -> miette::Result<()> {
    if global_inputs.is_empty() {
        return Ok(());
    }
    let mut pins_recorded = false;
    if !offline {
        let n = shuttle::pkg_source::ensure_input_pins(global_inputs, lockfile)?;
        pins_recorded |= n > 0;
    }
    shuttle::pkg_source::init_global_inputs_with(global_inputs, &lockfile.inputs, offline)?;
    if pins_recorded {
        lockfile.save(lock_path)?;
    }
    Ok(())
}

/// ADR-0011 step (d) + issue #56: opt-in manifest signing. A key at
/// ~/.config/shuttle/secret-key attests the canonical bytes (signatures
/// map excluded) and carries the SLSA-lite provenance under the
/// signature — builder, invocation, materials, subject digest. An
/// absent key keeps `signatures` {} with a note — eval never fails on
/// signing and never generates keys (that is the image build's
/// deliberate engagement; mandated signing is step (e)).
fn sign_eval_manifest(
    manifest: &mut shuttle::manifest::ImageManifest,
    arch: &str,
    channel: &str,
    offline: bool,
) {
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
    match shuttle::sign::load_secret_key(&home) {
        Ok(Some(kp)) => {
            let version = env!("CARGO_PKG_VERSION");
            match shuttle::sign::attest_eval(manifest, &kp, version, arch, channel, offline) {
                Ok(()) => eprintln!(
                    "  ✓ manifest signed with provenance (key id {}, builder {})",
                    kp.key_id(),
                    shuttle::sign::builder_id(version)
                ),
                Err(e) => eprintln!("  ⚠ signing skipped: {e:#}"),
            }
        }
        Ok(None) => {
            eprintln!(
                "  ℹ no signing key at {} — signatures left empty (opt-in until \
                 ceremony)",
                shuttle::sign::secret_key_path(&home).display()
            );
        }
        Err(e) => eprintln!("  ⚠ signing skipped: {e:#}"),
    }
}

/// Write the eval result: the manifest file plus a human confirmation
/// line, or the JSON bytes on stdout when no `--output` was given.
fn emit_eval_output(
    manifest: &shuttle::manifest::ImageManifest,
    output: Option<&str>,
) -> miette::Result<()> {
    match output {
        Some(out_path) => {
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

// ── Key ceremony (ADR-0011 step (e), ADR-0024 §4) ──

/// Resolve the key-ceremony home: the `--home` override, else `$HOME`
/// (the same default the build path uses). All ceremony state lives under
/// `<home>/.config/shuttle/`.
fn key_home(home: Option<String>) -> PathBuf {
    home.map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())))
}

fn cmd_key(sub: KeyCommand) -> miette::Result<()> {
    match sub {
        KeyCommand::Keygen { home, json } => {
            shuttle::output::set_mode(json);
            key_keygen(key_home(home))
        }
        KeyCommand::Rotate {
            home,
            manifest,
            window_days,
            json,
        } => {
            shuttle::output::set_mode(json);
            key_rotate(key_home(home), manifest, window_days)
        }
        KeyCommand::Promote { home, json } => {
            shuttle::output::set_mode(json);
            key_promote(key_home(home))
        }
        KeyCommand::Revoke { key_id, home, json } => {
            shuttle::output::set_mode(json);
            key_revoke(key_home(home), &key_id)
        }
        KeyCommand::List { home, json } => {
            shuttle::output::set_mode(json);
            key_list(key_home(home))
        }
        KeyCommand::Verify {
            manifest,
            home,
            json,
        } => {
            shuttle::output::set_mode(json);
            key_verify(key_home(home), &manifest)
        }
    }
}

/// `shuttle key keygen`: mint the secret key and trust it immediately.
/// Never prints the seed. The creation date is recorded in the ceremony
/// ledger (issue #51) — the audit trail starts here.
fn key_keygen(home: PathBuf) -> miette::Result<()> {
    let kp = shuttle::sign::create_secret_key(&home)?;
    let anchor = shuttle::sign::install_public_key(&kp, &shuttle::sign::keys_dir(&home))?;
    let mut ledger = shuttle::sign::CeremonyLedger::load(&shuttle::sign::keys_dir(&home))?;
    ledger.record_created(&kp, &shuttle::sign::now_rfc3339());
    ledger.save(&shuttle::sign::keys_dir(&home))?;
    shuttle::output::ok(format!(
        "signing key created: {} (key id {})",
        shuttle::sign::secret_key_path(&home).display(),
        kp.key_id()
    ));
    shuttle::output::info(format!("trust anchor installed: {}", anchor.display()));
    print_report(&serde_json::json!({
        "key_id": kp.key_id(),
        "secret_key": shuttle::sign::secret_key_path(&home).display().to_string(),
        "anchor": anchor.display().to_string(),
    }));
    Ok(())
}

/// `shuttle key rotate`: mint `secret-key.new`, record the generation
/// chain in the ledger (old id → successor → date → overlap window), and
/// dual-sign `--manifest` under the successor when given — the old
/// signature entry is kept, and an attested entry's provenance is
/// re-attached under the new signature (same claims, new key; issue #51).
fn key_rotate(home: PathBuf, manifest: Option<String>, window_days: u32) -> miette::Result<()> {
    let successor = shuttle::sign::mint_rotation_key(&home)?;
    let old = shuttle::sign::load_secret_key(&home)?.expect("rotation key requires an active key");
    let keys_dir = shuttle::sign::keys_dir(&home);
    let mut ledger = shuttle::sign::CeremonyLedger::load(&keys_dir)?;
    ledger.record_rotation(&old, &successor, &shuttle::sign::now_rfc3339(), window_days);
    ledger.save(&keys_dir)?;

    if let Some(path) = &manifest {
        rotate_dual_sign_manifest(path, &successor)?;
    }

    shuttle::output::ok(format!(
        "rotation key minted: {} (key id {}) — not trusted until promoted",
        shuttle::sign::rotation_key_path(&home).display(),
        successor.key_id()
    ));
    shuttle::output::info(format!(
        "generation chain recorded: {} replaced by {} (window {} days)",
        old.key_id(),
        successor.key_id(),
        window_days
    ));
    print_rotate_report(&home, &old, &successor, window_days, manifest.as_deref());
    Ok(())
}

/// The `--manifest` half of `shuttle key rotate`: dual-sign the manifest
/// file under the successor (old entries kept, provenance re-attached)
/// and write it back atomically.
fn rotate_dual_sign_manifest(path: &str, successor: &shuttle::sign::KeyPair) -> miette::Result<()> {
    let mut parsed = read_manifest(path)?;
    shuttle::sign::cosign_reattaching_provenance(&mut parsed, successor)?;
    parsed.write_atomic(std::path::Path::new(path))?;
    shuttle::output::ok(format!(
        "manifest dual-signed: {path} (key id {} beside the existing entries)",
        successor.key_id()
    ));
    Ok(())
}

/// The JSON report of a rotation, manifest field included when one was
/// dual-signed.
fn print_rotate_report(
    home: &Path,
    old: &shuttle::sign::KeyPair,
    successor: &shuttle::sign::KeyPair,
    window_days: u32,
    manifest: Option<&str>,
) {
    let mut report = serde_json::json!({
        "key_id": successor.key_id(),
        "rotation_key": shuttle::sign::rotation_key_path(home).display().to_string(),
        "trusted": false,
        "replaces": old.key_id(),
        "window_days": window_days,
    });
    if let Some(path) = manifest {
        report["manifest"] = serde_json::json!(path);
    }
    print_report(&report);
}

/// `shuttle key promote`: move the successor into place and trust it.
fn key_promote(home: PathBuf) -> miette::Result<()> {
    let kp = shuttle::sign::promote_rotation_key(&home, &shuttle::sign::keys_dir(&home))?;
    shuttle::output::ok(format!(
        "rotation promoted: key id {} is now the signing key",
        kp.key_id()
    ));
    print_report(&serde_json::json!({
        "key_id": kp.key_id(),
        "secret_key": shuttle::sign::secret_key_path(&home).display().to_string(),
        "trusted": true,
    }));
    Ok(())
}

/// `shuttle key revoke`: drop the local anchor, record the revocation in
/// `keys/revoked-keys`, and date it in the ceremony ledger.
fn key_revoke(home: PathBuf, key_id: &str) -> miette::Result<()> {
    shuttle::sign::revoke_local(&shuttle::sign::keys_dir(&home), key_id)?;
    let keys_dir = shuttle::sign::keys_dir(&home);
    let mut ledger = shuttle::sign::CeremonyLedger::load(&keys_dir)?;
    let revoked_at = shuttle::sign::now_rfc3339();
    ledger.record_revocation(key_id, &revoked_at);
    ledger.save(&keys_dir)?;
    shuttle::output::ok(format!("key {key_id} revoked (recorded {revoked_at})"));
    print_report(&serde_json::json!({
        "key_id": key_id,
        "revoked": true,
        "revoked_at": revoked_at,
    }));
    Ok(())
}

/// `shuttle key list`: print the ceremony ledger — the auditable trail of
/// every key the ceremony touched (issue #51).
fn key_list(home: PathBuf) -> miette::Result<()> {
    let ledger = shuttle::sign::CeremonyLedger::load(&shuttle::sign::keys_dir(&home))?;
    if ledger.keys.is_empty() {
        shuttle::output::info(format!(
            "no ceremony ledger yet at {} (run `shuttle key keygen`)",
            shuttle::sign::ceremony_ledger_path(&shuttle::sign::keys_dir(&home)).display()
        ));
        return Ok(());
    }
    for (key_id, entry) in &ledger.keys {
        let created = entry.created.as_deref().unwrap_or("?");
        let mut line = format!("{key_id}  created {created}");
        if let (Some(succ), Some(at)) = (&entry.replaced_by, &entry.rotated_at) {
            line.push_str(&format!(
                "  rotated→{succ} {at} (window {}d)",
                entry
                    .window_days
                    .unwrap_or(shuttle::sign::DEFAULT_WINDOW_DAYS)
            ));
        }
        if let Some(at) = &entry.revoked_at {
            line.push_str(&format!("  REVOKED {at}"));
        }
        if !shuttle::output::is_json() {
            println!("{line}");
        }
    }
    print_report(&ledger);
    Ok(())
}

/// `shuttle key verify`: verify a manifest JSON under the ceremony policy
/// (issue #51) — either key during a rotation window, a warning once an
/// expired window's key is the only signer, a named error for
/// revoked-only signatures. Provenance binding (issue #56) is enforced
/// for the entry that verified.
fn key_verify(home: PathBuf, manifest: &str) -> miette::Result<()> {
    let parsed = read_manifest(manifest)?;
    let outcome = verify_manifest_with_ceremony(&home, &parsed)?;
    for warning in &outcome.warnings {
        shuttle::output::warn(warning);
    }
    shuttle::output::ok(format!("manifest verified under key id {}", outcome.key_id));
    print_report(&serde_json::json!({
        "manifest": manifest,
        "key_id": outcome.key_id,
        "verified": true,
        "warnings": outcome.warnings,
    }));
    Ok(())
}

/// Read and parse a manifest JSON file (shared by `key rotate --manifest`
/// and `key verify`).
fn read_manifest(path: &str) -> miette::Result<shuttle::manifest::ImageManifest> {
    let text = std::fs::read_to_string(path).map_err(|e| miette::miette!("reading {path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| miette::miette!("parsing manifest {path}: {e}"))
}

/// The ceremony-policy verify half of `shuttle key verify`: canonical
/// bytes, operator keychain + ledger + `revoked-keys`, then the ledger
/// verify with provenance binding enforced on the winning entry.
fn verify_manifest_with_ceremony(
    home: &Path,
    parsed: &shuttle::manifest::ImageManifest,
) -> miette::Result<shuttle::sign::LedgerVerification> {
    let keys_dir = shuttle::sign::keys_dir(home);
    let body = shuttle::sign::canonical_bytes(parsed)?;
    let chain = shuttle::sign::Keychain::load_dir(&keys_dir)?;
    let ledger = shuttle::sign::CeremonyLedger::load(&keys_dir)?;
    let revoked = shuttle::sign::read_revoked_keys(&keys_dir)?;
    let outcome = shuttle::sign::verify_with_ledger_now(
        &body,
        &parsed.signatures,
        &chain,
        &ledger,
        &revoked,
    )?;
    if let Some(entry) = parsed.signatures.get(&outcome.key_id) {
        shuttle::sign::check_provenance(entry, &parsed.inputs)?;
    }
    Ok(outcome)
}

// ── Runtime command (ADR-0012 step 5, Phase 24b) ──

fn cmd_runtime(sub: RuntimeCommand) -> miette::Result<()> {
    match sub {
        RuntimeCommand::Install {
            name,
            channel,
            state_dir,
            json,
        } => {
            shuttle::output::set_mode(json);
            runtime_install(&name, &channel, state_dir)
        }
        RuntimeCommand::Remove {
            name,
            state_dir,
            json,
        } => {
            shuttle::output::set_mode(json);
            runtime_remove(&name, state_dir)
        }
        RuntimeCommand::Upgrade {
            name,
            all,
            channel,
            state_dir,
            json,
        } => {
            shuttle::output::set_mode(json);
            runtime_upgrade(name, all, &channel, state_dir)
        }
        RuntimeCommand::Rollback {
            generation,
            state_dir,
            json,
        } => {
            shuttle::output::set_mode(json);
            runtime_rollback(generation, state_dir)
        }
        RuntimeCommand::Gc {
            prune,
            state_dir,
            json,
        } => {
            shuttle::output::set_mode(json);
            runtime_gc(prune, state_dir)
        }
        RuntimeCommand::Activate { state_dir, json } => {
            shuttle::output::set_mode(json);
            runtime_activate(state_dir)
        }
        RuntimeCommand::RecoverSlots { esp_mount } => runtime_recover_slots(&esp_mount),
    }
}

// ── Pods (issues #2 + #4) ──

/// `shuttle pod shellenv` (issue #47): print the selected pod's
/// environment as shell statements — `export PATH="<farm>:$PATH"`, plus
/// the #89 loader-lib `LD_LIBRARY_PATH` prepend when the generation
/// ships payload libs — or as structured JSON with `--json`. The caller
/// `eval`s the output; this process only prints, never touching an RC
/// file.
fn cmd_pod_shellenv(pod_name: &str, json: bool, root: Option<String>) -> miette::Result<()> {
    shuttle::output::set_mode(json);
    let root = shuttle::pod::pod_root(root.as_deref());
    let env = shuttle::pod::shellenv(&root, pod_name)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&env).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        print!("{}", shuttle::pod::render_shellenv(&env));
    }
    Ok(())
}

fn cmd_pod(name: Option<&str>, sub: PodCommand) -> miette::Result<()> {
    let pod_name = name.unwrap_or(shuttle::pod::DEFAULT_POD);
    match sub {
        PodCommand::Add { package, root } => {
            let root = shuttle::pod::pod_root(root.as_deref());
            let report = shuttle::pod::add_package(&root, pod_name, &package)?;
            shuttle::output::ok(format!(
                "added '{}' ({}) to pod '{}'",
                report.name, report.version, report.pod
            ));
            Ok(())
        }
        PodCommand::Remove { package, root } => {
            let root = shuttle::pod::pod_root(root.as_deref());
            let report = shuttle::pod::remove_package(&root, pod_name, &package)?;
            shuttle::output::ok(format!(
                "removed '{}' from pod '{}'",
                report.name, report.pod
            ));
            Ok(())
        }
        PodCommand::Sync { root } => {
            let root = shuttle::pod::pod_root(root.as_deref());
            let report = shuttle::pod::sync_pod(&root, pod_name)?;
            print_pod_sync_report(&report);
            Ok(())
        }
        PodCommand::List { root } => {
            let root = shuttle::pod::pod_root(root.as_deref());
            let entries = shuttle::pod::list_packages(&root, pod_name)?;
            if entries.is_empty() {
                shuttle::output::info(format!("pod '{pod_name}' has no packages"));
                return Ok(());
            }
            let width = entries.iter().map(|e| e.spec.len()).max().unwrap_or(0);
            for entry in &entries {
                let version = entry.version.as_deref().unwrap_or("(unresolved)");
                // Float marking (ADR-0017): floating packages say so.
                let tag = if entry.floating { " (float)" } else { "" };
                shuttle::output::status(format!(
                    "{:<width$}  {}{}",
                    entry.spec,
                    version,
                    tag,
                    width = width
                ));
            }
            Ok(())
        }
        PodCommand::Shellenv { json, root } => cmd_pod_shellenv(pod_name, json, root),
        PodCommand::Update { packages, root } => {
            let root = shuttle::pod::pod_root(root.as_deref());
            let report = shuttle::pod::update_pod(&root, pod_name, &packages)?;
            print_pod_update_report(&report);
            Ok(())
        }
        PodCommand::Rebuild {
            package,
            latest,
            root,
        } => cmd_pod_rebuild(pod_name, &package, latest, root),
        PodCommand::Rollback { generation, root } => cmd_pod_rollback(pod_name, generation, root),
        PodCommand::Gc { prune, root } => cmd_pod_gc(pod_name, prune, root),
    }
}

/// `shuttle pod rebuild <pkg>` (issue #15): rebuild one declared
/// package at its pins, reusing the cached dependency closure (or
/// deliberately moving it with `--latest`).
fn cmd_pod_rebuild(
    pod_name: &str,
    package: &str,
    latest: bool,
    root: Option<String>,
) -> miette::Result<()> {
    let root = shuttle::pod::pod_root(root.as_deref());
    let report = shuttle::pod::rebuild_package(&root, pod_name, package, latest)?;
    let mut line = format!(
        "rebuilt '{}' ({}) in pod '{}'",
        report.name, report.version, report.pod
    );
    if let Some(n) = report.generation {
        line.push_str(&format!(" (generation {n})"));
    }
    shuttle::output::ok(line);
    print_report(&report);
    Ok(())
}

/// `shuttle run <app>`: run a confined app from a pod (ADR-0016, ticket
/// #11). Resolves the pod's active generation to find the package
/// providing `app`, reads its declared grants, and execs the app inside
/// the selected backend's sandbox. Confined apps fail closed when the
/// backend is unavailable — never silently unconfined. `--pod` selects
/// the pod (default `default`); `--root` overrides the pod state root.
fn cmd_run(
    pod: Option<&str>,
    root: Option<&str>,
    app: &str,
    app_args: &[String],
) -> miette::Result<()> {
    let pod_name = pod.unwrap_or(shuttle::pod::DEFAULT_POD);
    shuttle::pod::validate_pod_name(pod_name).map_err(|e| miette::miette!("shuttle run: {e}"))?;
    let root = shuttle::pod::pod_root(root);
    let dir = shuttle::pod::pod_dir(&root, pod_name);
    // Confinement is a runtime concern: the pod must have been reconciled
    // (a pod with no store/generation fails with a clear error).
    if !dir.join("generations").is_dir() {
        return Err(miette::miette!(
            "pod '{pod_name}' has not been reconciled yet — run `shuttle pod --name {pod_name} \
             sync` (or `add`) before `shuttle run`"
        ));
    }
    shuttle::confine::run(&dir, pod_name, app, app_args)
}

// ── Test command (QEMU boot-and-assert, issue #50) ──

/// The resolved host environment for a boot test — everything
/// [`shuttle::boot_test::BootTest`] needs that is not a flag. Kept separate
/// from the run so the scratch firmware dir lives across the QEMU call.
struct TestHost {
    qemu: PathBuf,
    timeout_bin: PathBuf,
    kvm_available: bool,
    firmware: shuttle::boot_test::Firmware,
    _scratch: tempfile::TempDir,
}

/// Validate `--runs`/`--expect-counter-seq` together and parse the expected
/// sequence. A single boot cannot observe a decrement, so a sequence spec
/// with `--runs 1` is rejected rather than silently ignored.
fn validate_sequence_args(
    runs: u32,
    expect_counter_seq: Option<&str>,
) -> miette::Result<Vec<shuttle::boot_test::ExpectedCounters>> {
    if runs == 0 {
        return Err(miette::miette!("--runs must be at least 1"));
    }
    let expect_counters = match expect_counter_seq {
        Some(spec) => shuttle::boot_test::parse_expect_counters(spec)?,
        None => Vec::new(),
    };
    if !expect_counters.is_empty() && runs == 1 {
        return Err(miette::miette!(
            "--expect-counter-seq needs at least 2 boots to observe a decrement; pass --runs N"
        ));
    }
    Ok(expect_counters)
}

/// `shuttle test`: boot a built image in QEMU and assert it reached
/// userspace. The host-side wrapper around
/// [`shuttle::boot_test::run_sequence`] — it resolves the
/// QEMU/firmware/timeout environment, runs the boot(s) through the real
/// [`RealRunner`][shuttle::command::RealRunner], prints each verdict, and
/// exits non-zero when any boot or sequence assertion fails (so this can gate
/// CI and, later, #63's revert test).
#[allow(clippy::too_many_arguments)]
fn cmd_test(
    image: String,
    timeout: u64,
    accel: shuttle::boot_test::Accel,
    log: Option<String>,
    require: Vec<String>,
    firmware_dir: Option<String>,
    runs: u32,
    expect_counter_seq: Option<String>,
    allow_no_completion: bool,
    qemu_args: Vec<String>,
    json: bool,
) -> miette::Result<()> {
    let image_path = PathBuf::from(&image);
    if !image_path.is_file() {
        return Err(miette::miette!(
            "image not found: {image} — build it first with `shuttle image` and pass the \
             resulting *.img"
        ));
    }
    let expect_counters = validate_sequence_args(runs, expect_counter_seq.as_deref())?;
    let log_path = log
        .map(PathBuf::from)
        .unwrap_or_else(|| shuttle::boot_test::default_log_path(&image_path));
    let host = resolve_test_host(firmware_dir.as_deref())?;

    let test = shuttle::boot_test::BootTest {
        image: image_path,
        log: log_path.clone(),
        accel,
        timeout: Duration::from_secs(timeout),
        firmware: host.firmware,
        qemu: host.qemu,
        timeout_bin: host.timeout_bin,
        kvm_available: host.kvm_available,
        required: require,
        runs,
        expect_counters,
        allow_no_completion,
        extra_qemu_args: qemu_args,
    };

    if !json {
        if runs > 1 {
            shuttle::output::status(format!(
                "booting {image} {runs} times (accel {})...",
                accel.qemu_arg()
            ));
        } else {
            shuttle::output::status(format!("booting {image} (accel {})...", accel.qemu_arg()));
        }
    }
    let outcome = shuttle::boot_test::run_sequence(&shuttle::command::RealRunner, &test)?;
    report_sequence_result(&image, &log_path, &outcome, json);

    if !outcome.passed() {
        std::process::exit(1);
    }
    Ok(())
}

/// Resolve qemu, `timeout`, KVM availability, and the UEFI firmware (with a
/// writable VARS copy staged in the returned scratch dir).
fn resolve_test_host(firmware_dir: Option<&str>) -> miette::Result<TestHost> {
    let qemu = shuttle::boot_test::resolve_qemu()?;
    let timeout_bin = shuttle::boot_test::resolve_timeout()?;
    let scratch = tempfile::tempdir()
        .map_err(|e| miette::miette!("failed to create scratch dir for firmware: {e}"))?;
    let firmware =
        shuttle::boot_test::prepare_firmware(&qemu, firmware_dir.map(Path::new), scratch.path())?;
    Ok(TestHost {
        qemu,
        timeout_bin,
        kvm_available: shuttle::boot_test::kvm_available(),
        firmware,
        _scratch: scratch,
    })
}

/// Print the boot verdict (human or JSON) plus the evidence path.
fn report_sequence_result(
    image: &str,
    log: &Path,
    outcome: &shuttle::boot_test::SequenceOutcome,
    json: bool,
) {
    if json {
        report_sequence_json(image, outcome);
        return;
    }
    if outcome.records.is_empty() {
        shuttle::output::err(outcome.message());
    } else {
        for record in &outcome.records {
            let label = format!("boot {}", record.index);
            let counters = record
                .counters
                .map(|c| {
                    let name = record.uki.as_deref().unwrap_or("");
                    let base = shuttle::esp::parse_uki_name(name).base;
                    format!(" (ESP {base} +{}-{})", c.tries_left, c.tries_done)
                })
                .unwrap_or_default();
            if record.outcome.passed() {
                shuttle::output::ok(format!("{label}: {}{counters}", record.outcome.message()));
            } else {
                shuttle::output::err(format!("{label}: {}{counters}", record.outcome.message()));
            }
        }
        if let Some(failure) = &outcome.failure {
            shuttle::output::err(format!("sequence: {}", failure.message()));
        }
    }
    if let Some(root) = &outcome.run_root {
        shuttle::output::status(format!("sequence evidence: {}", root.display()));
    } else {
        shuttle::output::status(format!("serial evidence: {}", log.display()));
        if !log.is_file() {
            shuttle::output::warn(format!("no serial log was written at {}", log.display()));
        }
    }
}

/// `--json` boot report: the sequence summary (one entry per boot) plus the
/// overall verdict, run root, and image.
fn report_sequence_json(image: &str, outcome: &shuttle::boot_test::SequenceOutcome) {
    let boots: Vec<serde_json::Value> = outcome
        .records
        .iter()
        .map(|record| {
            serde_json::json!({
                "index": record.index,
                "log": record.log.display().to_string(),
                "esp_listing": record.esp_listing.display().to_string(),
                "esp_entries": record.esp_entries,
                "uki": record.uki,
                "counters": record.counters.map(|c| serde_json::json!({
                    "tries_left": c.tries_left,
                    "tries_done": c.tries_done,
                })),
                "passed": record.outcome.passed(),
                "accel": record.outcome.accel.qemu_arg(),
                "timeout_secs": record.outcome.timeout.as_secs(),
                "argv": record.outcome.argv,
                "failure": record.outcome.failure.as_ref().map(|f| f.label()),
                "message": record.outcome.message(),
                "evidence": {
                    "userspace": record.outcome.evidence.userspace,
                    "markers": record.outcome.evidence.markers,
                    "target": record.outcome.evidence.target,
                    "service": record.outcome.evidence.service,
                    "handoff": record.outcome.evidence.handoff,
                    "boot_complete": record.outcome.evidence.boot_complete,
                    "panic": record.outcome.evidence.panic,
                    "activate": record.outcome.evidence.activate,
                },
            })
        })
        .collect();
    // Preserve the single-boot top-level shape for existing consumers: the
    // first boot's verdict is mirrored at the top level, with `boots`
    // carrying the sequence.
    let first = outcome.records.first();
    let report = serde_json::json!({
        "command": "test",
        "image": image,
        "image_booted": outcome.image.display().to_string(),
        "runs": outcome.records.len(),
        "run_root": outcome.run_root.as_ref().map(|r| r.display().to_string()),
        "log": first.map(|r| r.log.display().to_string()),
        "passed": outcome.passed(),
        "failure": outcome.failure.as_ref().map(|f| f.label()).or_else(|| {
            first.and_then(|r| r.outcome.failure.as_ref().map(|f| f.label()))
        }),
        "message": outcome.message(),
        "accel": first.map(|r| r.outcome.accel.qemu_arg()),
        "timeout_secs": first.map(|r| r.outcome.timeout.as_secs()),
        "argv": first.map(|r| r.outcome.argv.clone()),
        "esp_entries": first.map(|r| r.esp_entries.clone()),
        "counters": first.and_then(|r| r.counters).map(|c| serde_json::json!({
            "tries_left": c.tries_left,
            "tries_done": c.tries_done,
        })),
        "evidence": first.map(|r| serde_json::json!({
            "userspace": r.outcome.evidence.userspace,
            "markers": r.outcome.evidence.markers,
            "target": r.outcome.evidence.target,
            "service": r.outcome.evidence.service,
            "handoff": r.outcome.evidence.handoff,
            "boot_complete": r.outcome.evidence.boot_complete,
            "panic": r.outcome.evidence.panic,
            "activate": r.outcome.evidence.activate,
        })),
        "boots": boots,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
    );
}

/// Report the update outcome for `shuttle pod update`: a no-op says so,
/// updates name the version moves, held packages explain their
/// constraint, and the current generation closes the story.
fn print_pod_update_report(report: &shuttle::pod::PodUpdateReport) {
    if report.updated.is_empty() && report.held.is_empty() {
        shuttle::output::ok(format!(
            "pod '{}' is already at its newest matching versions — no new generation",
            report.pod
        ));
    }
    for entry in &report.updated {
        let from = entry.from.as_deref().unwrap_or("(unpinned)");
        shuttle::output::ok(format!("updated '{}' {} -> {}", entry.name, from, entry.to));
    }
    for held in &report.held {
        let pinned = held.pinned.as_deref().unwrap_or("(unpinned)");
        shuttle::output::warn(format!(
            "held '{}' at {} (constraint @{:?}: newest available {} does not match)",
            held.name, pinned, held.constraint, held.candidate
        ));
    }
    if let Some(n) = report.generation {
        shuttle::output::info(format!("generation {n} current"));
    }
    print_report(report);
}

/// `shuttle pod rollback`: report the flip (from → to) and the farm now
/// behind the pod's `current` link.
fn cmd_pod_rollback(
    pod_name: &str,
    generation: Option<u64>,
    root: Option<String>,
) -> miette::Result<()> {
    let root = shuttle::pod::pod_root(root.as_deref());
    let report = shuttle::pod::rollback_pod(&root, pod_name, generation)?;
    shuttle::output::ok(format!(
        "pod '{}' rolled back generation {} -> {}",
        report.pod, report.from, report.to
    ));
    if let Some(farm) = &report.farm {
        shuttle::output::info(format!("farm: {}", farm.display()));
    }
    print_report(&report);
    Ok(())
}

/// `shuttle pod gc`: report pruned generations and swept blobs.
fn cmd_pod_gc(pod_name: &str, prune: bool, root: Option<String>) -> miette::Result<()> {
    let root = shuttle::pod::pod_root(root.as_deref());
    let report = shuttle::pod::gc_pod(&root, pod_name, prune)?;
    if !report.generations_removed.is_empty() {
        shuttle::output::ok(format!(
            "pruned generation(s): {}",
            report
                .generations_removed
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if report.blobs_removed == 0 {
        shuttle::output::ok("pod store clean — nothing to sweep");
    } else {
        shuttle::output::ok(format!(
            "swept {} blob(s), {} bytes reclaimed",
            report.blobs_removed, report.bytes_reclaimed
        ));
    }
    print_report(&report);
    Ok(())
}

/// Report the reconcile outcome for `shuttle pod sync`: a no-op says
/// so (no new generation), changes name what moved, and the current
/// generation + farm path close the story.
fn print_pod_sync_report(report: &shuttle::pod::PodSyncReport) {
    if report.noop {
        shuttle::output::ok(format!(
            "pod '{}' already matches its declaration — no new generation",
            report.pod
        ));
    } else {
        for name in &report.installed {
            shuttle::output::ok(format!("installed {name}"));
        }
        for name in &report.removed {
            shuttle::output::ok(format!("removed {name}"));
        }
    }
    if let Some(n) = report.generation {
        shuttle::output::info(format!("generation {n} current"));
    }
    if let Some(farm) = &report.farm {
        shuttle::output::info(format!("farm: {}", farm.display()));
    }
    print_report(report);
}

// ── OCI registry push/pull (Phase 25) ──

/// Assemble registry credentials from the CLI flags: anonymous by
/// default; `--username` requires `--password-stdin` (fail-closed) and
/// the password is read as one line from stdin.
fn registry_auth(
    username: Option<&str>,
    password_stdin: bool,
) -> miette::Result<shuttle::oci::Auth> {
    match (username, password_stdin) {
        (Some(user), true) => {
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .map_err(|e| miette::miette!("failed to read password from stdin: {e}"))?;
            let password = line.trim_end_matches(['\n', '\r']).to_string();
            if password.is_empty() {
                miette::bail!("no password received on stdin (provide one line)");
            }
            Ok(shuttle::oci::Auth {
                username: Some(user.to_string()),
                password: Some(password),
            })
        }
        (Some(_), false) => {
            miette::bail!("--password-stdin is required with --username (no interactive prompt)")
        }
        (None, true) => miette::bail!("--username is required with --password-stdin"),
        (None, false) => Ok(shuttle::oci::Auth::default()),
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_push(
    reference: &str,
    dir: &str,
    snap: &[String],
    image: &[String],
    tag: Option<&str>,
    username: Option<&str>,
    password_stdin: bool,
    insecure_http: bool,
    mount_from: Option<&str>,
    record: Option<&str>,
) -> miette::Result<()> {
    let auth = registry_auth(username, password_stdin)?;
    let reference = shuttle::oci::Reference::parse(reference)?;
    let explicit: Vec<PathBuf> = snap.iter().chain(image).map(PathBuf::from).collect();
    for p in &explicit {
        if !p.exists() {
            miette::bail!("artifact {} does not exist", p.display());
        }
    }
    let plan = shuttle::oci::plan_push(Path::new(dir), &explicit, tag, &reference)?;
    shuttle::output::info(format!(
        "bundle {} v{} ({}) → tag '{}'",
        plan.meta.name, plan.meta.version, plan.meta.arch, plan.tag
    ));
    let report = shuttle::oci::push(&reference, &plan, auth, insecure_http, mount_from)?;
    if let Some(rec) = record {
        shuttle::oci::write_built_record(Path::new(rec), &plan)?;
        shuttle::output::ok(format!("built-manifest record written to {rec}"));
    }
    print_report(&report);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_pull(
    reference: &str,
    out_dir: String,
    username: Option<&str>,
    password_stdin: bool,
    insecure_http: bool,
    expect: Option<&str>,
    install: bool,
    state_dir: Option<String>,
) -> miette::Result<()> {
    let auth = registry_auth(username, password_stdin)?;
    let reference = shuttle::oci::Reference::parse(reference)?;
    let expected = match expect {
        Some(p) => Some(shuttle::oci::read_built_record(Path::new(p))?),
        None => None,
    };
    let mut report = shuttle::oci::pull(
        &reference,
        Path::new(&out_dir),
        auth,
        insecure_http,
        expected.as_ref(),
    )?;
    if install {
        let install_report = install_pulled(&report, state_dir.as_deref())?;
        print_install_summary(&install_report);
        report.install = Some(install_report);
    }
    print_report(&report);
    Ok(())
}

/// `pull --install`: resolve revisions for the pulled `.snap` payloads
/// from the local lockfile pins and install them as one generation.
/// The revision-resolution rule lives in
/// [`shuttle::oci::pending_from_blob`]; unpinned or divergent blobs are
/// refused there (fail-closed).
fn install_pulled(
    report: &shuttle::oci::PullReportJson,
    state_dir: Option<&str>,
) -> miette::Result<shuttle::runtime::InstallReport> {
    let lock_path = Path::new(LockFile::FILENAME);
    let lockfile = LockFile::load(lock_path)?.ok_or_else(|| {
        miette::miette!(
            "no {} in the current directory — --install resolves revisions \
             from lockfile pins; pull without --install to keep the files",
            lock_path.display()
        )
    })?;
    let mut pending: Vec<PendingSnap> = Vec::new();
    for f in &report.files {
        if f.path.ends_with(".snap") {
            pending.push(shuttle::oci::pending_from_blob(
                Path::new(&f.path),
                &lockfile,
            )?);
        }
    }
    if pending.is_empty() {
        miette::bail!("pulled bundle contains no .snap payloads — nothing to install");
    }
    let store = RuntimeStore::from_state_dir(state_dir);
    store.install_batch(
        &pending,
        &SignatureEnvelope::default(),
        &RuntimeTools::for_pod_runtime(),
    )
}

/// Resolve + download + verify one snap from the store (the store's
/// fail-closed snap-revision assertion path is reused, never
/// reimplemented) into the state root's downloads dir.
fn runtime_fetch(name: &str, channel: &str, downloads: &Path) -> miette::Result<PendingSnap> {
    let arch = shuttle::snap::host_arch();
    let pin = SnapRef {
        name: name.to_string(),
        revision: None,
        sha3_384: None,
    };
    let resolved = shuttle::store::StoreClient::resolve(&pin, channel, arch)?;
    let payload =
        shuttle::store::StoreClient::download(&shuttle::command::RealRunner, &resolved, downloads)?;
    shuttle::store::StoreClient::verify(&payload, &resolved.sha3_384)?;
    shuttle::output::ok(format!(
        "{name} revision {} — sha3-384 verified",
        resolved.revision
    ));
    Ok(PendingSnap {
        name: name.to_string(),
        revision: resolved.revision,
        sha3_384: resolved.sha3_384,
        payload_path: payload,
        ..Default::default()
    })
}

fn print_report<T: serde::Serialize>(value: &T) {
    if shuttle::output::is_json() {
        println!(
            "{}",
            serde_json::to_string_pretty(value).unwrap_or_default()
        );
    }
}

fn runtime_install(name: &str, channel: &str, state_dir: Option<String>) -> miette::Result<()> {
    let store = RuntimeStore::from_state_dir(state_dir.as_deref());
    let pending = runtime_fetch(name, channel, &store.downloads_dir())?;
    let report = store.install_batch(
        &[pending],
        &SignatureEnvelope::default(),
        &RuntimeTools::for_pod_runtime(),
    )?;
    print_install_report(&report);
    Ok(())
}

fn runtime_remove(name: &str, state_dir: Option<String>) -> miette::Result<()> {
    let store = RuntimeStore::from_state_dir(state_dir.as_deref());
    let report = store.remove(name, &RuntimeTools::for_pod_runtime())?;
    shuttle::output::ok(format!(
        "removed {name} — generation {} active",
        report.generation
    ));
    for note in &report.notes {
        shuttle::output::info(note);
    }
    print_report(&report);
    Ok(())
}

fn runtime_upgrade(
    name: Option<String>,
    _all: bool,
    channel: &str,
    state_dir: Option<String>,
) -> miette::Result<()> {
    let store = RuntimeStore::from_state_dir(state_dir.as_deref());
    store.recover()?;
    let active = active_or_err(&store)?;
    let targets = upgrade_targets(&active, &name)?;
    let resolved = resolve_targets(&targets, channel)?;
    let changed = changed_pins(&resolved, &active.packages);
    if changed.is_empty() {
        shuttle::output::ok("everything already at its channel head — no-op, no new generation");
        print_report(&serde_json::json!({ "noop": true, "changed": [] }));
        return Ok(());
    }
    let pending = fetch_changed(&store, &changed, channel)?;
    let report = store.install_batch(
        &pending,
        &SignatureEnvelope::default(),
        &RuntimeTools::for_pod_runtime(),
    )?;
    print_install_report(&report);
    Ok(())
}

fn active_or_err(store: &RuntimeStore) -> miette::Result<shuttle::runtime::Generation> {
    store
        .active_generation()?
        .ok_or_else(|| miette::miette!("nothing installed — no active generation to upgrade"))
}

fn fetch_changed(
    store: &RuntimeStore,
    changed: &[String],
    channel: &str,
) -> miette::Result<Vec<PendingSnap>> {
    let mut pending = Vec::new();
    for target in changed {
        pending.push(runtime_fetch(target, channel, &store.downloads_dir())?);
    }
    Ok(pending)
}

/// `upgrade <name>` targets one installed snap; anything else (bare
/// `upgrade` or `--all`) targets the whole installed set.
fn upgrade_targets(
    active: &shuttle::runtime::Generation,
    name: &Option<String>,
) -> miette::Result<Vec<String>> {
    if let Some(n) = name {
        if !active.packages.contains_key(n) {
            return Err(miette::miette!(
                "package '{n}' is not installed (generation {})",
                active.n
            ));
        }
        return Ok(vec![n.clone()]);
    }
    Ok(active.packages.keys().cloned().collect())
}

/// Re-resolve each target at its channel head (data-only until the
/// change comparison decides whether anything downloads).
fn resolve_targets(
    targets: &[String],
    channel: &str,
) -> miette::Result<Vec<(String, u32, String)>> {
    let arch = shuttle::snap::host_arch();
    let mut resolved = Vec::new();
    for target in targets {
        let pin = SnapRef {
            name: target.clone(),
            revision: None,
            sha3_384: None,
        };
        let r = shuttle::store::StoreClient::resolve(&pin, channel, arch)?;
        resolved.push((target.clone(), r.revision, r.sha3_384));
    }
    Ok(resolved)
}

fn print_install_summary(report: &shuttle::runtime::InstallReport) {
    for note in &report.notes {
        shuttle::output::info(note);
    }
    if report.noop {
        shuttle::output::ok("already installed at this revision — no-op");
    } else {
        for installed in &report.installed {
            shuttle::output::ok(format!(
                "installed {} {} (revision {}) into generation {}",
                installed.name,
                installed.version,
                installed.revision,
                report.generation.unwrap_or(0)
            ));
        }
    }
}

fn print_install_report(report: &shuttle::runtime::InstallReport) {
    print_install_summary(report);
    print_report(report);
}

fn runtime_rollback(generation: Option<u64>, state_dir: Option<String>) -> miette::Result<()> {
    let store = RuntimeStore::from_state_dir(state_dir.as_deref());
    let report = store.rollback(generation, &RuntimeTools::for_pod_runtime())?;
    shuttle::output::ok(format!(
        "rolled back generation {} -> {}",
        report.from, report.to
    ));
    if !report.started.is_empty() {
        shuttle::output::info(format!("started: {}", report.started.join(", ")));
    }
    if !report.stopped.is_empty() {
        shuttle::output::info(format!("stopped: {}", report.stopped.join(", ")));
    }
    for note in &report.notes {
        shuttle::output::info(note);
    }
    print_report(&report);
    Ok(())
}

fn runtime_gc(prune: bool, state_dir: Option<String>) -> miette::Result<()> {
    let store = RuntimeStore::from_state_dir(state_dir.as_deref());
    let report = store.gc(prune)?;
    if !report.generations_removed.is_empty() {
        shuttle::output::ok(format!(
            "pruned generation(s): {}",
            report
                .generations_removed
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if report.blobs_removed == 0 {
        shuttle::output::ok("store clean — nothing to sweep");
    } else {
        shuttle::output::ok(format!(
            "swept {} blob(s), {} bytes reclaimed",
            report.blobs_removed, report.bytes_reclaimed
        ));
    }
    print_report(&report);
    Ok(())
}

/// `shuttle runtime activate` (ADR-0023 §4, #60): activate the current
/// generation. Boot-safe and idempotent — a cold store is a no-op and a
/// half-written journal is discarded, so the emitted
/// `shuttle-runtime-activate.service` oneshot never wedges boot.
fn runtime_activate(state_dir: Option<String>) -> miette::Result<()> {
    let store = RuntimeStore::from_state_dir(state_dir.as_deref());
    let report = store.activate_current(&RuntimeTools::for_pod_runtime())?;
    if report.noop {
        shuttle::output::ok("no active generation — nothing to activate");
    } else {
        shuttle::output::ok(format!(
            "activated generation {}",
            report.generation.unwrap_or(0)
        ));
    }
    for note in &report.notes {
        shuttle::output::info(note);
    }
    print_report(&report);
    Ok(())
}

/// `shuttle runtime recover-slots` (issue #86): assess and reclaim
/// sysupdate slots stranded mid-install. Runs in-guest at boot (the
/// emitted `shuttle-slot-recovery.service` oneshot); see
/// [`shuttle::slot_recovery`] for the invariant and the conservative
/// recovery policy.
fn runtime_recover_slots(esp_mount: &str) -> miette::Result<()> {
    let runner = shuttle::command::RealRunner;
    let tools = shuttle::slot_recovery::SlotRecoveryTools::resolve();
    shuttle::slot_recovery::recover_slots(Path::new(esp_mount), &runner, &tools)
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
        IndexCommand::Resolve {
            index,
            channel,
            base,
        } => index_resolve(&index, &channel, &base),
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
            submodules: None,
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
/// save the updated index. Base-track passes (`--base core22 …`) pin the
/// channels the image build derives for kernel/gadget snaps (issue #69).
fn index_resolve(index: &str, channel: &str, bases: &[String]) -> miette::Result<()> {
    let path = Path::new(index);
    let mut idx = if path.exists() {
        PackageIndex::load(path)?
    } else {
        eprintln!("  index file not found at {}", index);
        return Ok(());
    };

    eprintln!("Resolving snap pins from store (channel: {channel})...");
    idx.resolve_all(channel, bases)?;
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
