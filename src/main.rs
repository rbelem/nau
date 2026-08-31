use std::collections::HashMap;
use std::path::Path;

use clap::Parser;
use shoot::cache::PackageCache;
use shoot::cli::{CacheCommand, Cli, Command, IndexCommand};
use shoot::image::ImageDeclaration;
use shoot::index::{IndexEntry, PackageIndex, StoreRef};
use shoot::lock::{LockFile, SourceLockEntry};
use shoot::snap::{PackageInput, SourceSpec};

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
            shoot::output::set_mode(json);
            // If --file is default and doesn't exist, try output_name as package name
            let file = if file == "shoot.lua" && !Path::new("shoot.lua").exists() {
                if let Some(ref name) = output_name {
                    resolve_file(name)
                } else {
                    file
                }
            } else {
                resolve_file(&file)
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
                shoot::output::flush_json("order");
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
            shoot::output::flush_json("build");
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
            shoot::output::set_mode(json);
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
            shoot::output::flush_json("image");
            r
        }

        Command::Deps {
            package,
            recursive,
            tree,
            flat,
            json,
        } => {
            shoot::output::set_mode(json);
            let r = cmd_deps(package, recursive, tree, flat, json);
            shoot::output::flush_json("deps");
            r
        }

        Command::Search { query, json } => {
            shoot::output::set_mode(json);
            cmd_search(&query, json);
            Ok(())
        }

        Command::Index(sub) => cmd_index(sub),

        Command::Doctor => cmd_doctor(),

        Command::Lock { file, lockfile } => cmd_lock(file, lockfile),

        Command::Completion { shell } => cmd_completion(shell),

        Command::Cache(sub) => cmd_cache(sub),
    }
}

// ── Package name resolution ──
// If file doesn't exist on disk, try resolving as a package name from
// local pkgs/ or from initialized input sources.

fn resolve_file(file: &str) -> String {
    if Path::new(file).exists() {
        return file.to_string();
    }
    match shoot::pkg_source::resolve_pkg(file) {
        shoot::pkg_source::PkgResult::File(path) => {
            eprintln!("  ℹ resolved '{}' to {}", file, path);
            path
        }
        shoot::pkg_source::PkgResult::Found { path, content } => {
            eprintln!("  ℹ using package '{}' ({})", file, path);
            // Write to temp file for evaluation (Lua needs a real file for require())
            let tmp = std::env::temp_dir().join(format!("shoot-{}.lua", file));
            let _ = std::fs::write(&tmp, &content);
            tmp.to_string_lossy().to_string()
        }
        shoot::pkg_source::PkgResult::NotFound => file.to_string(),
    }
}

/// Evaluate a file path or resolved package source, returning snap outputs.
fn evaluate_file_or_embedded(file: &str) -> miette::Result<shoot::lua::Outputs> {
    shoot::lua::evaluate_file(file)
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
    stage: String,
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
    // 2. Otherwise fall back to the default input (github:rbelem/shoot/main)
    let original_file = file.clone();
    let file_exists = Path::new(&original_file).exists();

    if file_exists {
        // Extract global inputs from the config file and use those
        match shoot::lua::evaluate_file_with_inputs(&original_file) {
            Ok(eval) => {
                let lockfile = prepare_inputs(
                    &eval.global_inputs,
                    &lockfile_path,
                    update.as_deref(),
                    offline,
                )?;
                shoot::pkg_source::init_global_inputs_with(
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
            Err(_) => {
                // Fall through to the normal path
            }
        }
    }

    // No config file or it failed — use default input and resolve by name
    let default_inputs = default_input_map();
    let lockfile = prepare_inputs(&default_inputs, &lockfile_path, update.as_deref(), offline)?;
    shoot::pkg_source::init_global_inputs_with(&default_inputs, &lockfile.inputs, offline)?;
    let file = resolve_file(&file);
    let all_outputs = evaluate_file_or_embedded(&file)?;

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
        shoot::pkg_source::DEFAULT_INPUT_NAME.to_string(),
        PackageInput {
            url: shoot::pkg_source::DEFAULT_INPUT_URL.to_string(),
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
        let n = shoot::pkg_source::update_input_pins(inputs, &names, &mut lockfile)?;
        changed |= n > 0;
        if n > 0 {
            shoot::output::ok(format!("updated {n} input pin(s)"));
        }
    } else if !offline {
        // Record-once: pin inputs missing from the lockfile (first build).
        let n = shoot::pkg_source::ensure_input_pins(inputs, &mut lockfile)?;
        changed |= n > 0;
    }

    if changed {
        lockfile.save(lock_path)?;
        shoot::output::ok(format!("lockfile updated: {lockfile_path}"));
    }
    Ok(lockfile)
}

/// Inner build logic after outputs are resolved.
#[allow(clippy::too_many_arguments)]
fn run_build(
    all_outputs: shoot::lua::Outputs,
    file: String,
    stage: String,
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
    let mut lockfile = LockFile::load(lock_path)?.unwrap_or_else(|| LockFile {
        version: 1,
        sources: HashMap::new(),
        snaps: HashMap::new(),
        inputs: HashMap::new(),
    });

    let stage_dir = std::path::Path::new(&stage);
    let output_dir = std::path::Path::new(&output);

    // Initialize binary cache if --cache was specified or --all is set
    let pkg_cache: Option<shoot::cache::PackageCache> =
        if all || cache.is_some() || cache_max_size.is_some() {
            let mut pc = shoot::cache::PackageCache::new(cache.map(std::path::PathBuf::from));
            if let Some(ref size_str) = cache_max_size {
                if let Some(bytes) = parse_size(size_str) {
                    pc = pc.with_max_size(bytes);
                    if !json {
                        shoot::output::info(format!("max cache size: {}", size_str));
                    }
                } else if !json {
                    shoot::output::warn(format!("invalid cache size: {}", size_str));
                }
            }
            Some(pc)
        } else {
            None
        };

    // If --target is set, override on all snap meta structs
    let iter: Vec<(&String, shoot::snap::SnapMeta)> = match &output_name {
        Some(name) => {
            let mut meta = all_outputs
                .get(name)
                .ok_or_else(|| miette::miette!("output '{}' not found in {}", name, file))?
                .clone();
            if let Some(ref t) = target {
                meta.target = Some(t.clone());
                if !json {
                    shoot::output::info(format!("target: {t}"));
                }
            }
            vec![(name, meta)]
        }
        None => {
            let mut vec: Vec<(&String, shoot::snap::SnapMeta)> = Vec::new();
            for (name, meta_ref) in &all_outputs {
                let mut meta = meta_ref.clone();
                if let Some(ref t) = target {
                    meta.target = Some(t.clone());
                }
                vec.push((name, meta));
            }
            if let Some(ref t) = target {
                if !json {
                    shoot::output::info(format!("target: {t}"));
                }
            }
            vec
        }
    };

    // Also apply target to dep builds
    let effective_target = target.clone();

    // If --all, resolve and build transitive dependencies first
    if all {
        let mut all_deps: Vec<String> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

        for (_name, meta) in &iter {
            if !meta.requires.is_empty() {
                if let Ok(deps) = shoot::deps::resolve_dep_names(&meta.requires, true) {
                    for dep in &deps {
                        if seen.insert(dep.clone()) {
                            all_deps.push(dep.clone());
                        }
                    }
                }
            }
        }

        if !all_deps.is_empty() {
            if !json {
                eprintln!("── Building {} dependencies ──", all_deps.len());
            }
            for dep_name in &all_deps {
                let mut dep_meta = match shoot::deps::load_meta(dep_name) {
                    Ok(m) => m,
                    Err(e) => {
                        shoot::output::warn(format!("skipping dependency '{}': {}", dep_name, e));
                        continue;
                    }
                };

                // Apply --target to deps as well
                if let Some(ref t) = effective_target {
                    dep_meta.target = Some(t.clone());
                }

                // Check cache first
                if let Some(ref cache) = pkg_cache {
                    if let Some(_cached_path) = cache.lookup(&dep_meta, "amd64") {
                        if !json {
                            shoot::output::ok(format!("{} (cached)", dep_name));
                        }
                        continue;
                    }
                }

                let dep_archs = shoot::snap::resolve_archs(&dep_meta, &arch);
                for a in &dep_archs {
                    if !json {
                        shoot::output::status(format!("building {} ({})...", dep_name, a));
                    }
                    let dep_stage = tempfile::tempdir()
                        .map_err(|e| miette::miette!("failed to create temp stage: {}", e))?;

                    match shoot::snap::build_snap(&dep_meta, dep_stage.path(), output_dir, a) {
                        Ok(result) => {
                            if !json {
                                shoot::output::ok(&result.snap_filename);
                            }
                            if let Some(ref cache) = pkg_cache {
                                if let Err(e) = cache.store(&dep_meta, &result, a, output_dir) {
                                    shoot::output::warn(format!("cache store failed: {}", e));
                                }
                            }
                        }
                        Err(e) => {
                            shoot::output::warn(format!("build failed for '{}': {}", dep_name, e));
                        }
                    }
                }
            }
        }
    }

    let mut all_source_info: Vec<shoot::snap::SourceInfo> = Vec::new();

    for (name, meta) in &iter {
        let archs = shoot::snap::resolve_archs(meta, &arch);
        if !json {
            eprintln!("Building {} ({})...", name, meta.version);
        }

        for a in &archs {
            if !json {
                shoot::output::status(format!("{}/{}:", name, a));
            }

            if let Some(SourceSpec::Unverified(ref url)) = meta.source {
                if lockfile.lookup_source(url).is_some() {
                    shoot::output::info(format!("using lockfile hash for {url}"));
                }
            }

            let result = shoot::snap::build_snap(meta, stage_dir, output_dir, a)?;
            if !json {
                shoot::output::ok(&result.snap_filename);
            } else {
                shoot::output::record_build_result(shoot::output::BuildResultJson {
                    name: meta.name.clone(),
                    version: meta.version.clone(),
                    arch: a.clone(),
                    filename: result.snap_filename.clone(),
                    sha256: result.source_info.as_ref().map(|s| s.sha256.clone()),
                });
            }

            if let Some(info) = result.source_info {
                all_source_info.push(info);
            }
        }
    }

    let mut changed = false;
    for info in &all_source_info {
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
        shoot::output::ok(format!("lockfile updated: {}", lockfile_path));
    }

    if !all_source_info.is_empty() && !json {
        for info in &all_source_info {
            let status = if lockfile.sources.contains_key(&info.url) {
                "pinned"
            } else {
                "recorded"
            };
            shoot::output::status(format!("source {status}: {:16} {}", info.sha256, info.url));
        }
    }

    Ok(())
}

// ── Order command (--order flag) ──

fn cmd_order(file: &str, output_name: &Option<String>, json: bool) -> miette::Result<()> {
    // Initialize global inputs (default if no config)
    shoot::pkg_source::init_global_inputs(&HashMap::new())?;
    let file = resolve_file(file);
    let all_outputs = evaluate_file_or_embedded(&file)?;

    let iter: Vec<&shoot::snap::SnapMeta> = match output_name {
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
            if meta.requires.is_empty() {
                continue;
            }
            let seen: std::collections::HashSet<&str> =
                meta.requires.iter().map(|s| s.as_str()).collect();
            if let Ok(order) = shoot::deps::resolve_dep_names(&meta.requires, true) {
                for dep in &order {
                    let kind = if seen.contains(dep.as_str()) {
                        "direct"
                    } else {
                        "transitive"
                    };
                    shoot::output::record_order_result(shoot::output::OrderResultJson {
                        name: dep.clone(),
                        kind: kind.to_string(),
                    });
                }
            }
            continue;
        }

        eprintln!("Package: {} {}", meta.name, meta.version);

        if meta.requires.is_empty() {
            eprintln!("  No dependencies");
            continue;
        }

        eprintln!("  Direct requires:");
        for dep in &meta.requires {
            eprintln!("    - {}", dep);
        }

        eprintln!("  Resolved build order (transitive):");
        match shoot::deps::resolve_dep_names(&meta.requires, true) {
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

    Ok(())
}

// ── Deps command ──

fn cmd_deps(
    package: String,
    recursive: bool,
    tree: bool,
    flat: bool,
    json: bool,
) -> miette::Result<()> {
    shoot::pkg_source::init_global_inputs(&HashMap::new())?;
    let names = vec![package.clone()];
    let nodes = shoot::deps::resolve_deps(&names, recursive)?;

    if nodes.is_empty() {
        if json {
            return Ok(());
        }
        eprintln!("No dependencies found for '{}'", package);
        return Ok(());
    }

    if json {
        let seen: std::collections::HashSet<&str> = nodes
            .iter()
            .flat_map(|n| &n.requires)
            .map(|s| s.as_str())
            .collect();
        for node in &nodes {
            let kind = if seen.contains(node.name.as_str()) {
                "direct"
            } else {
                "transitive"
            };
            shoot::output::record_dep_result(shoot::output::DepResultJson {
                name: node.name.clone(),
                requires: node.requires.clone(),
                kind: kind.to_string(),
            });
        }
        return Ok(());
    }

    if tree && recursive {
        eprintln!("Dependency tree for '{}':", package);
        let tree_str = shoot::deps::format_tree(&names, true)?;
        eprintln!("{}", tree_str);
    } else if flat {
        let names_only: Vec<String> = nodes.iter().map(|n| n.name.clone()).collect();
        eprintln!("Build order for '{}':", package);
        for (i, name) in names_only.iter().enumerate() {
            eprintln!("  {}. {}", i + 1, name);
        }
    } else {
        if let Some(pkg) = nodes.first() {
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
    shoot::pkg_source::init_global_inputs(&HashMap::new())?;
    let file = resolve_file(&file);

    if let Some(ref epoch) = source_date_epoch {
        std::env::set_var("SOURCE_DATE_EPOCH", epoch);
    }
    std::env::set_var("SHOOT_ARCH", &arch);

    let lock_path = Path::new(&lockfile_path);
    let mut lockfile = LockFile::load(lock_path)?.unwrap_or_else(|| LockFile {
        version: 1,
        sources: HashMap::new(),
        snaps: HashMap::new(),
        inputs: HashMap::new(),
    });

    let lua = shoot::lua::new_lua(&file)?;
    let images = if let Some(_embedded) = file.strip_prefix("embedded://") {
        // Embedded packages are single snaps, not images — return empty
        if !shoot::output::is_json() {
            shoot::output::warn(format!("'{}' is a package, not an image", file));
        }
        std::collections::HashMap::new()
    } else {
        shoot::lua::evaluate_images(&lua, &file)?
    };

    let output_dir = Path::new(&output);

    let cache_dir = cache.map_or_else(
        || {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            Path::new(&home).join(".cache/shoot/snaps")
        },
        |c| Path::new(&c).to_path_buf(),
    );

    let iter: Vec<(&String, &ImageDeclaration)> = match &output_name {
        Some(name) => {
            let img = images
                .get(name)
                .ok_or_else(|| miette::miette!("image '{}' not found in {}", name, file))?;
            vec![(name, img)]
        }
        None => images.iter().collect(),
    };

    let mut lock_changed = false;

    for (name, image_decl) in iter {
        if !json {
            eprintln!("Building image: {} ({})...", name, image_decl.version);
        }

        let result = if image_decl.disk.is_some() {
            shoot::image::build_disk_image(
                image_decl,
                output_dir,
                &cache_dir,
                &channel,
                &arch,
                &mut lockfile,
            )?
        } else {
            shoot::image::build_image(
                image_decl,
                output_dir,
                &cache_dir,
                &channel,
                &arch,
                &mut lockfile,
            )?
        };

        let fname = result
            .file_name()
            .unwrap_or(result.as_ref())
            .to_string_lossy()
            .to_string();

        if json {
            shoot::output::record_build_result(shoot::output::BuildResultJson {
                name: name.clone(),
                version: image_decl.version.clone(),
                arch: arch.clone(),
                filename: fname,
                sha256: None,
            });
        } else {
            shoot::output::ok(&fname);
        }
        lock_changed = true;
    }

    if lock_changed {
        lockfile.save(lock_path)?;
        shoot::output::ok(format!("lockfile updated: {}", lockfile_path));
    }

    Ok(())
}

// ── Doctor command ──

fn cmd_doctor() -> miette::Result<()> {
    let checks = shoot::doctor::run_all();
    shoot::doctor::print_report(&checks);
    if !shoot::doctor::all_ok(&checks) {
        std::process::exit(1);
    }
    Ok(())
}

// ── Lock command ──

/// `shoot lock`: resolve/refresh all input pins without building.
fn cmd_lock(file: String, lockfile_path: String) -> miette::Result<()> {
    let inputs = if Path::new(&file).exists() {
        match shoot::lua::evaluate_file_with_inputs(&file) {
            Ok(eval) if !eval.global_inputs.is_empty() => eval.global_inputs,
            Ok(_) => {
                eprintln!("  no inputs declared in '{file}', using default");
                default_input_map()
            }
            Err(e) => {
                return Err(miette::miette!("failed to read inputs from '{file}': {e}"));
            }
        }
    } else {
        eprintln!("  no config at '{file}', using default input");
        default_input_map()
    };

    let lock_path = Path::new(&lockfile_path);
    let mut lockfile = LockFile::load(lock_path)?.unwrap_or_else(|| LockFile {
        version: 1,
        sources: HashMap::new(),
        snaps: HashMap::new(),
        inputs: HashMap::new(),
    });

    // Empty names = refresh every declared input.
    let n = shoot::pkg_source::update_input_pins(&inputs, &[], &mut lockfile)?;

    for (name, entry) in &lockfile.inputs {
        if entry.local {
            eprintln!("  {name}: local (unlocked)");
        } else if let Some(rev) = &entry.revision {
            eprintln!("  {name}: pinned to {}", rev.get(..7).unwrap_or(rev));
        }
    }

    lockfile.save(lock_path)?;
    shoot::output::ok(format!("{n} input(s) locked -> {lockfile_path}"));
    Ok(())
}

// ── Index command ──

// ── Cache command ──

fn cmd_cache(sub: CacheCommand) -> miette::Result<()> {
    match sub {
        CacheCommand::Info { cache } => {
            let cache = PackageCache::new(cache.map(std::path::PathBuf::from));
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
        }
        CacheCommand::Clear { cache, force } => {
            let cache = PackageCache::new(cache.map(std::path::PathBuf::from));
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
            shoot::output::ok("cache cleared");
        }
        CacheCommand::Prune { days, cache, force } => {
            let cache = PackageCache::new(cache.map(std::path::PathBuf::from));
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
                shoot::output::ok(format!(
                    "pruned {} cache entr{}",
                    removed,
                    if removed == 1 { "y" } else { "ies" }
                ));
            } else {
                eprintln!("Nothing to prune.");
            }
        }
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
    let _ = shoot::pkg_source::init_global_inputs(&HashMap::new());

    let candidates = shoot::pkg_source::iter_packages();
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
            let inputs = if Path::new(&file).exists() {
                match shoot::lua::evaluate_file_with_inputs(&file) {
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
                    url: "github:rbelem/shoot/main".into(),
                };
                eprintln!("  Updating default package index...");
                if let Err(e) = shoot::pkg_source::refresh_input(&default) {
                    eprintln!("  ✗ failed: {e}");
                } else {
                    eprintln!("  ✓ default package index updated");
                }
            } else {
                for (name, input) in &inputs {
                    eprintln!("  Updating input '{name}'...");
                    match shoot::pkg_source::refresh_input(input) {
                        Ok(_) => eprintln!("  ✓ '{name}' updated"),
                        Err(e) => eprintln!("  ✗ '{name}' failed: {e}"),
                    }
                }
            }
        }
        IndexCommand::List { index } => {
            let path = Path::new(&index);
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
        }

        IndexCommand::Add {
            name,
            summary,
            store_name,
            channel,
            alias,
            index,
        } => {
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
            shoot::output::ok(format!("added '{}' to index", name));
        }

        IndexCommand::Resolve { index, channel } => {
            let path = Path::new(&index);
            let mut idx = if path.exists() {
                PackageIndex::load(path)?
            } else {
                eprintln!("  index file not found at {}", index);
                return Ok(());
            };

            eprintln!("Resolving snap pins from store (channel: {channel})...");
            idx.resolve_all(&channel)?;
            idx.save(path)?;
            shoot::output::ok(format!("index updated: {}", index));
        }
    }

    Ok(())
}
