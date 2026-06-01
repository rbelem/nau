use std::collections::HashMap;
use std::path::Path;

use clap::Parser;
use shoot::cli::{Cli, Command, IndexCommand};
use shoot::image::ImageDeclaration;
use shoot::index::{IndexEntry, PackageIndex, StoreRef};
use shoot::lock::{LockFile, SourceLockEntry};
use shoot::snap::SourceSpec;

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
        } => {
            if order {
                return cmd_order(&file, &output_name);
            }
            cmd_build(
                file,
                stage,
                output,
                arch,
                output_name,
                source_date_epoch,
                lockfile_path,
                all,
                cache,
            )
        }

        Command::Image {
            file,
            output,
            arch,
            channel,
            cache,
            output_name,
            source_date_epoch,
            lockfile: lockfile_path,
        } => cmd_image(
            file,
            output,
            arch,
            channel,
            cache,
            output_name,
            source_date_epoch,
            lockfile_path,
        ),

        Command::Deps {
            package,
            recursive,
            tree,
            flat,
        } => cmd_deps(package, recursive, tree, flat),

        Command::Index(sub) => cmd_index(sub),

        Command::Doctor => cmd_doctor(),
    }
}

// ── Build command ──

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
) -> miette::Result<()> {
    if let Some(ref epoch) = source_date_epoch {
        std::env::set_var("SOURCE_DATE_EPOCH", epoch);
    }

    let lock_path = Path::new(&lockfile_path);
    let mut lockfile = LockFile::load(lock_path)?.unwrap_or_else(|| LockFile {
        version: 1,
        sources: HashMap::new(),
        snaps: HashMap::new(),
    });

    let all_outputs = shoot::lua::evaluate_file(&file)?;

    let stage_dir = std::path::Path::new(&stage);
    let output_dir = std::path::Path::new(&output);

    // Initialize binary cache if --cache was specified or --all is set
    let pkg_cache = if all || cache.is_some() {
        Some(shoot::cache::PackageCache::new(
            cache.map(std::path::PathBuf::from),
        ))
    } else {
        None
    };

    let iter: Vec<(&String, &shoot::snap::SnapMeta)> = match &output_name {
        Some(name) => {
            let meta = all_outputs
                .get(name)
                .ok_or_else(|| miette::miette!("output '{}' not found in {}", name, file))?;
            vec![(name, meta)]
        }
        None => all_outputs.iter().collect(),
    };

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
            eprintln!("── Building {} dependencies ──", all_deps.len());
            for dep_name in &all_deps {
                // Try to load the dependency as a package from pkgs/
                let dep_meta = match shoot::deps::load_meta(dep_name) {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("  ⚠ skipping dependency '{}': {}", dep_name, e);
                        continue;
                    }
                };

                // Check cache first
                if let Some(ref cache) = pkg_cache {
                    if let Some(_cached_path) = cache.lookup(&dep_meta, "amd64") {
                        eprintln!("  ✓ {} (cached)", dep_name);
                        continue;
                    }
                }

                let dep_archs = shoot::snap::resolve_archs(&dep_meta, &arch);
                for a in &dep_archs {
                    eprintln!("  building {} ({})...", dep_name, a);
                    let dep_stage = tempfile::tempdir()
                        .map_err(|e| miette::miette!("failed to create temp stage: {}", e))?;

                    match shoot::snap::build_snap(&dep_meta, dep_stage.path(), output_dir, a) {
                        Ok(result) => {
                            eprintln!("    ✓ {}", result.snap_filename);
                            // Store in cache
                            if let Some(ref cache) = pkg_cache {
                                if let Err(e) = cache.store(&dep_meta, &result, a, output_dir) {
                                    eprintln!("  ⚠ cache store failed: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("  ⚠ build failed for '{}': {}", dep_name, e);
                        }
                    }
                }
            }
        }
    }

    let mut all_source_info: Vec<shoot::snap::SourceInfo> = Vec::new();

    for (name, meta) in iter {
        let archs = shoot::snap::resolve_archs(meta, &arch);

        println!("Building {} ({})...", name, meta.version);
        for a in &archs {
            println!("  {}/{}:", name, a);

            if let Some(SourceSpec::Unverified(ref url)) = meta.source {
                if lockfile.lookup_source(url).is_some() {
                    eprintln!("  ℹ using lockfile hash for {url}");
                }
            }

            let result = shoot::snap::build_snap(meta, stage_dir, output_dir, a)?;
            println!("    ✓ {}", result.snap_filename);

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
        eprintln!("  ✓ lockfile updated: {}", lockfile_path);
    }

    if !all_source_info.is_empty() {
        for info in &all_source_info {
            let status = if lockfile.sources.contains_key(&info.url) {
                "pinned"
            } else {
                "recorded"
            };
            eprintln!("  source {status}: {:16} {}", info.sha256, info.url);
        }
    }

    Ok(())
}

// ── Order command (--order flag) ──

fn cmd_order(file: &str, output_name: &Option<String>) -> miette::Result<()> {
    let all_outputs = shoot::lua::evaluate_file(file)?;

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
        println!("Package: {} {}", meta.name, meta.version);

        if meta.requires.is_empty() {
            println!("  No dependencies");
            continue;
        }

        println!("  Direct requires:");
        for dep in &meta.requires {
            println!("    - {}", dep);
        }

        println!("  Resolved build order (transitive):");
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
                    println!("    {:4} {}", marker, dep);
                }
            }
            Err(e) => {
                println!("    ⚠ could not resolve: {}", e);
            }
        }
    }

    Ok(())
}

// ── Deps command ──

fn cmd_deps(package: String, recursive: bool, tree: bool, flat: bool) -> miette::Result<()> {
    // Load the package
    let names = vec![package.clone()];
    let nodes = shoot::deps::resolve_deps(&names, recursive)?;

    if nodes.is_empty() {
        println!("No dependencies found for '{}'", package);
        return Ok(());
    }

    if tree && recursive {
        println!("Dependency tree for '{}':", package);
        let tree_str = shoot::deps::format_tree(&names, true)?;
        println!("{}", tree_str);
    } else if flat {
        let names_only: Vec<String> = nodes.iter().map(|n| n.name.clone()).collect();
        println!("Build order for '{}':", package);
        for (i, name) in names_only.iter().enumerate() {
            println!("  {}. {}", i + 1, name);
        }
    } else {
        // Default: show the package with its direct requires
        if let Some(pkg) = nodes.first() {
            println!("{} v1.0: {}", package, pkg.name);
            if pkg.requires.is_empty() {
                println!("  No dependencies");
            } else {
                println!("  Requires:");
                for dep in &pkg.requires {
                    println!("    - {}", dep);
                }
                if recursive {
                    println!("  (use --tree or --flat for full transitive resolution)");
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
    output_name: Option<String>,
    source_date_epoch: Option<String>,
    lockfile_path: String,
) -> miette::Result<()> {
    if let Some(ref epoch) = source_date_epoch {
        std::env::set_var("SOURCE_DATE_EPOCH", epoch);
    }
    std::env::set_var("SHOOT_ARCH", &arch);

    let lock_path = Path::new(&lockfile_path);
    let mut lockfile = LockFile::load(lock_path)?.unwrap_or_else(|| LockFile {
        version: 1,
        sources: HashMap::new(),
        snaps: HashMap::new(),
    });

    let lua = shoot::lua::new_lua(&file)?;
    let images = shoot::lua::evaluate_images(&lua, &file)?;

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
        println!("Building image: {} ({})...", name, image_decl.version);

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

        println!(
            "  ✓ {}",
            result
                .file_name()
                .unwrap_or(result.as_ref())
                .to_string_lossy()
        );
        lock_changed = true;
    }

    if lock_changed {
        lockfile.save(lock_path)?;
        eprintln!("  ✓ lockfile updated: {}", lockfile_path);
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

// ── Index command ──

fn cmd_index(sub: IndexCommand) -> miette::Result<()> {
    match sub {
        IndexCommand::List { index } => {
            let path = Path::new(&index);
            let idx = if path.exists() {
                PackageIndex::load(path)?
            } else {
                PackageIndex::load_or_default(path)?
            };

            println!("Package index: {} entries", idx.snaps.len());
            println!();
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
                println!("  {:<20} {}    pins: {}", entry.name, kind, pins);
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
            eprintln!("  ✓ added '{}' to index", name);
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
            eprintln!("  ✓ index updated: {}", index);
        }
    }

    Ok(())
}
