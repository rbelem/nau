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
        } => cmd_build(
            file,
            stage,
            output,
            arch,
            output_name,
            source_date_epoch,
            lockfile_path,
        ),

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

        Command::Index(sub) => cmd_index(sub),

        Command::Doctor => cmd_doctor(),
    }
}

// ── Build command ──

fn cmd_build(
    file: String,
    stage: String,
    output: String,
    arch: Vec<String>,
    output_name: Option<String>,
    source_date_epoch: Option<String>,
    lockfile_path: String,
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

    let iter: Vec<(&String, &shoot::snap::SnapMeta)> = match &output_name {
        Some(name) => {
            let meta = all_outputs
                .get(name)
                .ok_or_else(|| miette::miette!("output '{}' not found in {}", name, file))?;
            vec![(name, meta)]
        }
        None => all_outputs.iter().collect(),
    };

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

        let result = shoot::image::build_image(
            image_decl,
            output_dir,
            &cache_dir,
            &channel,
            &arch,
            &mut lockfile,
        )?;

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
