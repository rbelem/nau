//! The `cmd_*` command handlers (#313): every ADR-0049 verb's body,
//! moved verbatim from the binary entry. The binary dispatches the CLI
//! enum onto these; finer domain carving is #316/#317's job.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::cache::PackageCache;
use crate::cli::{
    BuildArgs, CaCommand, CacheCommand, Cli, IndexCommand, KeyCommand, PodCommand, RuntimeCommand,
};
use crate::image::ImageDeclaration;
use crate::index::{IndexEntry, PackageIndex, StoreRef};
use crate::lock::LockFile;
use crate::runtime::{changed_pins, PendingSnap, RuntimeStore, RuntimeTools, SignatureEnvelope};
use crate::snap::{PackageInput, SnapRef};
use miette::{IntoDiagnostic, WrapErr};

use crate::build_orch::{
    default_input_map, evaluate_file_or_embedded, load_lockfile_or_default, pin_update_line,
    resolve_build_outputs, resolve_file, run_build,
};

// ── Build command ──

#[allow(clippy::too_many_arguments)]
pub fn cmd_build(
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

    let (all_outputs, workers, file) =
        resolve_build_outputs(&file, update.as_deref(), offline, &lockfile_path)?;
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
        workers,
    )
}

/// The `nau build` arm of the CLI dispatch (#313): the output-mode and
/// NAU_OFFLINE setup, the package-name fallback for the positional, and
/// the `--order` branch — moved verbatim from `main()` so the binary is
/// a thin match.
pub fn build_command(args: BuildArgs) -> miette::Result<()> {
    let BuildArgs {
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
    } = args;
    crate::output::set_mode(json);
    // The eval worker reads this to refuse fetch() (ADR: eval-time
    // network is opt-in and never survives --offline).
    if offline {
        std::env::set_var("NAU_OFFLINE", "1");
    }
    // If --file is default and doesn't exist, try output_name as package name
    let file = if file == "nau.lua" && !Path::new("nau.lua").exists() {
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
        crate::output::flush_json("order");
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
    crate::output::flush_json("build");
    r
}

// ── Order command (--order flag) ──

fn cmd_order(file: &str, output_name: &Option<String>, json: bool) -> miette::Result<()> {
    // Initialize global inputs (default if no config)
    crate::pkg_source::init_global_inputs(&HashMap::new())?;
    let file = resolve_file(file)?;
    let all_outputs = evaluate_file_or_embedded(&file)?;

    let iter: Vec<&crate::snap::SnapMeta> = match output_name {
        Some(name) => {
            let meta = all_outputs
                .get(name)
                .ok_or_else(|| miette::miette!("output '{}' not found in {}", name, file))?;
            vec![meta]
        }
        None => {
            // `Outputs` is a HashMap: sort for deterministic multi-output
            // report order run to run.
            let mut metas: Vec<(&String, &crate::snap::SnapMeta)> = all_outputs.iter().collect();
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
fn report_order_json(meta: &crate::snap::SnapMeta) {
    let seeds = crate::deps::build_dep_seeds(meta);
    if seeds.is_empty() {
        return;
    }
    let seen: std::collections::HashSet<&str> = seeds.iter().map(|s| s.as_str()).collect();
    if let Ok(order) = crate::deps::resolve_dep_names(&seeds, true) {
        for dep in &order {
            let kind = if seen.contains(dep.as_str()) {
                "direct"
            } else {
                "transitive"
            };
            crate::output::record_order_result(crate::output::OrderResultJson {
                name: dep.clone(),
                kind: kind.to_string(),
            });
        }
    }
}

/// Text-mode order report for one output.
fn report_order_human(meta: &crate::snap::SnapMeta) {
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
    let seeds = crate::deps::build_dep_seeds(meta);
    match crate::deps::resolve_dep_names(&seeds, true) {
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

/// `nau deps fetch` (ADR-0017, issue #13): force a dependency-closure
/// fetch for the pod's interpreted packages. Reports each fetched closure
/// (and whether content moved) plus locked packages left untouched.
pub fn cmd_deps_fetch(pod: Option<&str>, root: Option<&str>, latest: bool) -> miette::Result<()> {
    let pod_name = pod.unwrap_or(crate::pod::DEFAULT_POD);
    let root = crate::pod::pod_root(root);
    let report = crate::pod::fetch_pod_deps(&root, pod_name, latest)?;
    for entry in &report.fetched {
        if entry.changed {
            crate::output::ok(format!(
                "fetched dependency closure for '{}' ({:.12}…)",
                entry.name, entry.deps_hash
            ));
        } else {
            crate::output::info(format!(
                "dependency closure for '{}' re-fetched, content unchanged ({:.12}…)",
                entry.name, entry.deps_hash
            ));
        }
    }
    for name in &report.skipped {
        crate::output::info(format!(
            "skipped '{name}': locked and its closure pin is cached (use --latest to re-resolve)"
        ));
    }
    for name in &report.sideloaded {
        crate::output::info(format!(
            "skipped '{name}' (sideloaded — blob pins never re-resolve from the collection)"
        ));
    }
    if report.fetched.is_empty() && report.skipped.is_empty() && report.sideloaded.is_empty() {
        crate::output::info(format!(
            "pod '{pod_name}' declares no dependency closures (deps = {{ npm = ... }} / pip)"
        ));
    }
    Ok(())
}

pub fn cmd_deps(
    package: String,
    recursive: bool,
    tree: bool,
    flat: bool,
    json: bool,
) -> miette::Result<()> {
    crate::pkg_source::init_global_inputs(&HashMap::new())?;
    let names = vec![package.clone()];
    let nodes = crate::deps::resolve_deps(&names, recursive)?;

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
fn report_deps_json(nodes: &[crate::deps::DepNode]) {
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
        crate::output::record_dep_result(crate::output::DepResultJson {
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
    nodes: &[crate::deps::DepNode],
    tree: bool,
    recursive: bool,
    flat: bool,
) -> miette::Result<()> {
    if tree && recursive {
        eprintln!("Dependency tree for '{}':", package);
        let names = vec![package.to_string()];
        let tree_str = crate::deps::format_tree(&names, true)?;
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
/// Pin the build epoch when the flag carries one (the env form is
/// already exported — the release gate requires one or the other).
fn pin_epoch(source_date_epoch: Option<&str>) {
    if let Some(epoch) = source_date_epoch {
        std::env::set_var("SOURCE_DATE_EPOCH", epoch);
    }
}

/// The #266 release gates (ADR-0044 D5/D8): the epoch must be pinned
/// (release media must be byte-reproducible) and the media names carry an
/// explicit architecture. `None` when this is a plain dev build.
fn release_args(
    release: &Option<String>,
    arch: &str,
    source_date_epoch: Option<&str>,
) -> miette::Result<Option<crate::image::release::ReleaseArgs>> {
    let Some(dir) = release else {
        return Ok(None);
    };
    if source_date_epoch.is_none() && std::env::var_os("SOURCE_DATE_EPOCH").is_none() {
        return Err(miette::miette!(
            "--release requires a pinned SOURCE_DATE_EPOCH — pass \
             --source-date-epoch <unix-seconds> or export SOURCE_DATE_EPOCH; \
             release media must be byte-reproducible (ADR-0044 D8)"
        ));
    }
    if arch == "all" {
        return Err(miette::miette!(
            "--release media name the architecture \
             (nau-<mission>-<version>-<arch>) — pass an explicit --arch, \
             e.g. --arch amd64"
        ));
    }
    Ok(Some(crate::image::release::ReleaseArgs {
        dir: PathBuf::from(dir),
    }))
}

/// The build destination: the release export tree in release mode, else
/// the `--output` directory.
fn image_output_dir<'a>(
    output: &'a str,
    release_args: Option<&'a crate::image::release::ReleaseArgs>,
) -> &'a Path {
    release_args
        .map(|r| r.dir.as_path())
        .unwrap_or_else(|| Path::new(output))
}

/// The images to build; release mode demands exactly ONE named pick —
/// the media set is a named artifact, not a batch output.
fn select_build_images<'a>(
    images: &'a HashMap<String, ImageDeclaration>,
    output_name: &'a Option<String>,
    file: &str,
    release: bool,
) -> miette::Result<Vec<(&'a String, &'a ImageDeclaration)>> {
    let iter = select_images(images, output_name, file)?;
    if release && iter.len() != 1 {
        return Err(miette::miette!(
            "--release publishes exactly ONE named mission image — pass \
             --output-name <name> to pick it (found {} declared images in {file})",
            iter.len()
        ));
    }
    Ok(iter)
}

/// `nau image` (the #266 release gates live in [`release_args`] and
/// [`select_build_images`]).
#[allow(clippy::too_many_arguments)]
pub fn cmd_image(
    file: String,
    output: String,
    arch: String,
    channel: String,
    cache: Option<String>,
    _cache_max_size: Option<String>,
    output_name: Option<String>,
    source_date_epoch: Option<String>,
    release: Option<String>,
    lockfile_path: String,
    json: bool,
) -> miette::Result<()> {
    crate::pkg_source::init_global_inputs(&HashMap::new())?;
    let file = resolve_file(&file)?;

    // #266 gates (ADR-0044 D5/D8): a release pins the epoch, names the
    // architecture, and publishes exactly ONE named disk image — Cassini
    // ships named artifacts, not ad-hoc builds.
    let release_args = release_args(&release, &arch, source_date_epoch.as_deref())?;

    pin_epoch(source_date_epoch.as_deref());
    std::env::set_var("NAU_ARCH", &arch);

    let lock_path = Path::new(&lockfile_path);
    let mut lockfile = load_lockfile_or_default(lock_path)?;

    let images = resolve_images(&file)?;
    // In release mode the build lands directly in the export tree under
    // the release media name — one set of image bytes, correctly named,
    // no duplicate artifact inviting distribution of the wrong one.
    let output_dir = image_output_dir(&output, release_args.as_ref());
    let cache_dir = image_cache_dir(cache.as_deref());
    let iter = select_build_images(&images, &output_name, &file, release_args.is_some())?;

    // Every selected image records lockfile pins as it builds.
    let lock_changed = !iter.is_empty();
    build_images(
        &iter,
        output_dir,
        &cache_dir,
        &channel,
        &arch,
        &mut lockfile,
        release_args.as_ref(),
        json,
    )?;

    if lock_changed {
        lockfile.save(lock_path)?;
        crate::output::ok(format!("lockfile updated: {}", lockfile_path));
    }

    Ok(())
}

/// `nau verify-image` (ADR-0044 D4, #265): read-only flash
/// verification against the published signed image manifest. The
/// machinery lives in [`crate::image::verify`]; this handler binds the
/// real runner and reports the outcome.
pub fn cmd_verify_image(
    device: &str,
    manifest: &str,
    key: Option<&str>,
    slot: crate::image::SlotSelector,
    json: bool,
) -> miette::Result<()> {
    let args = crate::image::VerifyImageArgs {
        device: PathBuf::from(device),
        manifest: PathBuf::from(manifest),
        key: key.map(PathBuf::from),
        slot,
    };
    let outcome = crate::image::verify_device(&crate::command::RealRunner, &args)?;
    if json {
        let report = serde_json::json!({
            "command": "verify-image",
            "device": device,
            "manifest": manifest,
            "slot": outcome.slot,
            "image": format!("{} {}", outcome.image_name, outcome.image_version),
            "verified_key_id": outcome.verified_key_id,
            "roothash": outcome.roothash,
            "root_partuuid": outcome.root_partuuid,
            "hash_partuuid": outcome.hash_partuuid,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|e| miette::miette!("verify-image JSON serialization: {e}"))?
        );
    } else {
        crate::output::ok(format!(
            "verified '{}' {} — slot {} root ({}) over hash ({}) recomputes to the \
             manifest roothash, under key {}",
            outcome.image_name,
            outcome.image_version,
            outcome.slot,
            outcome.root_partuuid,
            outcome.hash_partuuid,
            outcome.verified_key_id
        ));
        crate::output::info("the flashed medium matches the signed manifest (ADR-0044 D4)");
    }
    Ok(())
}

/// Load the image declarations for `file`. Embedded packages are single
/// snaps, not images — reported and treated as "no images".
fn resolve_images(file: &str) -> miette::Result<HashMap<String, ImageDeclaration>> {
    if let Some(_embedded) = file.strip_prefix("embedded://") {
        // Embedded packages are single snaps, not images — return empty
        if !crate::output::is_json() {
            crate::output::warn(format!("'{}' is a package, not an image", file));
        }
        Ok(std::collections::HashMap::new())
    } else {
        crate::lua::evaluate_images_file(file)
    }
}

/// Resolve the image cache directory: the --cache override, else the
/// default under $HOME.
fn image_cache_dir(cache: Option<&str>) -> std::path::PathBuf {
    cache.map_or_else(
        || {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            Path::new(&home).join(".cache/nau/snaps")
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
#[allow(clippy::too_many_arguments)]
fn build_images(
    iter: &[(&String, &ImageDeclaration)],
    output_dir: &Path,
    cache_dir: &Path,
    channel: &str,
    arch: &str,
    lockfile: &mut LockFile,
    release: Option<&crate::image::release::ReleaseArgs>,
    json: bool,
) -> miette::Result<()> {
    for (name, image_decl) in iter {
        if !json {
            eprintln!("Building image: {} ({})...", name, image_decl.version);
        }

        build_one_image(
            name, image_decl, output_dir, cache_dir, channel, arch, lockfile, release, json,
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
    release: Option<&crate::image::release::ReleaseArgs>,
    json: bool,
) -> miette::Result<()> {
    // #266: the release media set is the verity-protected whole-disk
    // mission image (ADR-0044 D1/D5) — the plain squashfs path has no
    // roothash and would publish a manifest verify-image must refuse.
    if release.is_some() && image_decl.disk.is_none() {
        return Err(miette::miette!(
            "--release requires a disk() mission image — '{}' declares no disk, so it \
             has no whole-disk GPT artifact to publish and no roothash to verify \
             against (ADR-0044 D1)",
            name
        ));
    }
    let result = if image_decl.disk.is_some() {
        crate::image::build_disk_image(
            image_decl, output_dir, cache_dir, channel, arch, lockfile, release,
        )?
    } else {
        crate::image::build_image(image_decl, output_dir, cache_dir, channel, arch, lockfile)?
    };

    let fname = result
        .file_name()
        .unwrap_or(result.as_ref())
        .to_string_lossy()
        .to_string();

    if json {
        crate::output::record_build_result(crate::output::BuildResultJson {
            name: name.to_string(),
            version: image_decl.version.clone(),
            arch: arch.to_string(),
            filename: fname,
            sha256: None,
            sources: None,
            executor: "local".into(),
            worker: None,
        });
    } else {
        crate::output::ok(&fname);
    }
    Ok(())
}

// ── Doctor command ──

pub fn cmd_doctor(
    pod: Option<Option<String>>,
    fix: bool,
    from: Option<&str>,
) -> miette::Result<()> {
    if from.is_some() && !fix {
        miette::bail!("--from requires --fix: doctor only provisions with explicit consent");
    }
    if fix {
        let source = match from {
            Some(dir) => crate::tools::ProvisionSource::FromDir(PathBuf::from(dir)),
            None => crate::tools::ProvisionSource::Fetch,
        };
        println!("provisioning floor tools (issue #101)...");
        let installed = crate::tools::provision(source)
            .into_diagnostic()
            .wrap_err("floor-tool provisioning failed")?;
        println!(
            "  ✓ floor tools provisioned — tools v{} active in {}",
            installed.tools_version,
            installed.bin_dir.display()
        );
    }
    let mut checks = if pod.is_some() || fix {
        crate::doctor::run_pod()
    } else {
        crate::doctor::run_all()
    };
    // `--pod <name>` (issue #231): the failed-unit scan for the named
    // pod. The name is validated fail-closed at the CLI boundary; the
    // scan itself is advisory (hint-only, never fails the report).
    if let Some(pod_name) = pod.clone().flatten().as_deref() {
        let (name, _) =
            crate::pod::resolve_pod_dir_under(&crate::pod::pod_root(None), Some(pod_name))?;
        checks.push(crate::doctor::check_pod_failed_units(&name));
    }
    crate::doctor::print_report(&checks);
    crate::doctor::print_notices();
    if !crate::doctor::all_ok(&checks) {
        std::process::exit(1);
    }
    Ok(())
}

// ── Check command ──

/// `nau check`: run one definition through the analyzer gate first
/// (ADR-0010 Decision 2 — `--!strict` type checking in the bounded
/// `__check-worker` subprocess, fail-closed on timeout with a single
/// `analysis timed out` diagnostic; fast fail with spanned diagnostics
/// before any eval work), then the existing bounded subprocess eval +
/// Rust-side schema validation (Decisions 3-5). Deterministic, no build, no
/// store access — the AI feedback-loop entry point. Exits 1 when the
/// definition has any problem.
pub fn cmd_check(file: &str, json: bool) -> miette::Result<()> {
    // Stage 1 — analyzer gate. A definition that does not type-check never
    // reaches the eval stage.
    let analyzer_diagnostics = crate::analysis::check_definition_file(file);
    let mut diagnostics: Vec<crate::lua::CheckDiagnostic> = analyzer_diagnostics
        .into_iter()
        .map(|d| crate::lua::CheckDiagnostic::from_analyzer(file, d))
        .collect();

    // Stage 2 — bounded subprocess eval + Rust-side validation (unchanged
    // path; the analyzer is check-only). `None` when stage 1 failed fast.
    let checked = if diagnostics.is_empty() {
        Some(crate::lua::check_file_with_inputs(file))
    } else {
        None
    };

    if let Some(checked) = &checked {
        diagnostics.extend(checked.diagnostics.clone());
        // A hard eval failure is a diagnostic too, so both output modes carry
        // the complete problem list in one shape.
        if let Some(err) = &checked.error {
            diagnostics.push(crate::lua::CheckDiagnostic {
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
    let lint: Vec<crate::lint::LintWarning> = checked
        .as_ref()
        .filter(|c| c.error.is_none())
        .map(|c| crate::lint::confinement_lint(&c.outputs))
        .unwrap_or_default();
    for w in &lint {
        crate::output::warn(&w.message);
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
    diagnostics: &[crate::lua::CheckDiagnostic],
    lint: &[crate::lint::LintWarning],
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

/// Success message for `nau check` — each output shown with its
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
    crate::output::ok(check_ok_message(outputs));
}

fn report_check_diagnostic(d: &crate::lua::CheckDiagnostic) {
    match (&d.key, &d.span) {
        // Keyed diagnostics with a located declaration site show both: the
        // file:line:col prefix (grep-friendly, matches the analyzer arm)
        // plus the output key in brackets.
        (Some(key), Some(s)) => crate::output::err(format!(
            "{}:{}:{}: [{key}] {}",
            d.label, s.begin_line, s.begin_col, d.message
        )),
        (Some(key), None) => crate::output::err(format!("{}[{key}]: {}", d.label, d.message)),
        // Analyzer diagnostics print with their 1-based begin span.
        (None, Some(s)) => crate::output::err(format!(
            "{}:{}:{}: {}",
            d.label, s.begin_line, s.begin_col, d.message
        )),
        (None, None) => crate::output::err(&d.message),
    }
}

// ── Lint command (issue #53) ──

/// Load the package index the same way the eval worker does
/// (`NAU_INDEX_PATH`, else `package-index.json` in the CWD).
fn lint_index() -> miette::Result<crate::index::PackageIndex> {
    let path = std::env::var("NAU_INDEX_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(crate::index::DEFAULT_INDEX));
    crate::index::PackageIndex::load_or_default(&path)
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
fn lint_pod_package(spec_str: &str) -> crate::checks::PodPackageMeta {
    let Ok(spec) = crate::pod::parse_pod_package(spec_str) else {
        return crate::checks::PodPackageMeta {
            spec: spec_str.to_string(),
            name: spec_str.to_string(),
            meta: None,
        };
    };
    // Resolution is data-only over local inputs — never the network.
    let meta = crate::deps::load_meta(&spec.name).ok();
    crate::checks::PodPackageMeta {
        spec: spec_str.to_string(),
        name: spec.name,
        meta,
    }
}

/// Resolve a pod's declared packages to metas for the lint, offline: the
/// declaration comes from the pod state directory, each package
/// declaration from local inputs.
fn lint_pod(pod_name: &str) -> miette::Result<crate::checks::PodLintData> {
    let root = crate::pod::pod_root(None);
    let decl_path = crate::pod::pod_lua_path(&root, pod_name);
    if !decl_path.exists() {
        miette::bail!(
            "pod '{pod_name}' has no declaration at {} (read verbs do not initialize pods)",
            decl_path.display()
        );
    }
    let decl = crate::pod::evaluate_pod_file(&decl_path)?;
    let packages = decl
        .packages
        .iter()
        .map(|spec| lint_pod_package(spec))
        .collect();
    Ok(crate::checks::PodLintData {
        name: pod_name.to_string(),
        packages,
    })
}

/// One finding's human-readable line pair (message + fix hint).
fn lint_finding_lines(f: &crate::checks::Finding, label: &str) -> String {
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
fn report_lint_human(findings: &[crate::checks::Finding], label: &str) {
    for f in findings {
        let lines = lint_finding_lines(f, label);
        match f.severity {
            crate::checks::Severity::Error => crate::output::err(lines),
            crate::checks::Severity::Warn => crate::output::warn(lines),
        }
    }
    if findings.is_empty() {
        crate::output::ok("lint clean: 0 findings");
    } else {
        let errors = findings
            .iter()
            .filter(|f| f.severity == crate::checks::Severity::Error)
            .count();
        crate::output::status(format!(
            "lint: {errors} error(s), {} warning(s)",
            findings.len() - errors
        ));
    }
}

/// JSON report shape for `nau lint --json`.
fn report_lint_json(findings: &[crate::checks::Finding], label: &str) {
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
        .filter(|f| f.severity == crate::checks::Severity::Error)
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

/// `nau lint`: run the check battery over a definition file (or a
/// pod's packages) and report findings. Exit code 1 only on error findings.
pub fn cmd_lint(
    file: String,
    pod: Option<String>,
    channel: String,
    json: bool,
) -> miette::Result<()> {
    crate::output::set_mode(json);
    let index = lint_index()?;

    let (label, eval, pod_data) = if let Some(pod_name) = pod.as_deref() {
        let data = lint_pod(pod_name)?;
        let path = crate::pod::pod_lua_path(&crate::pod::pod_root(None), pod_name);
        (path.display().to_string(), None, Some(data))
    } else {
        let eval = crate::lua::lint_eval_file(&file)?;
        for d in &eval.diagnostics {
            crate::output::warn(d);
        }
        (file.clone(), Some(eval), None)
    };

    let empty_raw = BTreeMap::new();
    let empty_outputs = crate::lua::Outputs::new();
    let empty_images: std::collections::HashMap<String, crate::image::ImageDeclaration> =
        Default::default();
    let no_unparsed: Vec<String> = Vec::new();
    let stage_dir = eval.is_some().then(|| lint_stage_dir(&file)).flatten();
    let arch = std::env::var("NAU_ARCH").unwrap_or_else(|_| "amd64".into());

    let input = crate::checks::LintInput {
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

    let findings = crate::checks::run_battery(&input);
    if json {
        report_lint_json(&findings, &label);
    } else {
        report_lint_human(&findings, &label);
    }

    if crate::checks::has_errors(&findings) {
        std::process::exit(1);
    }
    Ok(())
}

// ── Audit command (issue #52) ──

/// Human report: every finding on its channel, then summary lines
/// carrying the audit counters and the database state.
fn report_audit_human(report: &crate::audit::AuditReport, label: &str, cache_dir: &Path) {
    for f in &report.findings {
        let lines = lint_finding_lines(f, label);
        match f.severity {
            crate::checks::Severity::Error => crate::output::err(lines),
            crate::checks::Severity::Warn => crate::output::warn(lines),
        }
    }
    if report.findings.is_empty() {
        crate::output::ok("audit clean: 0 findings");
    } else {
        let errors = report
            .findings
            .iter()
            .filter(|f| f.severity == crate::checks::Severity::Error)
            .count();
        crate::output::status(format!(
            "audit: {} lockfile pin(s), {errors} error(s), {} warning(s)",
            report.targets,
            report.findings.len() - errors
        ));
    }
    if report.degraded {
        crate::output::warn(format!(
            "OSV database unreachable (offline?) — {} pin(s) left unaudited; run \
             `nau audit --update` when online (cache: {})",
            report.unaudited,
            cache_dir.display()
        ));
    }
}

/// JSON report: the `nau lint --json` shape (file/ok/errors/warnings/
/// findings) plus an additive `database` object for the audit counters.
fn report_audit_json(report: &crate::audit::AuditReport, label: &str) {
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
        .filter(|f| f.severity == crate::checks::Severity::Error)
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

/// `nau audit`: check lockfile pins against the OSV vulnerability
/// database (issue #52). Exit code 1 only on confirmed (version-matched)
/// findings; offline/stale databases warn, never fail.
pub fn cmd_audit(
    file: Option<String>,
    lockfile: String,
    update: bool,
    json: bool,
) -> miette::Result<()> {
    crate::output::set_mode(json);
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
        Some(f) => Some(crate::lua::lint_eval_file(f)?.raw),
        None => None,
    };

    let cfg = crate::audit::AuditConfig::from_env(update);
    let report = crate::audit::run_audit(&lock, raw.as_ref(), &cfg)?;

    if json {
        report_audit_json(&report, &lockfile);
    } else {
        report_audit_human(&report, &lockfile, &cfg.cache_dir);
    }

    if crate::checks::has_errors(&report.findings) {
        std::process::exit(1);
    }
    Ok(())
}

// ── Lock command ──

/// `nau lock`: resolve/refresh all input pins without building.
pub fn cmd_lock(file: String, lockfile_path: String) -> miette::Result<()> {
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
    let updates = crate::pkg_source::update_input_pins(&inputs, &[], &mut lockfile)?;

    report_lock_status(&updates, &lockfile);

    lockfile.save(lock_path)?;

    report_lock_output(&lockfile, &lockfile_path, updates.len())?;
    Ok(())
}

/// The inputs a `nau lock` run refreshes: the definition's global
/// inputs when the config exists and declares any, the default input
/// otherwise.
fn resolve_lock_inputs(file: &str) -> miette::Result<HashMap<String, PackageInput>> {
    let inputs = if Path::new(file).exists() {
        match crate::lua::evaluate_file_with_inputs(file) {
            Ok(eval) if !eval.global_inputs.is_empty() => eval.global_inputs,
            Ok(_) => {
                crate::output::info(format!("no inputs declared in '{file}', using default"));
                default_input_map()
            }
            Err(e) => {
                return Err(miette::miette!("failed to read inputs from '{file}': {e}"));
            }
        }
    } else {
        crate::output::info(format!("no config at '{file}', using default input"));
        default_input_map()
    };
    Ok(inputs)
}

/// Status lines for a lock run: each refreshed pin (old→new), then every
/// pin currently recorded in the lockfile.
fn report_lock_status(updates: &[crate::pkg_source::InputPinUpdate], lockfile: &LockFile) {
    for u in updates {
        crate::output::status(pin_update_line(u));
    }
    for (name, entry) in &lockfile.inputs {
        if entry.local {
            crate::output::status(format!("{name}: local (unlocked)"));
        } else if let Some(rev) = &entry.revision {
            crate::output::status(format!("{name}: pinned to {}", rev.get(..7).unwrap_or(rev)));
        }
    }
}

/// JSON/human output tail for `nau lock` (the lockfile is already
/// saved by the time this runs).
fn report_lock_output(
    lockfile: &LockFile,
    lockfile_path: &str,
    updated: usize,
) -> miette::Result<()> {
    if crate::output::is_json() {
        let mut pins: Vec<crate::output::LockPinJson> = lockfile
            .inputs
            .iter()
            .map(|(name, e)| crate::output::LockPinJson {
                name: name.clone(),
                local: e.local,
                revision: e.revision.clone(),
                sha256: e.sha256.clone(),
            })
            .collect();
        pins.sort_by(|a, b| a.name.cmp(&b.name));
        let out = crate::output::LockOutputJson {
            command: "lock".to_string(),
            lockfile: lockfile_path.to_string(),
            updated,
            pins,
        };
        let json = serde_json::to_string_pretty(&out)
            .map_err(|e| miette::miette!("failed to serialize lock output: {e}"))?;
        println!("{json}");
    } else {
        crate::output::ok(format!("{} input(s) locked -> {lockfile_path}", updated));
    }
    Ok(())
}

// ── Eval command ──

/// `nau eval`: evaluate a definition and emit the image manifest IR
/// (Phase 23, cross-distro-synthesis §5). No build, no store writes.
///
/// Resolution is data-only — definition pins, the Phase 16 lockfile, and
/// pre-resolved package-index pins — so a fully pinned project evals
/// offline and the result is a deterministic function of the definition +
/// lockfile. `--offline` additionally forbids fetching uncached package
/// inputs (named fail-closed error, same as build). Unresolvable pins and
/// missing lock entries fail closed: no partial manifest is ever written.
#[allow(clippy::too_many_arguments)]
pub fn cmd_eval(
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
    std::env::set_var("NAU_ARCH", &arch);

    let lock_path = Path::new(&lockfile_path);
    let mut lockfile = load_lockfile_or_default(lock_path)?;

    // Definition eval: snap outputs + global inputs, through the bounded
    // subprocess worker.
    let eval = crate::lua::evaluate_file_with_inputs(&file)?;

    materialize_eval_input_pins(&eval.global_inputs, &mut lockfile, lock_path, offline)?;

    // Image declarations (a second bounded eval of the same file, sharing
    // the worker output table with the snap outputs).
    let images = resolve_images(&file)?;

    let mut manifest = crate::manifest::build_manifest(
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
        let n = crate::pkg_source::ensure_input_pins(global_inputs, lockfile)?;
        pins_recorded |= n > 0;
    }
    crate::pkg_source::init_global_inputs_with(global_inputs, &lockfile.inputs, offline)?;
    if pins_recorded {
        lockfile.save(lock_path)?;
    }
    Ok(())
}

/// ADR-0011 step (d) + issue #56: opt-in manifest signing. A key at
/// ~/.config/nau/secret-key attests the canonical bytes (signatures
/// map excluded) and carries the SLSA-lite provenance under the
/// signature — builder, invocation, materials, subject digest. An
/// absent key keeps `signatures` {} with a note — eval never fails on
/// signing and never generates keys (that is the image build's
/// deliberate engagement; mandated signing is step (e)).
fn sign_eval_manifest(
    manifest: &mut crate::manifest::ImageManifest,
    arch: &str,
    channel: &str,
    offline: bool,
) {
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
    match crate::sign::load_secret_key(&home) {
        Ok(Some(kp)) => {
            let version = env!("CARGO_PKG_VERSION");
            match crate::sign::attest_eval(manifest, &kp, version, arch, channel, offline) {
                Ok(()) => eprintln!(
                    "  ✓ manifest signed with provenance (key id {}, builder {})",
                    kp.key_id(),
                    crate::sign::builder_id(version)
                ),
                Err(e) => eprintln!("  ⚠ signing skipped: {e:#}"),
            }
        }
        Ok(None) => {
            eprintln!(
                "  ℹ no signing key at {} — signatures left empty (opt-in until \
                 ceremony)",
                crate::sign::secret_key_path(&home).display()
            );
        }
        Err(e) => eprintln!("  ⚠ signing skipped: {e:#}"),
    }
}

/// Write the eval result: the manifest file plus a human confirmation
/// line, or the JSON bytes on stdout when no `--output` was given.
fn emit_eval_output(
    manifest: &crate::manifest::ImageManifest,
    output: Option<&str>,
) -> miette::Result<()> {
    match output {
        Some(out_path) => {
            manifest.write_atomic(Path::new(out_path))?;
            if !crate::output::is_json() {
                crate::output::ok(format!(
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

pub fn cmd_cache(sub: CacheCommand) -> miette::Result<()> {
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

/// `nau cache info`: print cache statistics.
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

/// `nau cache clear`: remove all cached packages, guarded by `--force`.
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
    crate::output::ok("cache cleared");
    Ok(())
}

/// `nau cache prune`: remove cache entries not accessed in `days`,
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
        crate::output::ok(format!(
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
/// `<home>/.config/nau/`.
fn key_home(home: Option<String>) -> PathBuf {
    home.map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())))
}

pub fn cmd_key(sub: KeyCommand) -> miette::Result<()> {
    match sub {
        KeyCommand::Keygen { home, json } => {
            crate::output::set_mode(json);
            key_keygen(key_home(home))
        }
        KeyCommand::Rotate {
            home,
            manifest,
            window_days,
            json,
        } => {
            crate::output::set_mode(json);
            key_rotate(key_home(home), manifest, window_days)
        }
        KeyCommand::Promote { home, json } => {
            crate::output::set_mode(json);
            key_promote(key_home(home))
        }
        KeyCommand::Revoke { key_id, home, json } => {
            crate::output::set_mode(json);
            key_revoke(key_home(home), &key_id)
        }
        KeyCommand::List { home, json } => {
            crate::output::set_mode(json);
            key_list(key_home(home))
        }
        KeyCommand::Verify {
            manifest,
            home,
            json,
        } => {
            crate::output::set_mode(json);
            key_verify(key_home(home), &manifest)
        }
    }
}

/// `nau key keygen`: mint the secret key and trust it immediately.
/// Never prints the seed. The creation date is recorded in the ceremony
/// ledger (issue #51) — the audit trail starts here.
fn key_keygen(home: PathBuf) -> miette::Result<()> {
    let kp = crate::sign::create_secret_key(&home)?;
    let anchor = crate::sign::install_public_key(&kp, &crate::sign::keys_dir(&home))?;
    let mut ledger = crate::sign::CeremonyLedger::load(&crate::sign::keys_dir(&home))?;
    ledger.record_created(&kp, &crate::sign::now_rfc3339());
    ledger.save(&crate::sign::keys_dir(&home))?;
    crate::output::ok(format!(
        "signing key created: {} (key id {})",
        crate::sign::secret_key_path(&home).display(),
        kp.key_id()
    ));
    crate::output::info(format!("trust anchor installed: {}", anchor.display()));
    print_report(&serde_json::json!({
        "key_id": kp.key_id(),
        "secret_key": crate::sign::secret_key_path(&home).display().to_string(),
        "anchor": anchor.display().to_string(),
    }));
    Ok(())
}

/// `nau key rotate`: mint `secret-key.new`, record the generation
/// chain in the ledger (old id → successor → date → overlap window), and
/// dual-sign `--manifest` under the successor when given — the old
/// signature entry is kept, and an attested entry's provenance is
/// re-attached under the new signature (same claims, new key; issue #51).
fn key_rotate(home: PathBuf, manifest: Option<String>, window_days: u32) -> miette::Result<()> {
    let successor = crate::sign::mint_rotation_key(&home)?;
    let old = crate::sign::load_secret_key(&home)?.expect("rotation key requires an active key");
    let keys_dir = crate::sign::keys_dir(&home);
    let mut ledger = crate::sign::CeremonyLedger::load(&keys_dir)?;
    ledger.record_rotation(&old, &successor, &crate::sign::now_rfc3339(), window_days);
    ledger.save(&keys_dir)?;

    if let Some(path) = &manifest {
        rotate_dual_sign_manifest(path, &successor)?;
    }

    crate::output::ok(format!(
        "rotation key minted: {} (key id {}) — not trusted until promoted",
        crate::sign::rotation_key_path(&home).display(),
        successor.key_id()
    ));
    crate::output::info(format!(
        "generation chain recorded: {} replaced by {} (window {} days)",
        old.key_id(),
        successor.key_id(),
        window_days
    ));
    print_rotate_report(&home, &old, &successor, window_days, manifest.as_deref());
    Ok(())
}

/// The `--manifest` half of `nau key rotate`: dual-sign the manifest
/// file under the successor (old entries kept, provenance re-attached)
/// and write it back atomically.
fn rotate_dual_sign_manifest(path: &str, successor: &crate::sign::KeyPair) -> miette::Result<()> {
    let mut parsed = read_manifest(path)?;
    crate::sign::cosign_reattaching_provenance(&mut parsed, successor)?;
    parsed.write_atomic(std::path::Path::new(path))?;
    crate::output::ok(format!(
        "manifest dual-signed: {path} (key id {} beside the existing entries)",
        successor.key_id()
    ));
    Ok(())
}

/// The JSON report of a rotation, manifest field included when one was
/// dual-signed.
fn print_rotate_report(
    home: &Path,
    old: &crate::sign::KeyPair,
    successor: &crate::sign::KeyPair,
    window_days: u32,
    manifest: Option<&str>,
) {
    let mut report = serde_json::json!({
        "key_id": successor.key_id(),
        "rotation_key": crate::sign::rotation_key_path(home).display().to_string(),
        "trusted": false,
        "replaces": old.key_id(),
        "window_days": window_days,
    });
    if let Some(path) = manifest {
        report["manifest"] = serde_json::json!(path);
    }
    print_report(&report);
}

/// `nau key promote`: move the successor into place and trust it.
fn key_promote(home: PathBuf) -> miette::Result<()> {
    let kp = crate::sign::promote_rotation_key(&home, &crate::sign::keys_dir(&home))?;
    crate::output::ok(format!(
        "rotation promoted: key id {} is now the signing key",
        kp.key_id()
    ));
    print_report(&serde_json::json!({
        "key_id": kp.key_id(),
        "secret_key": crate::sign::secret_key_path(&home).display().to_string(),
        "trusted": true,
    }));
    Ok(())
}

/// `nau key revoke`: drop the local anchor, record the revocation in
/// `keys/revoked-keys`, and date it in the ceremony ledger.
fn key_revoke(home: PathBuf, key_id: &str) -> miette::Result<()> {
    crate::sign::revoke_local(&crate::sign::keys_dir(&home), key_id)?;
    let keys_dir = crate::sign::keys_dir(&home);
    let mut ledger = crate::sign::CeremonyLedger::load(&keys_dir)?;
    let revoked_at = crate::sign::now_rfc3339();
    ledger.record_revocation(key_id, &revoked_at);
    ledger.save(&keys_dir)?;
    crate::output::ok(format!("key {key_id} revoked (recorded {revoked_at})"));
    print_report(&serde_json::json!({
        "key_id": key_id,
        "revoked": true,
        "revoked_at": revoked_at,
    }));
    Ok(())
}

/// `nau key list`: print the ceremony ledger — the auditable trail of
/// every key the ceremony touched (issue #51).
fn key_list(home: PathBuf) -> miette::Result<()> {
    let ledger = crate::sign::CeremonyLedger::load(&crate::sign::keys_dir(&home))?;
    if ledger.keys.is_empty() {
        crate::output::info(format!(
            "no ceremony ledger yet at {} (run `nau key keygen`)",
            crate::sign::ceremony_ledger_path(&crate::sign::keys_dir(&home)).display()
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
                    .unwrap_or(crate::sign::DEFAULT_WINDOW_DAYS)
            ));
        }
        if let Some(at) = &entry.revoked_at {
            line.push_str(&format!("  REVOKED {at}"));
        }
        if !crate::output::is_json() {
            println!("{line}");
        }
    }
    print_report(&ledger);
    Ok(())
}

/// `nau key verify`: verify a manifest JSON under the ceremony policy
/// (issue #51) — either key during a rotation window, a warning once an
/// expired window's key is the only signer, a named error for
/// revoked-only signatures. Provenance binding (issue #56) is enforced
/// for the entry that verified.
fn key_verify(home: PathBuf, manifest: &str) -> miette::Result<()> {
    let parsed = read_manifest(manifest)?;
    let outcome = verify_manifest_with_ceremony(&home, &parsed)?;
    for warning in &outcome.warnings {
        crate::output::warn(warning);
    }
    crate::output::ok(format!("manifest verified under key id {}", outcome.key_id));
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
fn read_manifest(path: &str) -> miette::Result<crate::manifest::ImageManifest> {
    let text = std::fs::read_to_string(path).map_err(|e| miette::miette!("reading {path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| miette::miette!("parsing manifest {path}: {e}"))
}

/// The ceremony-policy verify half of `nau key verify`: canonical
/// bytes, operator keychain + ledger + `revoked-keys`, then the ledger
/// verify with provenance binding enforced on the winning entry.
fn verify_manifest_with_ceremony(
    home: &Path,
    parsed: &crate::manifest::ImageManifest,
) -> miette::Result<crate::sign::LedgerVerification> {
    let keys_dir = crate::sign::keys_dir(home);
    let body = crate::sign::eval_manifest_canonical_bytes(parsed)?;
    let chain = crate::sign::Keychain::load_dir(&keys_dir)?;
    let ledger = crate::sign::CeremonyLedger::load(&keys_dir)?;
    let revoked = crate::sign::read_revoked_keys(&keys_dir)?;
    let outcome =
        crate::sign::verify_with_ledger_now(&body, &parsed.signatures, &chain, &ledger, &revoked)?;
    if let Some(entry) = parsed.signatures.get(&outcome.key_id) {
        crate::sign::check_provenance(entry, &parsed.inputs)?;
    }
    Ok(outcome)
}

// ── CA command (ADR-0045 amendment, #283 — the host CA ceremony) ──

/// `nau ca` dispatch: keygen mints the host CA, list introspects it.
pub fn cmd_ca(sub: CaCommand) -> miette::Result<()> {
    match sub {
        CaCommand::Keygen { home, force, json } => {
            crate::output::set_mode(json);
            ca_keygen(key_home(home), force)
        }
        CaCommand::List { home, json } => {
            crate::output::set_mode(json);
            ca_list(key_home(home))
        }
    }
}

/// `nau ca keygen`: mint the host CA keypair under the ceremony home
/// and print its public line + ssh-keygen SHA256 fingerprint — the two
/// values every downstream consumer (the `@cert-authority` pin, the
/// workers-entry fingerprint) derives from.
fn ca_keygen(home: PathBuf, force: bool) -> miette::Result<()> {
    let runner = crate::command::RealRunner;
    let info = crate::ca::create_ca_keypair(&runner, &home, force)?;
    crate::output::ok(format!(
        "host CA created: {} (fingerprint {})",
        crate::ca::ca_secret_path(&home).display(),
        info.fingerprint
    ));
    crate::output::info(format!(
        "public half: {} — one @cert-authority line per operator (ADR-0045)",
        crate::ca::ca_public_path(&home).display()
    ));
    print_report(&serde_json::json!({
        "public_line": info.public_line,
        "fingerprint": info.fingerprint,
        "secret": crate::ca::ca_secret_path(&home).display().to_string(),
        "public": crate::ca::ca_public_path(&home).display().to_string(),
    }));
    Ok(())
}

/// `nau ca list`: introspect the host CA. Absent is an informational
/// hint (exit 0 — the ceremony has simply not run); a secret without its
/// public half is a named refusal from [`crate::ca::inspect`].
fn ca_list(home: PathBuf) -> miette::Result<()> {
    let runner = crate::command::RealRunner;
    match crate::ca::inspect(&runner, &home)? {
        None => {
            crate::output::info(format!(
                "no host CA at {} (run `nau ca keygen`)",
                crate::ca::ca_dir(&home).display()
            ));
            print_report(&serde_json::json!({ "present": false }));
        }
        Some(info) => {
            crate::output::ok(format!("host CA: {}", info.fingerprint));
            crate::output::info(format!("public line: {}", info.public_line));
            if !info.secret_present {
                crate::output::warn(
                    "private half missing — introspection works, certificate issuance will not",
                );
            }
            print_report(&serde_json::json!({
                "present": true,
                "secret_present": info.secret_present,
                "public_line": info.public_line,
                "fingerprint": info.fingerprint,
            }));
        }
    }
    Ok(())
}

// ── Runtime command (ADR-0012 step 5, Phase 24b) ──

pub fn cmd_runtime(sub: RuntimeCommand) -> miette::Result<()> {
    match sub {
        RuntimeCommand::Install {
            name,
            channel,
            state_dir,
            json,
        } => {
            crate::output::set_mode(json);
            runtime_install(&name, &channel, state_dir)
        }
        RuntimeCommand::Remove {
            name,
            state_dir,
            json,
        } => {
            crate::output::set_mode(json);
            runtime_remove(&name, state_dir)
        }
        RuntimeCommand::Upgrade {
            name,
            all,
            channel,
            state_dir,
            json,
        } => {
            crate::output::set_mode(json);
            runtime_upgrade(name, all, &channel, state_dir)
        }
        RuntimeCommand::Rollback {
            generation,
            state_dir,
            json,
        } => {
            crate::output::set_mode(json);
            runtime_rollback(generation, state_dir)
        }
        RuntimeCommand::Gc {
            prune,
            state_dir,
            json,
        } => {
            crate::output::set_mode(json);
            runtime_gc(prune, state_dir)
        }
        RuntimeCommand::Activate { state_dir, json } => {
            crate::output::set_mode(json);
            runtime_activate(state_dir)
        }
        RuntimeCommand::RecoverSlots { esp_mount } => runtime_recover_slots(&esp_mount),
    }
}

// ── Pods (issues #2 + #4) ──

/// `nau pod shellenv` (issue #47): print the selected pod's
/// environment as shell statements — `export PATH="<farm>:$PATH"`, the
/// #311 ambient loader-lib strip (never a loader-lib export; the seam
/// lives in the emit-time wrappers, ADR-0034), and the declared env /
/// secret exports — or as structured JSON with `--json`. The caller
/// `eval`s the output; this process only prints, never touching an RC
/// file.
fn cmd_pod_shellenv(pod_name: &str, json: bool, root: Option<String>) -> miette::Result<()> {
    crate::output::set_mode(json);
    let root = crate::pod::pod_root(root.as_deref());
    let env = crate::pod::shellenv(&root, pod_name)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&env).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        print!("{}", crate::pod::render_shellenv(&env));
    }
    Ok(())
}

/// `nau pod secrets` (ADR-0042, issue #183): references, health,
/// and the session-cache lifecycle. Values never reach any output here
/// (D8) — the reference table, the health report, and refresh counts
/// are the entire surface.
fn cmd_pod_secrets(
    pod_name: &str,
    command: crate::cli::PodSecretsCommand,
    root: Option<String>,
) -> miette::Result<()> {
    let root = crate::pod::pod_root(root.as_deref());
    match command {
        crate::cli::PodSecretsCommand::List => {
            let rows = crate::secrets::list_pod(&root, pod_name, None)?;
            if rows.is_empty() {
                crate::output::info(format!("pod '{pod_name}' has no secret references"));
            } else {
                print!("{}", crate::secrets::render_list_rows(pod_name, &rows));
            }
            Ok(())
        }
        crate::cli::PodSecretsCommand::Check => {
            let rows = crate::secrets::check_pod(&root, pod_name)?;
            print!("{}", crate::secrets::render_check_rows(pod_name, &rows));
            if !crate::secrets::check_healthy(&rows) {
                let bad = rows.iter().filter(|r| r.status != "ok").count();
                miette::bail!("{bad} secret reference(s) unhealthy for pod '{pod_name}'");
            }
            Ok(())
        }
        crate::cli::PodSecretsCommand::Refresh => {
            let tools = crate::runtime::RuntimeTools::for_pod_runtime();
            let report = crate::secrets::refresh_pod(&root, pod_name, None, &tools)?;
            if report.resolved == 0 {
                crate::output::info(format!("pod '{pod_name}' has no secret references"));
                return Ok(());
            }
            print_refresh_counts(&report);
            crate::output::ok(format!(
                "resolved {} secret(s) from [{}] — values cached for this session",
                report.resolved,
                report
                    .sources
                    .iter()
                    .map(|(k, n)| format!("{k}={n}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            print_refresh_restarts(&report);
            Ok(())
        }
    }
}

/// The refresh report's cache counts: the dropped-entry line, only
/// when something was actually dropped (a quiet no-op stays quiet).
fn print_refresh_counts(report: &crate::secrets::SecretsRefreshReport) {
    if report.purged == 0 {
        return;
    }
    let noun = if report.purged == 1 {
        "entry"
    } else {
        "entries"
    };
    crate::output::info(format!("dropped {} cached {noun}", report.purged));
}

/// The refresh report's rotate-restart half (ADR-0042 D3, issue #224):
/// name every unit that moved and every named skip.
fn print_refresh_restarts(report: &crate::secrets::SecretsRefreshReport) {
    if !report.restarted.is_empty() {
        crate::output::ok(format!("restarted {}", report.restarted.join(", ")));
    }
    if !report.skipped.is_empty() {
        crate::output::info(format!(
            "restart skipped for {} — systemctl unavailable",
            report.skipped.join(", ")
        ));
    }
}

/// Render `nau pod list` output: one spec + resolved version per
/// line (float-marked per ADR-0017), or an empty-pod notice.
fn print_pod_packages(pod_name: &str, entries: &[crate::pod::PodListEntry]) {
    if entries.is_empty() {
        crate::output::info(format!("pod '{pod_name}' has no packages"));
        return;
    }
    let width = entries.iter().map(|e| e.spec.len()).max().unwrap_or(0);
    for entry in entries {
        let version = entry.version.as_deref().unwrap_or("(unresolved)");
        // Float marking (ADR-0017): floating packages say so.
        let tag = if entry.floating { " (float)" } else { "" };
        crate::output::status(format!(
            "{:<width$}  {}{}",
            entry.spec,
            version,
            tag,
            width = width
        ));
    }
}

/// Resolve the effective pod name from the two `--name` positions
/// (issue #4): before-verb (`nau pod --name X <verb>`) and
/// after-verb (`nau pod <verb> --name X`). Both given and equal →
/// fine; both given and different → hard error naming both values; one
/// given → it wins. No silent precedence.
fn merge_pod_name<'a>(parent: Option<&'a str>, verb: Option<&'a str>) -> miette::Result<&'a str> {
    match (parent, verb) {
        (Some(parent), Some(verb)) if parent != verb => Err(miette::miette!(
            "conflicting --name values: '{parent}' (before the verb) \
             and '{verb}' (after the verb) select different pods"
        )),
        (Some(parent), _) => Ok(parent),
        (None, Some(verb)) => Ok(verb),
        (None, None) => Ok(crate::pod::DEFAULT_POD),
    }
}

/// `nau pod add`: a collection package by name, or — with `--snap`
/// — a sideloaded `.snap` payload (issue #116).
fn cmd_pod_add(
    pod_name: &str,
    package: Option<String>,
    snap: Option<String>,
    ack_unsigned: bool,
    root: Option<String>,
) -> miette::Result<()> {
    let root = crate::pod::pod_root(root.as_deref());
    if let Some(snap) = snap {
        let report = crate::pod::add_snap_pod(&root, pod_name, Path::new(&snap), ack_unsigned)?;
        if report.noop {
            crate::output::ok(format!(
                "'{}' is already sideloaded into pod '{pod_name}' at this content \
                 ({:.12}…) — nothing to do",
                report.name, report.sha3_384
            ));
        } else if let Some(old) = &report.replaced {
            // A replacement under a pinned name (issue #164 follow-up
            // output): name the pin move so a same-version content
            // swap is distinguishable from a first install.
            let mut line = format!(
                "replaced '{}' ({}): sha3-384 {old:.12}… → {:.12}…",
                report.name, report.version, report.sha3_384
            );
            if let Some(n) = report.generation {
                line.push_str(&format!(", generation {n}"));
            }
            crate::output::ok(line);
        } else {
            let mut line = format!(
                "sideloaded '{}' ({}) into pod '{pod_name}'",
                report.name, report.version
            );
            if let Some(n) = report.generation {
                line.push_str(&format!(" (generation {n})"));
            }
            crate::output::ok(line);
        }
        return Ok(());
    }
    // clap enforces: required unless --snap.
    let package = package.expect("clap: package required unless --snap");
    let report = crate::pod::add_package(&root, pod_name, &package)?;
    crate::output::ok(format!(
        "added '{}' ({}) to pod '{}'",
        report.name, report.version, report.pod
    ));
    Ok(())
}

/// `nau pod declare --file <pod.lua>` (gate-pod gap 5): make a
/// checked-in file the pod's declaration and reconcile. The summary is
/// the declaration delta vs the previous state — one line, not a
/// report.
fn cmd_pod_declare(pod_name: &str, file: &str, root: Option<String>) -> miette::Result<()> {
    let root = crate::pod::pod_root(root.as_deref());
    let report = crate::pod::declare_pod(&root, pod_name, Path::new(file))?;
    let mut line = format!("declared pod '{}' from {file}", report.pod);
    let mut changes = Vec::new();
    if !report.added.is_empty() {
        changes.push(format!("added: {}", report.added.join(", ")));
    }
    if !report.removed.is_empty() {
        changes.push(format!("removed: {}", report.removed.join(", ")));
    }
    if changes.is_empty() {
        line.push_str(" — no package changes");
    } else {
        line.push_str(&format!(" ({})", changes.join("; ")));
    }
    crate::output::ok(line);
    for name in &report.sync.held {
        crate::output::warn(format!("held '{name}' at its pin"));
    }
    if let Some(n) = report.sync.generation {
        crate::output::info(format!("generation {n} current"));
    }
    Ok(())
}

/// `nau pod refresh <member…>` (issue #142): rebuild the named
/// members from their current recipes and report per-member outcomes —
/// installed (generation named) or byte-identical (store content kept).
/// Unrelated drifted members are baselined, not rebuilt, and the
/// summary names them.
fn cmd_pod_refresh(root: &Path, pod_name: &str, members: &[String]) -> miette::Result<()> {
    let report = crate::pod::refresh_pod(root, pod_name, members)?;
    for member in &report.members {
        if member.installed {
            let generation = report
                .sync
                .generation
                .map(|n| n.to_string())
                .unwrap_or_else(|| "unknown".into());
            crate::output::ok(format!(
                "refreshed '{}' ({}) — installed on generation {generation}",
                member.name, member.version
            ));
        } else {
            crate::output::ok(format!(
                "refreshed '{}' ({}) — rebuild byte-identical, store content kept",
                member.name, member.version
            ));
        }
    }
    for name in &report.sync.baselined {
        crate::output::warn(format!(
            "baselined '{name}' — drift pre-dating this refresh: recipe hash \
             recorded, installed content kept (`nau pod refresh {name}` \
             rebuilds it)"
        ));
    }
    if let Some(n) = report.sync.generation {
        crate::output::info(format!("generation {n} current"));
    }
    Ok(())
}

pub fn cmd_pod(name: Option<&str>, sub: PodCommand) -> miette::Result<()> {
    // Owned so `pod_name` doesn't borrow `sub` across the match's move.
    let verb_name = sub.pod_name().map(str::to_owned);
    let pod_name = merge_pod_name(name, verb_name.as_deref())?;
    match sub {
        PodCommand::Add {
            package,
            snap,
            ack_unsigned,
            root,
            ..
        } => cmd_pod_add(pod_name, package, snap, ack_unsigned, root),
        PodCommand::Declare { file, root, .. } => cmd_pod_declare(pod_name, &file, root),
        PodCommand::Remove { package, root, .. } => {
            let root = crate::pod::pod_root(root.as_deref());
            let report = crate::pod::remove_package(&root, pod_name, &package)?;
            crate::output::ok(format!(
                "removed '{}' from pod '{}'",
                report.name, report.pod
            ));
            Ok(())
        }
        PodCommand::Sync {
            rebuild_unstamped,
            root,
            ..
        } => {
            let root = crate::pod::pod_root(root.as_deref());
            let report = crate::pod::sync_pod_with(&root, pod_name, rebuild_unstamped)?;
            print_pod_sync_report(&report);
            Ok(())
        }
        PodCommand::Refresh { members, root, .. } => {
            let root = crate::pod::pod_root(root.as_deref());
            cmd_pod_refresh(&root, pod_name, &members)
        }
        PodCommand::List { root, .. } => {
            let root = crate::pod::pod_root(root.as_deref());
            let entries = crate::pod::list_packages(&root, pod_name)?;
            print_pod_packages(pod_name, &entries);
            Ok(())
        }
        PodCommand::Shellenv { json, root, .. } => cmd_pod_shellenv(pod_name, json, root),
        PodCommand::Update { packages, root, .. } => {
            let root = crate::pod::pod_root(root.as_deref());
            let report = crate::pod::update_pod(&root, pod_name, &packages)?;
            print_pod_update_report(&report);
            Ok(())
        }
        PodCommand::Rebuild {
            package,
            latest,
            root,
            ..
        } => cmd_pod_rebuild(pod_name, &package, latest, root),
        PodCommand::Rollback {
            generation, root, ..
        } => cmd_pod_rollback(pod_name, generation, root),
        PodCommand::Gc { prune, root, .. } => cmd_pod_gc(pod_name, prune, root),
        PodCommand::Secrets { command, root, .. } => cmd_pod_secrets(pod_name, command, root),
    }
}

/// `nau pod rebuild <pkg>` (issue #15): rebuild one declared
/// package at its pins, reusing the cached dependency closure (or
/// deliberately moving it with `--latest`).
fn cmd_pod_rebuild(
    pod_name: &str,
    package: &str,
    latest: bool,
    root: Option<String>,
) -> miette::Result<()> {
    let root = crate::pod::pod_root(root.as_deref());
    let report = crate::pod::rebuild_package(&root, pod_name, package, latest)?;
    if report.held {
        // A blob-pinned (sideloaded) package cannot rebuild — the
        // payload is its content. Report the hold the way sync does,
        // never as "rebuilt" (issue #116).
        crate::output::warn(format!("held '{}' at its pin", report.name));
        if let Some(n) = report.generation {
            crate::output::info(format!("generation {n} current"));
        }
    } else {
        let mut line = format!(
            "rebuilt '{}' ({}) in pod '{}'",
            report.name, report.version, report.pod
        );
        if let Some(n) = report.generation {
            line.push_str(&format!(" (generation {n})"));
        }
        crate::output::ok(line);
    }
    print_report(&report);
    Ok(())
}

/// `nau run`: run a declared confined app from a pod (ADR-0016,
/// ticket #11) or, with `--`, an arbitrary command with the pod's env
/// overlaid (issue #102). For a declared app this resolves the pod's
/// active generation to find the package providing `app`, reads its
/// declared grants, and execs the app inside the selected backend's
/// sandbox; confined apps fail closed when the backend is unavailable —
/// never silently unconfined. `--pod` selects the pod (default
/// `default`); `--root` overrides the pod state root.
pub fn cmd_run(
    pod: Option<&str>,
    root: Option<&str>,
    app: Option<&str>,
    app_args: &[String],
) -> miette::Result<()> {
    let Some(app) = app else {
        return Err(miette::miette!(
            "nau run: nothing to run — name a declared app \
             (`nau run <app>`) or a command (`nau run -- <cmd...>`)"
        ));
    };
    let pod_name = pod.unwrap_or(crate::pod::DEFAULT_POD);
    crate::pod::validate_pod_name(pod_name).map_err(|e| miette::miette!("nau run: {e}"))?;
    let root = crate::pod::pod_root(root);
    let dir = crate::pod::pod_dir(&root, pod_name);
    // Confinement is a runtime concern: the pod must have been reconciled
    // (a pod with no store/generation fails with a clear error).
    if !dir.join("generations").is_dir() {
        return Err(miette::miette!(
            "pod '{pod_name}' has not been reconciled yet — run `nau pod --name {pod_name} \
             sync` (or `add`) before `nau run`"
        ));
    }
    crate::confine::run(&dir, pod_name, app, app_args)
}

// ── Test command (QEMU boot-and-assert, issue #50) ──

/// The resolved host environment for a boot test — everything
/// [`crate::boot_test::BootTest`] needs that is not a flag. Kept separate
/// from the run so the scratch firmware dir lives across the QEMU call.
struct TestHost {
    qemu: PathBuf,
    timeout_bin: PathBuf,
    kvm_available: bool,
    firmware: crate::boot_test::Firmware,
    _scratch: tempfile::TempDir,
}

/// Validate `--runs`/`--expect-counter-seq` together and parse the expected
/// sequence. A single boot cannot observe a decrement, so a sequence spec
/// with `--runs 1` is rejected rather than silently ignored.
fn validate_sequence_args(
    runs: u32,
    expect_counter_seq: Option<&str>,
) -> miette::Result<Vec<crate::boot_test::ExpectedCounters>> {
    if runs == 0 {
        return Err(miette::miette!("--runs must be at least 1"));
    }
    let expect_counters = match expect_counter_seq {
        Some(spec) => crate::boot_test::parse_expect_counters(spec)?,
        None => Vec::new(),
    };
    if !expect_counters.is_empty() && runs == 1 {
        return Err(miette::miette!(
            "--expect-counter-seq needs at least 2 boots to observe a decrement; pass --runs N"
        ));
    }
    Ok(expect_counters)
}

/// `nau test`: boot a built image in QEMU and assert it reached
/// userspace. The host-side wrapper around
/// [`crate::boot_test::run_sequence`] — it resolves the
/// QEMU/firmware/timeout environment, runs the boot(s) through the real
/// [`RealRunner`][crate::command::RealRunner], prints each verdict, and
/// exits non-zero when any boot or sequence assertion fails (so this can gate
/// CI and, later, #63's revert test).
#[allow(clippy::too_many_arguments)]
pub fn cmd_test(
    image: String,
    timeout: u64,
    accel: crate::boot_test::Accel,
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
            "image not found: {image} — build it first with `nau image` and pass the \
             resulting *.img"
        ));
    }
    let expect_counters = validate_sequence_args(runs, expect_counter_seq.as_deref())?;
    let log_path = log
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::boot_test::default_log_path(&image_path));
    let host = resolve_test_host(firmware_dir.as_deref())?;

    let test = crate::boot_test::BootTest {
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
            crate::output::status(format!(
                "booting {image} {runs} times (accel {})...",
                accel.qemu_arg()
            ));
        } else {
            crate::output::status(format!("booting {image} (accel {})...", accel.qemu_arg()));
        }
    }
    let outcome = crate::boot_test::run_sequence(&crate::command::RealRunner, &test)?;
    report_sequence_result(&image, &log_path, &outcome, json);

    if !outcome.passed() {
        std::process::exit(1);
    }
    Ok(())
}

/// Resolve qemu, `timeout`, KVM availability, and the UEFI firmware (with a
/// writable VARS copy staged in the returned scratch dir).
fn resolve_test_host(firmware_dir: Option<&str>) -> miette::Result<TestHost> {
    let qemu = crate::boot_test::resolve_qemu()?;
    let timeout_bin = crate::boot_test::resolve_timeout()?;
    let scratch = tempfile::tempdir()
        .map_err(|e| miette::miette!("failed to create scratch dir for firmware: {e}"))?;
    let firmware =
        crate::boot_test::prepare_firmware(&qemu, firmware_dir.map(Path::new), scratch.path())?;
    Ok(TestHost {
        qemu,
        timeout_bin,
        kvm_available: crate::boot_test::kvm_available(),
        firmware,
        _scratch: scratch,
    })
}

/// Print the boot verdict (human or JSON) plus the evidence path.
fn report_sequence_result(
    image: &str,
    log: &Path,
    outcome: &crate::boot_test::SequenceOutcome,
    json: bool,
) {
    if json {
        report_sequence_json(image, outcome);
        return;
    }
    if outcome.records.is_empty() {
        crate::output::err(outcome.message());
    } else {
        for record in &outcome.records {
            let label = format!("boot {}", record.index);
            let counters = record
                .counters
                .map(|c| {
                    let name = record.uki.as_deref().unwrap_or("");
                    let base = crate::esp::parse_uki_name(name).base;
                    format!(" (ESP {base} +{}-{})", c.tries_left, c.tries_done)
                })
                .unwrap_or_default();
            if record.outcome.passed() {
                crate::output::ok(format!("{label}: {}{counters}", record.outcome.message()));
            } else {
                crate::output::err(format!("{label}: {}{counters}", record.outcome.message()));
            }
        }
        if let Some(failure) = &outcome.failure {
            crate::output::err(format!("sequence: {}", failure.message()));
        }
    }
    if let Some(root) = &outcome.run_root {
        crate::output::status(format!("sequence evidence: {}", root.display()));
    } else {
        crate::output::status(format!("serial evidence: {}", log.display()));
        if !log.is_file() {
            crate::output::warn(format!("no serial log was written at {}", log.display()));
        }
    }
}

/// `--json` boot report: the sequence summary (one entry per boot) plus the
/// overall verdict, run root, and image.
fn report_sequence_json(image: &str, outcome: &crate::boot_test::SequenceOutcome) {
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

/// Report the update outcome for `nau pod update`: a no-op says so,
/// updates name the version moves, held packages explain their
/// constraint, and the current generation closes the story.
fn print_pod_update_report(report: &crate::pod::PodUpdateReport) {
    if report.updated.is_empty() && report.held.is_empty() && report.skipped.is_empty() {
        crate::output::ok(format!(
            "pod '{}' is already at its newest matching versions — no new generation",
            report.pod
        ));
    }
    for name in &report.skipped {
        crate::output::warn(format!(
            "skipped '{name}' (sideloaded — blob pins never float; re-add with a \
             new --snap to move it)"
        ));
    }
    for entry in &report.updated {
        let from = entry.from.as_deref().unwrap_or("(unpinned)");
        crate::output::ok(format!("updated '{}' {} -> {}", entry.name, from, entry.to));
    }
    for held in &report.held {
        let pinned = held.pinned.as_deref().unwrap_or("(unpinned)");
        crate::output::warn(format!(
            "held '{}' at {} (constraint @{:?}: newest available {} does not match)",
            held.name, pinned, held.constraint, held.candidate
        ));
    }
    if let Some(n) = report.generation {
        crate::output::info(format!("generation {n} current"));
    }
    print_report(report);
}

/// `nau pod rollback`: report the flip (from → to) and the farm now
/// behind the pod's `current` link.
fn cmd_pod_rollback(
    pod_name: &str,
    generation: Option<u64>,
    root: Option<String>,
) -> miette::Result<()> {
    let root = crate::pod::pod_root(root.as_deref());
    let report = crate::pod::rollback_pod(&root, pod_name, generation)?;
    crate::output::ok(format!(
        "pod '{}' rolled back generation {} -> {}",
        report.pod, report.from, report.to
    ));
    if let Some(farm) = &report.farm {
        crate::output::info(format!("farm: {}", farm.display()));
    }
    if !report.blob_pins_without_content.is_empty() {
        // Issue #135: the flipped generation predates a blob pin — every
        // mutating verb fails named until the pin is repaired.
        crate::output::warn(format!(
            "generation {} does not carry blob pin(s) ({}) — mutating verbs fail \
             until each is re-added (`nau pod --name {} add --snap`) or removed",
            report.to,
            report.blob_pins_without_content.join(", "),
            report.pod
        ));
    }
    if let Some(services) = &report.services {
        print_pod_services(services);
    }
    print_report(&report);
    Ok(())
}

/// `nau pod gc`: report pruned generations and swept blobs.
fn cmd_pod_gc(pod_name: &str, prune: bool, root: Option<String>) -> miette::Result<()> {
    let root = crate::pod::pod_root(root.as_deref());
    let report = crate::pod::gc_pod(&root, pod_name, prune)?;
    if !report.generations_removed.is_empty() {
        crate::output::ok(format!(
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
        crate::output::ok("pod store clean — nothing to sweep");
    } else {
        crate::output::ok(format!(
            "swept {} blob(s), {} bytes reclaimed",
            report.blobs_removed, report.bytes_reclaimed
        ));
    }
    print_report(&report);
    Ok(())
}

/// Report the reconcile outcome for `nau pod sync`: a no-op says
/// so (no new generation), changes name what moved, and the current
/// generation + farm path close the story.
fn print_pod_sync_report(report: &crate::pod::PodSyncReport) {
    if report.noop {
        crate::output::ok(format!(
            "pod '{}' already matches its declaration — no new generation",
            report.pod
        ));
    } else {
        for name in &report.installed {
            crate::output::ok(format!("installed {name}"));
        }
        for name in &report.removed {
            crate::output::ok(format!("removed {name}"));
        }
    }
    for name in &report.held {
        crate::output::warn(format!("held '{name}' at its pin"));
    }
    if let Some(n) = report.generation {
        crate::output::info(format!("generation {n} current"));
    }
    if let Some(farm) = &report.farm {
        crate::output::info(format!("farm: {}", farm.display()));
    }
    if let Some(services) = &report.services {
        print_pod_services(services);
    }
    print_report(report);
}

/// The compact services section of a pod report (ADR-0032 Decision 8):
/// printed only when the reconcile did anything — a no-op stays as
/// quiet about services as the sync report is about packages.
fn print_pod_services(report: &crate::services::ServiceReconcileReport) {
    if report.is_trivial() {
        return;
    }
    if report.reloaded {
        crate::output::info("systemd user manager reloaded");
    }
    if !report.activated.is_empty() {
        crate::output::ok(format!(
            "services activated: {}",
            report.activated.join(", ")
        ));
    }
    if !report.restarted.is_empty() {
        crate::output::ok(format!(
            "services restarted: {}",
            report.restarted.join(", ")
        ));
    }
    if !report.deactivated.is_empty() {
        crate::output::ok(format!(
            "services deactivated: {}",
            report.deactivated.join(", ")
        ));
    }
    for skip in &report.skipped {
        crate::output::warn(format!("service skip: {skip}"));
    }
}

// ── OCI registry push/pull (Phase 25) ──

/// Assemble registry credentials from the CLI flags: anonymous by
/// default; `--username` requires `--password-stdin` (fail-closed) and
/// the password is read as one line from stdin.
fn registry_auth(username: Option<&str>, password_stdin: bool) -> miette::Result<crate::oci::Auth> {
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
            Ok(crate::oci::Auth {
                username: Some(user.to_string()),
                password: Some(password),
            })
        }
        (Some(_), false) => {
            miette::bail!("--password-stdin is required with --username (no interactive prompt)")
        }
        (None, true) => miette::bail!("--username is required with --password-stdin"),
        (None, false) => Ok(crate::oci::Auth::default()),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn cmd_push(
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
    let reference = crate::oci::Reference::parse(reference)?;
    let explicit: Vec<PathBuf> = snap.iter().chain(image).map(PathBuf::from).collect();
    for p in &explicit {
        if !p.exists() {
            miette::bail!("artifact {} does not exist", p.display());
        }
    }
    let plan = crate::oci::plan_push(Path::new(dir), &explicit, tag, &reference)?;
    crate::output::info(format!(
        "bundle {} v{} ({}) → tag '{}'",
        plan.meta.name, plan.meta.version, plan.meta.arch, plan.tag
    ));
    let report = crate::oci::push(&reference, &plan, auth, insecure_http, mount_from)?;
    if let Some(rec) = record {
        crate::oci::write_built_record(Path::new(rec), &plan)?;
        crate::output::ok(format!("built-manifest record written to {rec}"));
    }
    print_report(&report);
    Ok(())
}

/// `nau pull` dispatch across the reference lanes (ADR-0033): the
/// OCI lane keeps the original body unchanged — same parse, same flags —
/// while `nau://` peer references and `http(s)://` static-tree
/// references hand off to the pull lane.
#[allow(clippy::too_many_arguments)]
pub fn run_pull(
    reference: &str,
    out_dir: String,
    username: Option<&str>,
    password_stdin: bool,
    insecure_http: bool,
    expect: Option<&str>,
    install: bool,
    state_dir: Option<String>,
    pod: Option<&str>,
    allow_downgrade: bool,
) -> miette::Result<()> {
    match crate::pull_ref::PullRef::parse(reference)? {
        crate::pull_ref::PullRef::Oci(_) => cmd_pull(
            reference,
            out_dir,
            username,
            password_stdin,
            insecure_http,
            expect,
            install,
            state_dir,
        ),
        peer_or_url => cmd_pull_peer(&peer_or_url, pod, allow_downgrade),
    }
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
    let reference = crate::oci::Reference::parse(reference)?;
    let expected = match expect {
        Some(p) => Some(crate::oci::read_built_record(Path::new(p))?),
        None => None,
    };
    let mut report = crate::oci::pull(
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

/// `nau serve`: evaluate `node {}` from nau.lua for the
/// binding + announce policy (ADR-0033 Decisions 3+5+6), then hand the
/// overrides to the serve lane. `--announce` forces announcing over the
/// declaration; the declaration is the source of truth — absent both,
/// serve does not announce. Absent `--address`, the declared
/// `serve.address` (or the loopback default) binds.
pub fn cmd_serve(
    address: Option<&str>,
    port: Option<u16>,
    announce_flag: bool,
    pod: Option<&str>,
) -> miette::Result<()> {
    let node = load_node_decl()?;
    let announce = announce_flag || node.as_ref().is_some_and(|n| n.serve.announce);
    let node_name = node.as_ref().map(|n| n.name.as_str());
    let address = address
        .map(str::to_string)
        .or_else(|| node.as_ref().map(|n| n.serve_address().to_string()));
    crate::serve::run(address.as_deref(), port, announce, node_name, pod)
}

/// The `node {}` declaration from `./nau.lua`, if the file exists
/// (ADR-0033 Decision 6 — same eval path as every other verb). A
/// missing file yields `None`: zero behavior change. A file that fails
/// to evaluate fails the verb — a config nau cannot evaluate must
/// not be silently ignored by a serving verb.
fn load_node_decl() -> miette::Result<Option<crate::lua::NodeConfig>> {
    if !Path::new("nau.lua").exists() {
        return Ok(None);
    }
    let evaluated = crate::lua::evaluate_file_with_inputs("nau.lua")?;
    Ok(evaluated.node)
}

/// `nau peers`: browse the LAN for announcing nodes (ADR-0033
/// Decision 3) and print name + host:port. Discovery only, never trust:
/// every manifest stays fail-closed on pull (ADR-0033 Decision 7).
pub fn cmd_peers(secs: u64) -> miette::Result<()> {
    crate::output::status(format!("browsing the LAN for _nau._tcp peers ({secs}s)…"));
    let mut peers = crate::discovery::browse(Duration::from_secs(secs))?;
    peers.sort_by(|a, b| a.name.cmp(&b.name));
    if peers.is_empty() {
        crate::output::warn("no nau peers found — is `nau serve` running there with announce on?");
    } else {
        for peer in &peers {
            // Instance names arrive off the LAN unauthenticated: strip
            // control characters (terminal escapes) before the name
            // reaches the operator's terminal.
            let name = crate::output::strip_control_chars(&peer.name);
            crate::output::status(format!("{:<24} {}:{}", name, peer.host, peer.port));
        }
        crate::output::ok(format!("{} peer(s) found", peers.len()));
    }
    print_report(&serde_json::json!({ "command": "peers", "peers": peers }));
    Ok(())
}

/// `nau export`: hand the destination and pod to the export lane
/// (ADR-0033 Decision 10 — a static tree any web server can serve).
/// With `--mission`, the export is CURATED (#275): only the packages
/// the named `image()` declaration pins are exported — the curation
/// list is read from the mission's existing declaration, never a new
/// schema.
pub fn cmd_export(
    out: &str,
    pod: Option<&str>,
    mission: Option<&str>,
    file: Option<&str>,
) -> miette::Result<()> {
    match mission {
        None => crate::export::run(out, pod)?,
        Some(name) => {
            // The same eval path `nau image` builds from: missions
            // ARE image declarations (this is the mission schema).
            crate::pkg_source::init_global_inputs(&HashMap::new())?;
            let file = file.unwrap_or("nau.lua");
            let file = resolve_file(file)?;
            let images = crate::lua::evaluate_images_file(&file)?;
            let decl = images.get(name).ok_or_else(|| {
                miette::miette!(
                    "mission '{name}' not found in {file} — curate from an \
                     image() declaration (nau image --output-name {name})"
                )
            })?;
            let curation = crate::export::mission_curation(decl);
            crate::export::run_mission(out, pod, &curation)?;
        }
    }
    crate::output::ok(format!("exported static tree to {out}"));
    Ok(())
}

/// Peer/static pull: the verified manifest + blobs stage into the named
/// pod's store; installation stays the pod workflow (ADR-0033
/// Decision 5).
fn cmd_pull_peer(
    pull_ref: &crate::pull_ref::PullRef,
    pod: Option<&str>,
    allow_downgrade: bool,
) -> miette::Result<()> {
    crate::pull_peer::run(pull_ref, pod, allow_downgrade)
}

/// `pull --install`: resolve revisions for the pulled `.snap` payloads
/// from the local lockfile pins and install them as one generation.
/// The revision-resolution rule lives in
/// [`crate::oci::pending_from_blob`]; unpinned or divergent blobs are
/// refused there (fail-closed).
fn install_pulled(
    report: &crate::oci::PullReportJson,
    state_dir: Option<&str>,
) -> miette::Result<crate::runtime::InstallReport> {
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
            pending.push(crate::oci::pending_from_blob(
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
    let arch = crate::snap::host_arch();
    let pin = SnapRef {
        name: name.to_string(),
        revision: None,
        sha3_384: None,
    };
    let resolved = crate::store::StoreClient::resolve(&pin, channel, arch)?;
    let payload =
        crate::store::StoreClient::download(&crate::command::RealRunner, &resolved, downloads)?;
    crate::store::StoreClient::verify(&payload, &resolved.sha3_384)?;
    crate::output::ok(format!(
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
    if crate::output::is_json() {
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
    crate::output::ok(format!(
        "removed {name} — generation {} active",
        report.generation
    ));
    for note in &report.notes {
        crate::output::info(note);
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
        crate::output::ok("everything already at its channel head — no-op, no new generation");
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

fn active_or_err(store: &RuntimeStore) -> miette::Result<crate::runtime::Generation> {
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
    active: &crate::runtime::Generation,
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
    let arch = crate::snap::host_arch();
    let mut resolved = Vec::new();
    for target in targets {
        let pin = SnapRef {
            name: target.clone(),
            revision: None,
            sha3_384: None,
        };
        let r = crate::store::StoreClient::resolve(&pin, channel, arch)?;
        resolved.push((target.clone(), r.revision, r.sha3_384));
    }
    Ok(resolved)
}

fn print_install_summary(report: &crate::runtime::InstallReport) {
    for note in &report.notes {
        crate::output::info(note);
    }
    if report.noop {
        crate::output::ok("already installed at this revision — no-op");
    } else {
        for installed in &report.installed {
            crate::output::ok(format!(
                "installed {} {} (revision {}) into generation {}",
                installed.name,
                installed.version,
                installed.revision,
                report.generation.unwrap_or(0)
            ));
        }
    }
}

fn print_install_report(report: &crate::runtime::InstallReport) {
    print_install_summary(report);
    print_report(report);
}

fn runtime_rollback(generation: Option<u64>, state_dir: Option<String>) -> miette::Result<()> {
    let store = RuntimeStore::from_state_dir(state_dir.as_deref());
    let report = store.rollback(generation, &RuntimeTools::for_pod_runtime())?;
    crate::output::ok(format!(
        "rolled back generation {} -> {}",
        report.from, report.to
    ));
    if !report.started.is_empty() {
        crate::output::info(format!("started: {}", report.started.join(", ")));
    }
    if !report.stopped.is_empty() {
        crate::output::info(format!("stopped: {}", report.stopped.join(", ")));
    }
    for note in &report.notes {
        crate::output::info(note);
    }
    print_report(&report);
    Ok(())
}

fn runtime_gc(prune: bool, state_dir: Option<String>) -> miette::Result<()> {
    let store = RuntimeStore::from_state_dir(state_dir.as_deref());
    let report = store.gc(prune)?;
    if !report.generations_removed.is_empty() {
        crate::output::ok(format!(
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
        crate::output::ok("store clean — nothing to sweep");
    } else {
        crate::output::ok(format!(
            "swept {} blob(s), {} bytes reclaimed",
            report.blobs_removed, report.bytes_reclaimed
        ));
    }
    print_report(&report);
    Ok(())
}

/// `nau runtime activate` (ADR-0023 §4, #60): activate the current
/// generation. Boot-safe and idempotent — a cold store is a no-op and a
/// half-written journal is discarded, so the emitted
/// `nau-runtime-activate.service` oneshot never wedges boot.
fn runtime_activate(state_dir: Option<String>) -> miette::Result<()> {
    let store = RuntimeStore::from_state_dir(state_dir.as_deref());
    let report = store.activate_current(&RuntimeTools::for_pod_runtime())?;
    if report.noop {
        crate::output::ok("no active generation — nothing to activate");
    } else {
        crate::output::ok(format!(
            "activated generation {}",
            report.generation.unwrap_or(0)
        ));
    }
    for note in &report.notes {
        crate::output::info(note);
    }
    print_report(&report);
    Ok(())
}

/// `nau runtime recover-slots` (issue #86): assess and reclaim
/// sysupdate slots stranded mid-install. Runs in-guest at boot (the
/// emitted `nau-slot-recovery.service` oneshot); see
/// [`crate::slot_recovery`] for the invariant and the conservative
/// recovery policy.
fn runtime_recover_slots(esp_mount: &str) -> miette::Result<()> {
    let runner = crate::command::RealRunner;
    let tools = crate::slot_recovery::SlotRecoveryTools::resolve();
    crate::slot_recovery::recover_slots(Path::new(esp_mount), &runner, &tools)
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

pub fn cmd_search(query: &str, json: bool) {
    // Ensure global inputs are initialized for iter_packages
    let _ = crate::pkg_source::init_global_inputs(&HashMap::new());

    let candidates = crate::pkg_source::iter_packages();
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

pub fn cmd_completion(shell: clap_complete::Shell) -> miette::Result<()> {
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
    Ok(())
}

// ── Index command ──

pub fn cmd_index(sub: IndexCommand) -> miette::Result<()> {
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

/// `nau index update`: refresh package inputs from the config file, or
/// the default input when the file is absent/unreadable/empty.
fn index_update(file: &str) {
    let inputs = if Path::new(file).exists() {
        match crate::lua::evaluate_file_with_inputs(file) {
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
            url: "github:rbelem/nau/main".into(),
            submodules: None,
        };
        eprintln!("  Updating default package index...");
        if let Err(e) = crate::pkg_source::refresh_input(&default) {
            eprintln!("  ✗ failed: {e}");
        } else {
            eprintln!("  ✓ default package index updated");
        }
    } else {
        for (name, input) in &inputs {
            eprintln!("  Updating input '{name}'...");
            match crate::pkg_source::refresh_input(input) {
                Ok(_) => eprintln!("  ✓ '{name}' updated"),
                Err(e) => eprintln!("  ✗ '{name}' failed: {e}"),
            }
        }
    }
}

/// `nau index list`: print every index entry with its kind and pin
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

/// `nau index add`: upsert a store-backed entry and save the index.
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
    crate::output::ok(format!("added '{}' to index", name));
    Ok(())
}

/// `nau index resolve`: query the Snap Store for every entry's pins and
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
    crate::output::ok(format!("index updated: {}", index));
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
