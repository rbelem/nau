//! Farm dispatch (#313): the burst's wrapped-build sizing — the pending
//! farmed jobs of a would-be `nau build` plus its jobs-per-worker. Lives
//! in the library so `crate::provision` calls it directly; the binary no
//! longer hands a function pointer across the lib boundary (#313).

use std::collections::BTreeMap;
use std::path::Path;

use crate::cli::{normalize_domain, BuildArgs, Command};
use crate::lock::LockFile;

use crate::build_orch::{
    collect_dep_graph, dep_pending, init_pkg_cache, load_lockfile_or_default,
    resolve_build_outputs, resolve_file, select_outputs,
};

/// `workers burst --count auto`'s sizing source (#304): the wrapped
/// build's pending farmed jobs — its resolved outputs' dep set minus the
/// fully-cached names — plus the jobs-per-worker the sizing divides by.
/// Same resolution path as cmd_build by construction: the wrapped argv
/// parses through the real Cli definition and the config resolves in
/// [`resolve_build_outputs`]. Both the legacy spelling (`nau build …`,
/// bare `build …`) and the ADR-0049 domain spelling (`nau build snap …`,
/// bare `build snap …`) are accepted — the fold in
/// [`normalize_domain`] flattens `build snap` onto the same variant, so
/// identical effective flags size identically under either spelling.
/// Quiet: sizing prints only its own decision line, not the build's
/// progress.
pub(crate) fn wrapped_build_pending_jobs(command: &[String]) -> miette::Result<(usize, u32)> {
    // normalize_domain folds the `build snap` subcommand's args onto the
    // flat Build variant; `build cache …` folds to a non-build and is
    // refused below with the other non-builds.
    let Command::Build {
        args:
            BuildArgs {
                file,
                output_name,
                arch,
                all,
                cache,
                cache_max_size,
                target,
                update,
                offline,
                lockfile: lockfile_path,
                ..
            },
        command: None,
    } = normalize_domain(crate::cli::wrapped_build(command)?)
    else {
        // Neither wrapped_build nor the fold produces a flat Build for a
        // non-build (nor for `build cache …`); fail-closed anyway.
        return Err(miette::miette!(
            "workers burst: --count auto sizes a wrapped 'nau build' — '{}' is not one, \
             and there is no pending set to size from",
            command.join(" ")
        ));
    };

    // main()'s positional fallback, applied before cmd_build sees the
    // args: a package name in place of a missing nau.lua resolves through
    // the input sources, and an embedded:// resolution never carries an
    // output filter.
    let file = if file == "nau.lua" && !Path::new("nau.lua").exists() {
        match &output_name {
            Some(name) => resolve_file(name)?,
            None => file,
        }
    } else {
        resolve_file(&file)?
    };
    let output_name = if file.starts_with("embedded://") {
        None
    } else {
        output_name
    };

    let (all_outputs, workers, file) =
        resolve_build_outputs(&file, update.as_deref(), offline, &lockfile_path)?;
    let lockfile = load_lockfile_or_default(Path::new(&lockfile_path))?;
    let pkg_cache = init_pkg_cache(all, cache, cache_max_size, true);
    let pending = pending_dep_jobs(
        &all_outputs,
        &output_name,
        &file,
        target.as_ref(),
        &arch,
        pkg_cache.as_ref(),
        &lockfile,
    )?;
    // The burst's own pins carry no explicit `jobs`, so the fleet takes
    // the lua.rs default 2 — unless the wrapped config's entries say
    // otherwise (one homogeneous fleet is the real shape).
    let jobs_per_worker = workers.workers.first().map(|w| w.jobs).unwrap_or(2);
    Ok((pending.len(), jobs_per_worker))
}

/// The farmed pending set of a build (#304): the selected outputs' dep
/// graph, metas loaded, closure keys precomputed, fully-cached names
/// subtracted — exactly what `build_all_deps` schedules onto the workers.
/// Output-free: the `select_outputs` target line and the "(cached)" lines
/// are suppressed for the burst's silent sizing.
pub(crate) fn pending_dep_jobs(
    all_outputs: &crate::lua::Outputs,
    output_name: &Option<String>,
    file: &str,
    target: Option<&String>,
    cli_archs: &[String],
    pkg_cache: Option<&crate::cache::PackageCache>,
    lockfile: &LockFile,
) -> miette::Result<BTreeMap<String, crate::snap::SnapMeta>> {
    let iter = select_outputs(all_outputs, output_name, file, target, true)?;
    let dep_nodes = collect_dep_graph(&iter);
    let (metas, _closures, pre_done) =
        dep_pending(&dep_nodes, target, pkg_cache, cli_archs, lockfile, true);
    Ok(metas
        .into_iter()
        .filter(|(name, _)| !pre_done.contains(name))
        .collect())
}
