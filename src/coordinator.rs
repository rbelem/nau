//! The farm coordinator's assembly (ADR-0040 Decisions 3–8, #193 review
//! F2): what one node's remote job needs, resolved up front on the
//! orchestrator thread, plus the coordinator-side
//! [`ManifestSource`] that feeds every worker's dispatches — recipe
//! slice, pinned sources, dep-payload closure, staging, ingest, and the
//! JSON event. Lives in the lib so the assembly layer is testable
//! against temp dirs and a fake command runner (the binary's `run_farm`
//! wires it to the real runner and the parsed `workers` table).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use crate::build_sched::ManifestSource;
use crate::command::{exit_code, CommandRunner};
use crate::lock::LockFile;
use crate::snap::{SnapMeta, SourceSpec};
use crate::ssh_exec::{PreflightChecks, SshExecutor, PREFLIGHT_MIN_FREE_DISK_BYTES};

/// Everything one node's remote job needs, resolved up front on the
/// orchestrator thread: the recipe bytes, the transitive dep payload
/// specs (name + version, resolved against the job's single arch at
/// dispatch time), and the declared sources. An `Err` plans the node
/// as local-only: the scheduler routes it to the coordinator's slots
/// and the reason never surfaces unless someone force-dispatches it.
pub struct NodeJobPlan {
    /// The manifest's recipe key: `pkgs/<letter>/<name>.lua`, the
    /// CWD-relative shape the worker's own `load_meta` resolves.
    pub recipe_key: String,
    pub recipe: String,
    /// The job's single build arch (multi-arch nodes stay local).
    pub arch: String,
    /// The `--target` triplet, when the job cross-compiles.
    pub cross_target: Option<String>,
    pub package: String,
    /// Transitive `requires` ∪ `build_deps` members, by name. Versions
    /// resolve through `dep_metas` at dispatch time.
    pub deps: Vec<String>,
    pub sources: Vec<SourceSpec>,
}

/// The coordinator-side assembly feeding every worker's dispatches
/// (the [`ManifestSource`] implementation). `manifest_for` is pure —
/// every eval ran up front in [`precompute_farm_plans`] — so dispatch
/// threads never touch the isolate worker; only payload staging
/// downloads (curl, the repo's one network convention) and hash
/// verification run there. `R` is the command seam: production passes
/// [`RealRunner`](crate::command::RealRunner), hermetic tests inject a
/// fake curl.
pub struct FarmSource<'a, R: CommandRunner> {
    pub plans: HashMap<String, NodeJobPlan>,
    pub dep_metas: HashMap<String, SnapMeta>,
    pub dep_closures: HashMap<String, crate::cache::BuildClosure>,
    pub lockfile: &'a LockFile,
    pub output_dir: &'a Path,
    pub pkg_cache: Option<&'a crate::cache::PackageCache>,
    pub json: bool,
    pub epoch: Option<i64>,
    pub runner: R,
}

impl<R: CommandRunner> FarmSource<'_, R> {
    /// Resolve one dep's payload: the run's output dir first (built
    /// earlier in this run, local or remote alike), then the binary
    /// cache (a dep that was fully cached before the run started).
    fn dep_payload_path(&self, name: &str, arch: &str) -> miette::Result<PathBuf> {
        let meta = self.dep_metas.get(name).ok_or_else(|| {
            miette::miette!("farm job: dep '{name}' has no preloaded meta — plan gap")
        })?;
        let filename = format!("{name}_{}_{}.snap", meta.version, arch);
        let in_output = self.output_dir.join(&filename);
        if in_output.exists() {
            return Ok(in_output);
        }
        if let (Some(cache), Some(closure)) = (self.pkg_cache, self.dep_closures.get(name)) {
            if let Some(cached) = cache.lookup(meta, arch, closure) {
                return Ok(cached);
            }
        }
        Err(miette::miette!(
            "farm job: dep payload '{filename}' is neither in {} nor in the binary cache — \
             the scheduler builds deps before dependents, so this is a plan gap",
            self.output_dir.display()
        ))
    }

    /// The pin a source must ship under: the lockfile's recorded hash
    /// (the fetch phase's current truth), else the recipe's declared
    /// `sha256`. An unpinned source is a named refusal — the worker
    /// refuses unpinned sources too (`refuse_unshipped_sources`), and
    /// v1 ships pinned sources from the coordinator only (ADR-0040
    /// Decision 6).
    fn source_pin(&self, spec: &SourceSpec) -> miette::Result<(String, String)> {
        let url = spec.url();
        let pin = self
            .lockfile
            .lookup_source(url)
            .or(spec.expected_sha256())
            .ok_or_else(|| {
                miette::miette!(
                    "farm job: source '{url}' is unpinned — pin it (source.sha256 or the \
                     lockfile) before dispatching to a worker; a worker never fetches \
                     upstream (ADR-0040 Decision 6)"
                )
            })?;
        Ok((url.to_string(), pin.to_string()))
    }
}

impl<R: CommandRunner + Sync> ManifestSource for FarmSource<'_, R> {
    fn manifest_for(&self, name: &str) -> miette::Result<crate::worker::JobManifest> {
        let plan = self.plans.get(name).ok_or_else(|| {
            miette::miette!("farm job: node '{name}' has no precomputed plan — plan gap")
        })?;

        // Recipe slice: one entry, the node's own recipe (#172: own
        // recipe bytes included).
        let mut recipes = BTreeMap::new();
        recipes.insert(plan.recipe_key.clone(), plan.recipe.clone());

        // Pin slice: every declared source under its verified hash.
        let mut pins = Vec::new();
        for spec in &plan.sources {
            let (url, sha) = self.source_pin(spec)?;
            pins.push(crate::worker::SourcePin { url, sha256: sha });
        }

        // Closure: dep payloads (hashed from the resolved files) plus
        // the source blobs (hashes are the pins themselves — the blobs
        // materialize only in `stage_payload`, and only when the job
        // actually dispatches).
        let mut closure = Vec::new();
        for dep in &plan.deps {
            let path = self.dep_payload_path(dep, &plan.arch)?;
            let bytes = std::fs::read(&path).map_err(|e| {
                miette::miette!("farm job: cannot read dep payload {}: {e}", path.display())
            })?;
            closure.push(crate::worker::ClosureObject {
                sha256: crate::oci::sha256_hex(&bytes),
                size: bytes.len() as u64,
                purpose: format!("dep:{dep}"),
            });
        }
        for spec in &plan.sources {
            let (_, sha) = self.source_pin(spec)?;
            closure.push(crate::worker::ClosureObject {
                sha256: sha,
                size: 0, // verified at arrival against the pin; the size is not known pre-fetch
                purpose: "source".to_string(),
            });
        }

        Ok(crate::worker::JobManifest {
            protocol_version: crate::worker::WORKER_PROTOCOL_VERSION,
            target: plan.arch.clone(),
            cross_target: plan.cross_target.clone(),
            source_date_epoch: self.epoch,
            package: plan.package.clone(),
            recipes,
            pins,
            closure,
            payload_dir: None,
        })
    }

    fn stage_payload(
        &self,
        manifest: &crate::worker::JobManifest,
    ) -> miette::Result<tempfile::TempDir> {
        let stage = tempfile::tempdir()
            .map_err(|e| miette::miette!("farm job: cannot stage the payload dir: {e}"))?;
        let plan = self.plans.get(&manifest.package).ok_or_else(|| {
            miette::miette!(
                "farm job: node '{}' has no precomputed plan",
                manifest.package
            )
        })?;

        // Dep payloads: hardlinked into the stage under their hash —
        // the hash computed once in `manifest_for` and carried by the
        // manifest's closure (#193 review F5: the dispatch path reads
        // and hashes each payload once, not twice).
        for dep in &plan.deps {
            let path = self.dep_payload_path(dep, &plan.arch)?;
            let sha = manifest
                .closure
                .iter()
                .find(|o| o.purpose == format!("dep:{dep}"))
                .map(|o| o.sha256.clone())
                .ok_or_else(|| {
                    miette::miette!(
                        "farm job: manifest carries no closure object for dep '{dep}' — plan gap"
                    )
                })?;
            std::fs::hard_link(&path, stage.path().join(&sha)).map_err(|e| {
                miette::miette!(
                    "farm job: cannot link dep payload {} into the stage: {e}",
                    path.display()
                )
            })?;
        }

        // Sources: fetched from upstream BY THE COORDINATOR (curl, the
        // repo's one network convention), hash-verified against the pin
        // before anything ships — a mismatch refuses the dispatch.
        for spec in &plan.sources {
            let (url, sha) = self.source_pin(spec)?;
            let dest = stage.path().join(&sha);
            fetch_pinned_source(&self.runner, &url, &sha, &dest)?;
        }
        Ok(stage)
    }

    fn ingest(
        &self,
        name: &str,
        outcome: &crate::ssh_exec::DispatchOutcome,
        artifacts_in: &Path,
        display: &str,
    ) -> miette::Result<()> {
        // Place every returned artifact where the rest of the build
        // finds it: the run's output directory (dependents' build
        // prefixes resolve there first). The bytes are already
        // hash-verified coordinator-side; the copy re-serves them from
        // the ingest record.
        for art in &outcome.result.artifacts {
            let src = artifacts_in.join(&art.filename);
            let dst = self.output_dir.join(&art.filename);
            if src != dst {
                std::fs::copy(&src, &dst).map_err(|e| {
                    miette::miette!(
                        "farm ingest: cannot place artifact {} into {}: {e}",
                        src.display(),
                        self.output_dir.display()
                    )
                })?;
            }
        }

        if self.json {
            if let Some(event) = farm_build_result(name, outcome, display) {
                crate::output::record_build_result(event);
            }
        }
        Ok(())
    }
}

/// The JSON event for one successful farm dispatch: executor `ssh`, the
/// worker attributed, and the version parsed from the artifact filename
/// (`<name>_<version>_<arch>.snap`, matching the local path's
/// post-build identity; the "0" placeholder when the stem does not
/// parse). `None` when the dispatch returned no artifact.
pub fn farm_build_result(
    name: &str,
    outcome: &crate::ssh_exec::DispatchOutcome,
    display: &str,
) -> Option<crate::output::BuildResultJson> {
    let art = outcome.result.artifacts.first()?;
    let stem = art
        .filename
        .strip_prefix(&format!("{name}_"))
        .and_then(|s| s.strip_suffix(&format!("_{}.snap", outcome.result.target)));
    Some(crate::output::BuildResultJson {
        name: name.to_string(),
        version: stem.unwrap_or("0").to_string(),
        arch: outcome.result.target.clone(),
        filename: art.filename.clone(),
        sha256: Some(art.sha256.clone()),
        sources: None,
        executor: "ssh".into(),
        worker: Some(display.to_string()),
    })
}

/// Download one pinned source for the payload stage and verify it
/// against the pin before it can ship. `curl` behind the CommandRunner
/// (the oci.rs network convention), bounded connect + total time.
pub fn fetch_pinned_source<R: CommandRunner>(
    runner: &R,
    url: &str,
    sha256: &str,
    dest: &Path,
) -> miette::Result<()> {
    let out = runner
        .run(&[
            "curl".to_string(),
            "-fsSL".to_string(),
            "--connect-timeout".to_string(),
            "30".to_string(),
            "--max-time".to_string(),
            "1800".to_string(),
            "-A".to_string(),
            concat!(
                "nau/",
                env!("CARGO_PKG_VERSION"),
                " (farm dispatch source ship)"
            )
            .to_string(),
            "-o".to_string(),
            dest.to_string_lossy().into_owned(),
            url.to_string(),
        ])
        .map_err(|e| miette::miette!("farm job: curl cannot be spawned for {url}: {e}"))?;
    if exit_code(&out) != 0 {
        return Err(miette::miette!(
            "farm job: source fetch failed for {url}: {}",
            out.stderr.trim()
        ));
    }
    let bytes = std::fs::read(dest)
        .map_err(|e| miette::miette!("farm job: cannot read the fetched source {url}: {e}"))?;
    let got = crate::oci::sha256_hex(&bytes);
    if got != sha256 {
        return Err(miette::miette!(
            "farm job: source {url} hashes to {got} but the pin says {sha256} — refusing to \
             ship (the lockfile pin is stale; refresh it before dispatching)"
        ));
    }
    Ok(())
}

/// Preflight every declared worker, sequentially, before anything
/// dispatches (ADR-0040 Decision 3): the entry's declared arch rides
/// the check, so a declared-vs-reported mismatch refuses the run here —
/// named by worker and probe — instead of mid-run, per dispatch, after
/// other work has already gone out (#193 review F1). Alongside the arch
/// assertion, the bare probes run: pin, reachability, protocol, bwrap,
/// functioning sandbox, mksquashfs, free disk. The same channel also
/// learns the worker's object-store listing (#303 — placement's warm
/// hint; a failed listing never fails the worker, the store just reads
/// unknown). A refusal is a config
/// error that kills the run before an hours-long build starts; the
/// escape hatch is removing the worker from config.
pub fn preflight_farm_workers<R: CommandRunner>(
    executors: &[SshExecutor<R>],
) -> miette::Result<()> {
    for exec in executors {
        exec.preflight(PreflightChecks {
            arch: exec.declared_arch(),
            min_free_disk: PREFLIGHT_MIN_FREE_DISK_BYTES,
        })?;
    }
    Ok(())
}

/// Everything the farm's assembly phase precomputes, up front, on the
/// orchestrator thread.
pub struct FarmPlans {
    pub plans: HashMap<String, NodeJobPlan>,
    pub dep_metas: HashMap<String, SnapMeta>,
    pub dep_closures: HashMap<String, crate::cache::BuildClosure>,
    pub caps: HashMap<String, crate::build_sched::JobCaps>,
}

/// The placement-known objects of one RESOLVED plan (#303): the pinned
/// sources' hashes, resolved exactly like dispatch's `source_pin`
/// (lockfile first, then the recipe's declared pin); unpinned sources
/// contribute nothing here — dispatch refuses them, named. Dep payload
/// hashes are not knowable at plan time — they hash built snaps — so
/// they stay out; this set only aims placement, delta_sync remains the
/// authority.
pub fn plan_objects(plan: &NodeJobPlan, lockfile: &LockFile) -> BTreeSet<String> {
    plan.sources
        .iter()
        .filter_map(|spec| {
            lockfile
                .lookup_source(spec.url())
                .or(spec.expected_sha256())
                .map(str::to_string)
        })
        .collect()
}

/// Resolve every node's remote-job plan up front, on the orchestrator
/// thread: the recipe slice, the transitive dep payload specs (each
/// dep's meta evaluated once, sequentially — the evals never run on
/// dispatch threads), the declared sources, and the placement caps.
/// A node whose plan cannot resolve (directory-form recipe, multi-arch
/// job) plans as local-only: it builds on the coordinator's slots
/// exactly as it did before the farm existed.
pub fn precompute_farm_plans(
    metas: &BTreeMap<String, SnapMeta>,
    cli_archs: &[String],
    lockfile: &LockFile,
) -> miette::Result<FarmPlans> {
    let mut plans = HashMap::new();
    let mut dep_metas: HashMap<String, SnapMeta> = HashMap::new();
    let mut dep_closures: HashMap<String, crate::cache::BuildClosure> = HashMap::new();
    let mut caps: HashMap<String, crate::build_sched::JobCaps> = HashMap::new();

    for (name, meta) in metas {
        let archs = crate::snap::resolve_archs(meta, cli_archs);
        // A job building several archs mixes per-arch build prefixes
        // into one manifest — a shape the v1 manifest does not carry;
        // it stays local before anything else is even attempted. Same
        // for a metadata-only "all" job (no declared architectures): a
        // real worker always reports a concrete arch and the dispatch
        // preflight refuses "all", so placement must never route it
        // away from the coordinator.
        let multi_arch = archs.len() > 1;
        let all_only = archs.len() == 1 && archs[0] == "all";
        let plan = plan_node_job(
            name,
            meta,
            &archs,
            lockfile,
            &mut dep_metas,
            &mut dep_closures,
        );
        let local_only = multi_arch || all_only || plan.is_err();
        // The placement-known objects (#303) — see [`plan_objects`].
        let objects = plan
            .as_ref()
            .map(|p| plan_objects(p, lockfile))
            .unwrap_or_default();
        if let Ok(p) = plan {
            plans.insert(name.clone(), p);
        }
        caps.insert(
            name.clone(),
            crate::build_sched::JobCaps {
                archs,
                cross: meta.target.is_some(),
                local_only,
                objects,
            },
        );
    }
    Ok(FarmPlans {
        plans,
        dep_metas,
        dep_closures,
        caps,
    })
}

/// Resolve one node's remote-job plan: the recipe slice, the transitive
/// dep payload specs (each dep's meta evaluated exactly once, here, on
/// the orchestrator thread — evals never run on dispatch threads), and
/// the declared sources.
pub fn plan_node_job(
    name: &str,
    meta: &SnapMeta,
    archs: &[String],
    lockfile: &LockFile,
    dep_metas: &mut HashMap<String, SnapMeta>,
    dep_closures: &mut HashMap<String, crate::cache::BuildClosure>,
) -> miette::Result<NodeJobPlan> {
    // The recipe bytes: single-file recipes only. A directory-form
    // recipe (init.lua + sibling files) needs its whole directory in
    // the slice — a v1 limit, named, routing the node local.
    let (key, recipe) = match crate::pkg_source::resolve_pkg(name) {
        crate::pkg_source::PkgResult::File(path) => {
            if path.ends_with("init.lua") {
                miette::bail!(
                    "farm dispatch builds single-file recipes in v1; '{name}' is a \
                     directory recipe ({path}) — it builds on the coordinator's slots"
                );
            }
            let bytes = std::fs::read_to_string(&path)
                .map_err(|e| miette::miette!("farm job: cannot read recipe {path}: {e}"))?;
            (path, bytes)
        }
        crate::pkg_source::PkgResult::Found { content, .. } => {
            let first = name.chars().next().unwrap_or('x').to_ascii_lowercase();
            (format!("pkgs/{first}/{name}.lua"), content)
        }
        crate::pkg_source::PkgResult::NotFound => {
            miette::bail!("farm job: recipe for '{name}' not found")
        }
    };

    // Transitive build-time dep closure (the merged build prefix's
    // members).
    let mut deps = Vec::new();
    for dep in crate::deps::resolve_dep_names(&[name.to_string()], true)? {
        let dep_meta = match crate::deps::load_meta(&dep) {
            Ok(m) => m,
            Err(e) => miette::bail!("farm job: dep '{dep}' of '{name}': {e:#}"),
        };
        if !dep_metas.contains_key(&dep) {
            dep_closures.insert(dep.clone(), build_closure(&dep_meta, lockfile));
            dep_metas.insert(dep.clone(), dep_meta);
        }
        deps.push(dep);
    }

    let mut sources = Vec::new();
    if let Some(spec) = &meta.source {
        sources.push(spec.clone());
    }
    if let Some(named) = &meta.sources {
        sources.extend(named.values().cloned());
    }

    Ok(NodeJobPlan {
        recipe_key: key,
        recipe,
        arch: archs.first().cloned().unwrap_or_else(|| "all".to_string()),
        cross_target: meta.target.clone(),
        package: meta.name.clone(),
        deps,
        sources,
    })
}

/// The binary-cache closure key of one snap: the parts spec + cross-
/// compilation target + resolved requires closure (gap-analysis §4.3).
/// Computed once per snap per build, after requires resolution; every
/// cache lookup/store uses the key derived from it.
///
/// Requires resolution uses lockfile pins when present (no I/O); unpinned
/// deps are resolved from already-initialized local input caches — this
/// never fetches. With `--offline` an unfetchable input fails earlier, in
/// `init_global_inputs_with`, exactly as before this existed.
pub fn build_closure(meta: &SnapMeta, lockfile: &LockFile) -> crate::cache::BuildClosure {
    let seeds = crate::deps::build_dep_seeds(meta);
    let mut names: Vec<String> = if seeds.is_empty() {
        Vec::new()
    } else {
        crate::deps::resolve_dep_names(&seeds, true).unwrap_or_default()
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
    crate::cache::BuildClosure::for_meta(meta, requires, build_deps)
}

/// Resolve one requires-closure member. A lockfile pin (revision +
/// sha3-384) wins — pure data, safe offline. Otherwise the dep's declared
/// version pins it with `hash: None`: an unpinned store dep is only
/// version-pinned, so content changes behind the version cannot invalidate
/// the cache key (known limitation; `nau lock` and image builds record
/// snap pins that close this gap).
pub fn requires_member(name: &str, lockfile: &LockFile) -> crate::cache::RequiresMember {
    if let Some(member) = crate::cache::pinned_member(name, lockfile) {
        return member;
    }
    let pin = crate::deps::load_meta(name).ok().map(|meta| meta.version);
    crate::cache::RequiresMember {
        name: name.to_string(),
        pin,
        hash: None,
    }
}
