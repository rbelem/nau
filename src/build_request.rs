//! The build-request lane (ADR-0052 Decisions 4+6): the device-side
//! submit client (`nau build-request submit`) and the farm-side drain
//! (`nau build-request run`), over [`nau_peer::queue`]'s file-backed
//! request directory.
//!
//! Division of trust (ADR-0052 Security): a request carries recipe
//! IDENTITY only (`package` + `version` + who asked). The drain
//! resolves the recipe file under the farm's own recipes root,
//! re-evaluates it farm-side with the requested version as the
//! `constraint` global (the ADR-0047/0052 plumbing the eval worker
//! already carries), and never executes client-supplied build text.
//! Both the build and the release steps ride injectable seams (the
//! `pull_peer::Fetch` pattern): production defaults to the pool's
//! build scheduler and `nau_ship::release::release`; tests inject
//! fakes.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use miette::{IntoDiagnostic, WrapErr};

use nau_core::servers::ServerFront;
use nau_peer::queue::BuildQueue;

// The queue vocabulary is the lane's shared wire shape; re-exported so
// the CLI/commands layer (and tests) consume one set of names.
pub use nau_peer::queue::{is_pkg_name, is_version_triple, BuildRequest, QueuedRequest, Receipt};

// ── Identity validation (client-side mirror of the server gate) ──

/// Validate a build-request identity BEFORE it goes on the wire (the
/// `pull_ref` convention: the client strictly requests well-formed
/// names, so a malformed submit fails locally with the same message the
/// server would answer 400 with).
pub fn validate_identity(package: &str, version: &str) -> miette::Result<()> {
    if !is_pkg_name(package) {
        miette::bail!(
            "package '{package}' must match [a-z0-9-] (the ADR-0032 collision-classifier charset)"
        );
    }
    if !is_version_triple(version) {
        miette::bail!("version '{version}' must be a plain numeric triple (X.Y.Z)");
    }
    Ok(())
}

/// Normalize a token for the wire: trimmed, non-empty, no control
/// characters (a token rides an HTTP header — CR/LF would smuggle a
/// second header line).
pub fn sanitize_token(raw: &str) -> miette::Result<String> {
    let token = raw.trim();
    if token.is_empty() {
        miette::bail!("bearer token is empty — pass --token-file or pipe one on stdin");
    }
    if token.chars().any(|c| c.is_control()) {
        miette::bail!("bearer token must not contain control characters");
    }
    Ok(token.to_string())
}

// ── Server resolution (ADR-0052 Decision 6) ──

/// Resolve the server fronts a submit targets: the pod's override list
/// when it declared one, else the system config's list, tried in
/// declaration order. Empty everywhere is a named error — the package
/// that was asked for plus the provisioning hint (the ADR's
/// "error with a provisioning hint").
///
/// A pure fold over the two config sources so the ORDER contract is
/// unit-testable without any eval.
pub fn resolve_server_fronts<'a>(
    pod_override: Option<&'a [String]>,
    system: &'a [ServerFront],
    package: &str,
) -> miette::Result<Cow<'a, [String]>> {
    if let Some(pod_list) = pod_override.filter(|l| !l.is_empty()) {
        return Ok(Cow::Borrowed(pod_list));
    }
    if !system.is_empty() {
        return Ok(Cow::Owned(system.iter().map(|f| f.url.clone()).collect()));
    }
    miette::bail!(
        "no server configured to build '{package}' — add \
         `servers = {{ \"https://<your-farm>/nau\" }}` to nau.lua (or a `servers` \
         list to the pod's pod.lua to override), and provision the \
         build-request endpoint on that server"
    )
}

/// The system config's `servers` list: the `file`'s global, through the
/// same eval path every verb uses. A missing file is an empty list
/// (zero behavior change); a file that fails to evaluate fails the verb
/// (the `load_node_decl` posture — config nau cannot evaluate must not
/// be silently ignored).
pub fn load_system_servers(file: &str) -> miette::Result<Vec<ServerFront>> {
    if !Path::new(file).exists() {
        return Ok(Vec::new());
    }
    let evaluated = nau_chart::lua::evaluate_file_with_inputs(file)?;
    Ok(evaluated.servers)
}

/// The pod's `servers` override: the named pod's declaration
/// (`None` when the pod has no `pod.lua` yet). The env-reading pod
/// root resolves here (root glue), the declaration shape lives in
/// nau-pod.
pub fn load_pod_servers(root: &Path, pod: Option<&str>) -> miette::Result<Option<Vec<String>>> {
    let (pod_name, pod_dir) = nau_core::paths::resolve_pod_dir_under(root, pod)?;
    if !crate::pod::pod_lua_path(&pod_dir, &pod_name).is_file() {
        return Ok(None);
    }
    let decl = crate::pod::load_declaration(root, &pod_name)?;
    Ok(Some(decl.servers))
}

// ── The submit client ──

/// Outcome of one accepted submit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submitted {
    /// The server-assigned request id.
    pub id: String,
    /// The front that accepted it (the report's evidence).
    pub server: String,
}

/// Submit one build request: POST `<front>/build-requests` with the
/// bearer token and the identity JSON, trying the resolved fronts in
/// order. Transport failures and 5xx fall through to the next front; a
/// 4xx is terminal — that server received and refused the request, and
/// re-sending it elsewhere would only duplicate the refusal. Returns
/// the accepting server's request id.
pub fn submit(
    fronts: &[String],
    package: &str,
    version: &str,
    requested_by: &str,
    token: &str,
) -> miette::Result<Submitted> {
    validate_identity(package, version)?;
    let token = sanitize_token(token)?;
    let body = serde_json::to_vec(&BuildRequest {
        package: package.to_string(),
        version: version.to_string(),
        requested_by: requested_by.to_string(),
    })
    .map_err(|e| miette::miette!("serialize build request: {e}"))?;
    let mut failures: Vec<String> = Vec::new();
    for front in fronts {
        let url = format!("{}/build-requests", front.trim_end_matches('/'));
        match post_json(&url, &token, &body) {
            Ok((status, body)) if (200..300).contains(&status) => {
                let parsed: serde_json::Value = serde_json::from_slice(&body)
                    .map_err(|e| miette::miette!("{url} answered {status} with non-JSON: {e}"))?;
                let id = parsed["id"].as_str().map(str::to_string).ok_or_else(|| {
                    miette::miette!("{url} answered {status} without a request id")
                })?;
                return Ok(Submitted {
                    id,
                    server: front.clone(),
                });
            }
            Ok((status, body)) => {
                if (500..600).contains(&status) {
                    // Server-side trouble: the NEXT front is a fair try.
                    failures.push(format!(
                        "{url}: HTTP {status} — {}",
                        String::from_utf8_lossy(&body).trim()
                    ));
                    continue;
                }
                miette::bail!(
                    "{url} refused the request (HTTP {status}): {}",
                    String::from_utf8_lossy(&body).trim()
                );
            }
            Err(e) => {
                failures.push(format!("{url}: {e:#}"));
                continue;
            }
        }
    }
    miette::bail!("every configured server failed:\n{}", failures.join("\n"))
}

/// One JSON POST with a bearer token, curl-backed (the
/// `nau_ship::oci` client convention: body via `--data-binary @file`,
/// response headers dumped with `-D`, body captured with `-o`, so the
/// plain [`nau_infra::command::CommandRunner`] suffices and the status
/// line comes from the header dump — no `-w` parsing games). Returns
/// (status, body); only transport-level failures are `Err` — HTTP
/// statuses come back as data so the caller decides failover.
/// The curl argv for one bearer JSON POST (the `nau_ship::oci` exec
/// shape: bounded timeouts, body file, header dump, body capture).
fn curl_post_argv(
    url: &str,
    token: &str,
    body_file: &Path,
    header_file: &Path,
    out_file: &Path,
) -> Vec<String> {
    use nau_ship::oci::{BLOB_TIMEOUT_SECS, CONNECT_TIMEOUT_SECS};
    vec![
        "curl".to_string(),
        "-sS".to_string(),
        "--connect-timeout".to_string(),
        CONNECT_TIMEOUT_SECS.to_string(),
        "--max-time".to_string(),
        BLOB_TIMEOUT_SECS.to_string(),
        "-X".to_string(),
        "POST".to_string(),
        "-H".to_string(),
        format!("Authorization: Bearer {token}"),
        "-H".to_string(),
        "Content-Type: application/json".to_string(),
        "--data-binary".to_string(),
        format!("@{}", body_file.display()),
        "-D".to_string(),
        header_file.to_string_lossy().into_owned(),
        "-o".to_string(),
        out_file.to_string_lossy().into_owned(),
        url.to_string(),
    ]
}

fn post_json(url: &str, token: &str, body: &[u8]) -> miette::Result<(u16, Vec<u8>)> {
    use nau_infra::command::{exit_code, CommandRunner, RealRunner};
    let scratch = tempfile::tempdir()
        .into_diagnostic()
        .wrap_err("creating the submit scratch dir")?;
    let body_file = scratch.path().join("request.json");
    let header_file = scratch.path().join("headers.txt");
    let out_file = scratch.path().join("response.json");
    std::fs::write(&body_file, body)
        .into_diagnostic()
        .wrap_err("writing the request body file")?;
    let argv = curl_post_argv(url, token, &body_file, &header_file, &out_file);
    let out = RealRunner
        .run(&argv)
        .map_err(|e| miette::miette!("curl not found: {e}"))?;
    if exit_code(&out) != 0 {
        return Err(miette::miette!(
            "POST {url} failed (curl exit {}): {}",
            exit_code(&out),
            out.stderr.trim()
        ));
    }
    parse_curl_response(url, &header_file, &out_file)
}

/// The status line (first header-dump line) plus the captured body.
fn parse_curl_response(
    url: &str,
    header_file: &Path,
    out_file: &Path,
) -> miette::Result<(u16, Vec<u8>)> {
    let headers = std::fs::read_to_string(header_file)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading the {url} response head"))?;
    let status = headers
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| miette::miette!("POST {url}: unreadable HTTP status in response"))?;
    let response = std::fs::read(out_file)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading the {url} response body"))?;
    Ok((status, response))
}

// ── The drain ──

/// Where the drain's release step points (ADR-0052 Decision 5): the
/// update-manifest signing key, the rustfs (S3) target, and the public
/// tree base the receipt's URLs are reported against. Assembled into a
/// [`nau_ship::release::ReleaseInput`] per request.
#[derive(Debug, Clone, Default)]
pub struct ReleaseConfig {
    pub signing_key: Option<PathBuf>,
    pub s3_endpoint: Option<String>,
    pub s3_bucket: Option<String>,
    pub s3_region: Option<String>,
    pub s3_access_key: Option<String>,
    pub s3_secret_key: Option<String>,
    pub tree_base: Option<String>,
}

impl ReleaseConfig {
    /// The S3 target the build step's tree reads ride — the same fields
    /// the release input carries; the signing key and tree base are
    /// release-only.
    fn s3_target(&self) -> miette::Result<nau_ship::release::S3Target> {
        let missing = |what: &str| {
            miette::miette!(
                "release not configured: {what} is required \
                 (--s3-endpoint, --s3-bucket, --s3-region, --s3-access-key, --s3-secret-key)"
            )
        };
        Ok(nau_ship::release::S3Target {
            endpoint: self
                .s3_endpoint
                .clone()
                .ok_or_else(|| missing("s3-endpoint"))?,
            bucket: self.s3_bucket.clone().ok_or_else(|| missing("s3-bucket"))?,
            region: self.s3_region.clone().ok_or_else(|| missing("s3-region"))?,
            access_key: self
                .s3_access_key
                .clone()
                .ok_or_else(|| missing("s3-access-key"))?,
            secret_key: self
                .s3_secret_key
                .clone()
                .ok_or_else(|| missing("s3-secret-key"))?,
        })
    }

    fn build_input(
        &self,
        snap_path: &Path,
        package: &str,
        version: &str,
    ) -> miette::Result<nau_ship::release::ReleaseInput> {
        let missing = |what: &str| {
            miette::miette!(
                "release not configured: {what} is required \
                 (--signing-key, --tree-base, --s3-endpoint, --s3-bucket, --s3-region, \
                 --s3-access-key, --s3-secret-key)"
            )
        };
        Ok(nau_ship::release::ReleaseInput {
            snap_path: snap_path.to_path_buf(),
            package: package.to_string(),
            version: version.to_string(),
            signing_key: self
                .signing_key
                .clone()
                .ok_or_else(|| missing("a signing key"))?,
            s3: nau_ship::release::S3Target {
                endpoint: self
                    .s3_endpoint
                    .clone()
                    .ok_or_else(|| missing("an S3 endpoint"))?,
                bucket: self
                    .s3_bucket
                    .clone()
                    .ok_or_else(|| missing("an S3 bucket"))?,
                region: self
                    .s3_region
                    .clone()
                    .ok_or_else(|| missing("an S3 region"))?,
                access_key: self
                    .s3_access_key
                    .clone()
                    .ok_or_else(|| missing("S3 access keys"))?,
                secret_key: self
                    .s3_secret_key
                    .clone()
                    .ok_or_else(|| missing("S3 access keys"))?,
            },
            tree_base: self
                .tree_base
                .clone()
                .ok_or_else(|| missing("a public tree base"))?,
        })
    }
}

/// The build seam (the `pull_peer::Fetch` pattern): given the claimed
/// request and its farm-side-resolved meta, produce the built `.snap`.
pub trait BuildStep {
    fn build(
        &self,
        request: &BuildRequest,
        meta: &nau_core::snap_types::SnapMeta,
        recipe: &Path,
        output_dir: &Path,
    ) -> miette::Result<PathBuf>;
}

/// The release seam: production is [`nau_ship::release::release`]
/// (currently the #328 lane-B stub, which bails — the receipt records
/// the error); tests inject fakes.
pub trait Releaser {
    fn release(
        &self,
        input: &nau_ship::release::ReleaseInput,
    ) -> miette::Result<nau_ship::release::ReleaseOutput>;
}

/// Production release step: the ship crate's fail-closed chain.
pub struct ShipReleaser;

impl Releaser for ShipReleaser {
    fn release(
        &self,
        input: &nau_ship::release::ReleaseInput,
    ) -> miette::Result<nau_ship::release::ReleaseOutput> {
        nau_ship::release::release(input)
    }
}

/// Production build step: one farm-side build through the pool's
/// ready-set scheduler (`nau_pool::build_sched` — PR 9's public build
/// API, budget from the `workers` conventions) with the single-node
/// graph the request names; the job runs the normal snap build path
/// (`crate::snap::build_snap`) over the constraint-resolved meta.
/// Production build step: one farm-side build through the pool's
/// scheduler, the request's bd closure staged against the released tree
/// first (rbelem/nau#338 — `farm_prefix::farm_build_prefix`).
pub struct PoolBuild {
    tree: crate::farm_prefix::S3Tree,
}

impl BuildStep for PoolBuild {
    fn build(
        &self,
        request: &BuildRequest,
        meta: &nau_core::snap_types::SnapMeta,
        _recipe: &Path,
        output_dir: &Path,
    ) -> miette::Result<PathBuf> {
        // The build phase needs its own scratch (the dep-build shape):
        // a private tempdir, default stage policy.
        let stage = tempfile::tempdir()
            .into_diagnostic()
            .wrap_err("creating the build stage dir")?;
        let arch = std::env::var("NAU_ARCH").unwrap_or_else(|_| "amd64".into());

        // The bd closure stages BEFORE the scheduler: the merged prefix
        // owns its tempdir and must outlive the build it feeds. Payloads
        // come from the released tree first, local builds only for tree
        // misses (#338).
        let cache = output_dir.join(".dep-cache");
        let mut building = Vec::new();
        let prefix =
            crate::farm_prefix::farm_build_prefix(&self.tree, &cache, meta, &arch, &mut building)?;
        // Empty listings when the build materializes no prefix — the scan
        // contract every wired build path runs (issue #35).
        let scan_listings = match &prefix {
            Some(p) => crate::leak_scan::listings_for_build(meta, p)?,
            None => crate::leak_scan::PayloadListings::default(),
        };

        let snap_name: Mutex<Option<String>> = Mutex::new(None);
        let graph = BTreeMap::from([(request.package.clone(), Vec::new())]);
        let budget =
            nau_pool::build_sched::pool_budget(&nau_core::worker_types::WorkersConfig::default());
        let job = |_name: &str| -> Result<(), String> {
            match crate::snap::build_snap(
                meta,
                stage.path(),
                output_dir,
                &arch,
                nau_build::snap::StagePolicy::Default,
                // No pod store on the farm: no ELF repair, no wrappers.
                None,
                // Ecosystem-deps closures stay pod-only (#338 follow-up).
                None,
                prefix.as_ref().map(|p| p.path()),
                Some(&scan_listings),
                false,
                Some(&crate::build_orch::SeamSourceFetcher),
            ) {
                Ok(result) => {
                    *snap_name.lock().unwrap() = Some(result.snap_filename);
                    Ok(())
                }
                Err(e) => Err(format!("{e:#}")),
            }
        };
        nau_pool::build_sched::run_ready_set(&graph, &HashSet::new(), budget, job).map_err(
            |failed| {
                let (name, err) = failed
                    .failed
                    .first()
                    .cloned()
                    .unwrap_or_else(|| ("build".into(), "unknown failure".into()));
                miette::miette!("build of {name} failed: {err}")
            },
        )?;
        let filename =
            snap_name.lock().unwrap().clone().ok_or_else(|| {
                miette::miette!("scheduler reported success but no snap was built")
            })?;
        Ok(output_dir.join(filename))
    }
}

/// Everything one drain run needs. `build`/`release` are the injected
/// seams; production assembles [`Drain::production`].
pub struct Drain {
    pub queue: BuildQueue,
    pub recipes_root: PathBuf,
    pub release_cfg: ReleaseConfig,
    pub build: Box<dyn BuildStep>,
    pub release: Box<dyn Releaser>,
    /// Exit after the first claim (whether it succeeded or failed).
    pub once: bool,
    /// Seconds between polls of an empty queue.
    pub poll_secs: u64,
}

impl Drain {
    /// The production wiring: the pool build path and the ship release
    /// seam. The build step reads the released tree for its dep closures,
    /// so an unusable S3 target fails the drain at construction, never
    /// mid-request (rbelem/nau#338).
    pub fn production(
        queue: BuildQueue,
        recipes_root: PathBuf,
        release_cfg: ReleaseConfig,
        once: bool,
    ) -> miette::Result<Self> {
        let tree =
            crate::farm_prefix::S3Tree::new(nau_ship::s3::S3Client::new(release_cfg.s3_target()?)?);
        Ok(Drain {
            queue,
            recipes_root,
            release_cfg,
            build: Box::new(PoolBuild { tree }),
            release: Box::new(ShipReleaser),
            once,
            poll_secs: 2,
        })
    }
}

/// One settled request, for the run report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settled {
    pub id: String,
    pub package: String,
    pub version: String,
    pub released: bool,
    pub manifest_url: Option<String>,
    pub blob_urls: Vec<String>,
    pub error: Option<String>,
}

/// Run the drain loop: claim → evaluate → build → release → receipt →
/// next. A failure of ANY step is recorded in the receipt and the
/// claimed file moves to `done/` — the loop never dies on one bad
/// request. `--once` exits after the first settlement (or immediately
/// when the queue is empty); the default polls forever.
pub fn run_drain(drain: &Drain) -> miette::Result<Vec<Settled>> {
    let mut settled = Vec::new();
    loop {
        match drain.queue.claim()? {
            None if drain.once => return Ok(settled),
            None => {
                nau_infra::output::status(format!(
                    "queue empty — polling again in {}s (Ctrl-C to stop)",
                    drain.poll_secs
                ));
                std::thread::sleep(std::time::Duration::from_secs(drain.poll_secs));
            }
            Some(claimed) => {
                let entry = settle_one(drain, &claimed);
                match &entry.error {
                    None => nau_infra::output::ok(format!(
                        "released {} {} (request {})",
                        entry.package, entry.version, entry.id
                    )),
                    Some(error) => nau_infra::output::warn(format!(
                        "request {} ({} {}) failed: {error}",
                        claimed.id, entry.package, entry.version
                    )),
                }
                settled.push(entry);
                if drain.once {
                    return Ok(settled);
                }
            }
        }
    }
}

/// Settle one claimed request: run the pipeline, write the receipt
/// (release urls or the error chain), move the claim to `done/`.
fn settle_one(drain: &Drain, claimed: &QueuedRequest) -> Settled {
    let base = || Settled {
        id: claimed.id.clone(),
        package: claimed.request.package.clone(),
        version: claimed.request.version.clone(),
        released: false,
        manifest_url: None,
        blob_urls: Vec::new(),
        error: None,
    };
    match drain_request(drain, claimed) {
        Ok((manifest_url, blob_urls)) => {
            match drain
                .queue
                .complete(&claimed.id, &claimed.request, &manifest_url, &blob_urls)
            {
                Ok(()) => Settled {
                    released: true,
                    manifest_url: Some(manifest_url),
                    blob_urls,
                    ..base()
                },
                Err(e) => failed(base(), format!("receipt write failed: {e:#}")),
            }
        }
        Err(e) => {
            let error = format!("{e:#}");
            // The failure receipt is the drain's audit trail; failing to
            // write it cannot resurrect the request either — the file
            // stays in claimed/ where an operator can see it.
            if let Err(receipt_err) = drain.queue.fail(&claimed.id, &claimed.request, &error) {
                nau_infra::output::warn(format!(
                    "could not write the failure receipt for request {}: {receipt_err:#}",
                    claimed.id
                ));
            }
            failed(base(), error)
        }
    }
}

fn failed(mut settled: Settled, error: String) -> Settled {
    settled.released = false;
    settled.error = Some(error);
    settled
}

/// Resolve the recipe file for a package under the recipes root: the
/// collection layout `pkgs/<first-letter>/<name>.lua` (the
/// `pkg_source::resolve_pkg` grammar, rooted at the drain's recipes
/// root — single-file first, then the `<name>/init.lua` directory form).
pub fn resolve_recipe(recipes_root: &Path, package: &str) -> miette::Result<PathBuf> {
    if !is_pkg_name(package) {
        miette::bail!(
            "package '{package}' must match [a-z0-9-] (the ADR-0032 collision-classifier charset)"
        );
    }
    let first = package
        .chars()
        .next()
        .expect("is_pkg_name refuses empty")
        .to_ascii_lowercase();
    let base = recipes_root.join(first.to_string());
    let single = base.join(format!("{package}.lua"));
    if single.is_file() {
        return Ok(single);
    }
    let dir_form = base.join(package).join("init.lua");
    if dir_form.is_file() {
        return Ok(dir_form);
    }
    miette::bail!(
        "recipe '{package}' not found under {} (expected {} or {})",
        recipes_root.display(),
        single.display(),
        dir_form.display()
    )
}

/// The claim → release pipeline for one request: farm-side eval under
/// the requested-version constraint → build (the seam) → release (the
/// seam). Error-typed so the receipt records the chain.
type ReleaseUrls = (String, Vec<String>);

fn drain_request(drain: &Drain, claimed: &QueuedRequest) -> miette::Result<ReleaseUrls> {
    let request = &claimed.request;
    // 1. The farm's own recipe — the request names identity, never
    // build text (ADR-0052 Security).
    let recipe = resolve_recipe(&drain.recipes_root, &request.package)?;
    // 2. Farm-side eval with the requested version as the constraint
    // (ADR-0052 Decision 3 — a version-lined recipe refuses an unknown
    // constraint itself; a recipe that ignores the global fails the
    // identity check below).
    let outputs = nau_chart::lua::evaluate_file_with_constraint(
        &recipe.display().to_string(),
        Some(&request.version),
    )?;
    let meta = match outputs.get(&request.package) {
        Some(meta) => meta,
        None if outputs.len() == 1 => outputs.values().next().expect("len 1 checked above"),
        None => {
            let mut names: Vec<&String> = outputs.keys().collect();
            names.sort();
            let names = names
                .iter()
                .map(|n| n.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            miette::bail!(
                "recipe {} declares no output named '{}' (outputs: {names})",
                recipe.display(),
                request.package,
            );
        }
    };
    // 3. Identity check: what the recipe resolved must BE what was
    // requested — the gate that keeps a constraint-ignoring recipe from
    // releasing its floating default instead.
    if meta.name != request.package {
        miette::bail!(
            "recipe {} resolved '{}', not the requested '{}'",
            recipe.display(),
            meta.name,
            request.package
        );
    }
    if meta.version != request.version {
        miette::bail!(
            "recipe {} resolved version '{}', not the requested '{}' — the recipe must \
             honor the constraint global",
            recipe.display(),
            meta.version,
            request.version
        );
    }
    // 4. Build via the pool (the seam), 5. release via ship (the seam).
    let output_dir = std::env::current_dir()
        .into_diagnostic()
        .wrap_err("resolving the drain's output directory")?;
    let snap_path = drain.build.build(request, meta, &recipe, &output_dir)?;
    let input = drain
        .release_cfg
        .build_input(&snap_path, &request.package, &request.version)?;
    let out = drain.release.release(&input)?;
    Ok((out.manifest_url, out.blob_urls))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Identity grammar (the client-side mirror) ──

    #[test]
    fn identity_validation_mirrors_the_server_gate() {
        assert!(validate_identity("hello-world", "1.2.3").is_ok());
        let err = validate_identity("Hello_World", "1.2.3").unwrap_err();
        assert!(err.to_string().contains("[a-z0-9-]"), "{err}");
        let err = validate_identity("hello", "1.2").unwrap_err();
        assert!(err.to_string().contains("triple"), "{err}");
    }

    #[test]
    fn token_sanitization_refuses_the_wire_hostile_shapes() {
        assert_eq!(sanitize_token("  tok \n").unwrap(), "tok");
        assert!(sanitize_token("").is_err());
        assert!(sanitize_token("  \n").is_err());
        let err = sanitize_token("to\nken").unwrap_err();
        assert!(err.to_string().contains("control"), "{err}");
    }

    // ── Server resolution order (ADR-0052 Decision 6) ──

    fn front(url: &str) -> ServerFront {
        ServerFront {
            url: url.to_string(),
        }
    }

    #[test]
    fn pod_override_wins_over_the_system_list_wholesale() {
        let pod = vec!["https://pod.example/nau".to_string()];
        let system = vec![front("https://system.example/nau")];
        let resolved = resolve_server_fronts(Some(&pod), &system, "git").unwrap();
        assert_eq!(
            resolved.as_ref(),
            &["https://pod.example/nau".to_string()],
            "the pod override REPLACES the system list"
        );
    }

    #[test]
    fn an_empty_pod_override_falls_through_to_the_system_list_in_order() {
        let pod: Vec<String> = Vec::new();
        let system = vec![
            front("https://first.example/nau"),
            front("http://second.example:7780"),
        ];
        let resolved = resolve_server_fronts(Some(&pod), &system, "git").unwrap();
        assert_eq!(
            resolved.as_ref(),
            &[
                "https://first.example/nau".to_string(),
                "http://second.example:7780".to_string()
            ],
            "declaration order IS the try order"
        );
    }

    #[test]
    fn no_config_anywhere_names_the_package_and_the_remedy() {
        let err = resolve_server_fronts(None, &[], "opencode-bin").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("opencode-bin"), "names the package: {msg}");
        assert!(msg.contains("servers"), "hints at the config key: {msg}");
    }

    // ── Recipe resolution (the pkgs/<letter>/<name>.lua layout) ──

    #[test]
    fn recipe_resolution_follows_the_collection_layout() {
        let root = tempfile::tempdir().unwrap();
        let single = root.path().join("t").join("testpkg.lua");
        std::fs::create_dir_all(single.parent().unwrap()).unwrap();
        std::fs::write(&single, "-- recipe").unwrap();
        assert_eq!(
            resolve_recipe(root.path(), "testpkg").unwrap(),
            single,
            "single-file form resolves first"
        );

        let dir_form_root = tempfile::tempdir().unwrap();
        let init = dir_form_root
            .path()
            .join("d")
            .join("dirpkg")
            .join("init.lua");
        std::fs::create_dir_all(init.parent().unwrap()).unwrap();
        std::fs::write(&init, "-- recipe").unwrap();
        assert_eq!(
            resolve_recipe(dir_form_root.path(), "dirpkg").unwrap(),
            init,
            "the <name>/init.lua form resolves too"
        );
    }

    #[test]
    fn missing_recipes_are_named_by_path() {
        let root = tempfile::tempdir().unwrap();
        let err = resolve_recipe(root.path(), "ghost").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ghost"), "{msg}");
        assert!(
            msg.contains(
                &root
                    .path()
                    .join("g")
                    .join("ghost.lua")
                    .display()
                    .to_string()
            ),
            "names the expected path: {msg}"
        );
        let err = resolve_recipe(root.path(), "../escape").unwrap_err();
        assert!(err.to_string().contains("[a-z0-9-]"), "{err}");
    }

    // ── Drain plumbing over the seams (no eval here — the eval-backed
    // happy path lives in tests/build_request.rs) ──

    fn release_cfg() -> ReleaseConfig {
        ReleaseConfig {
            signing_key: Some(PathBuf::from("/keys/update.pub")),
            s3_endpoint: Some("https://s3.internal.example".into()),
            s3_bucket: Some("nau-tree".into()),
            s3_region: Some("us-east-1".into()),
            s3_access_key: Some("ak".into()),
            s3_secret_key: Some("sk".into()),
            tree_base: Some("https://tree.example/nau".into()),
        }
    }

    #[test]
    fn release_config_assembles_the_release_input_and_names_gaps() {
        let cfg = release_cfg();
        let input = cfg
            .build_input(Path::new("/out/x_1.2.3_amd64.snap"), "x", "1.2.3")
            .unwrap();
        assert_eq!(input.package, "x");
        assert_eq!(input.version, "1.2.3");
        assert_eq!(input.s3.bucket, "nau-tree");

        let err = ReleaseConfig::default()
            .build_input(Path::new("/out/x.snap"), "x", "1.2.3")
            .unwrap_err();
        assert!(err.to_string().contains("release not configured"), "{err}");
    }

    // The eval-backed drain tests live in tests/build_request.rs: they
    // run the REAL bounded-subprocess eval worker, which re-executes
    // CARGO_BIN_EXE_nau — a binary only the integration suite has.
}
