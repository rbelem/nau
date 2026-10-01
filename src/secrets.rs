//! Pod secret resolution (ADR-0042, issue #183) — the `pod secrets`
//! VERB layer (list/check/refresh) plus the re-export of the resolve
//! half.
//!
//! Issue #326 PR 6 (crate extraction): the RESOLVE half — the provider
//! registry, the reference walk, the decl-hash cache, the serve/envfile
//! layer, and the `SecretSource` grammar type — moved DOWN into
//! `nau_pod::secrets` (this crate's `pod` module re-exports the type
//! for `PodDeclaration`). This root module keeps the verbs (they fold
//! the declaration through the root EVAL — `load_declaration` — and
//! `refresh` restarts units through the root runtime tools), re-exports
//! everything that moved, and hosts the verb test suite (eval- and
//! systemd-coupled; the crate side carries no tests — ADR-0053 ruling
//! 6's zero-churn reading: the suite runs where its dependencies live).
//!
//! Governing decisions:
//! - **D3 (serve-time resolve; session cache on tmpfs).** Values cache
//!   at `$XDG_RUNTIME_DIR/nau/secrets/<pod>/<decl-hash>.json`, mode
//!   0600, written ATOMICALLY (temp file in the same dir + rename). The
//!   cache key is the SHA-256 of the canonical reference bytes and
//!   DELIBERATELY drops the generation — a rollback to an old
//!   generation must not serve that generation's pre-rotation cached
//!   value. The generation number rides INSIDE the entry body
//!   (stale-ness is detectable).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub use nau_pod::secrets::*;

/// set (declaration-folded, own-over-loaded per ADR-0042 D2).
struct VerbInputs {
    pod_dir: PathBuf,
    generation: u64,
    refs: BTreeMap<String, SecretSource>,
}

/// Load [`VerbInputs`] for a pod: the shellenv read-verb rule — an
/// unknown pod or one with no active generation fails named.
fn verb_inputs(root: &Path, pod_name: &str) -> miette::Result<VerbInputs> {
    crate::pod::validate_pod_name(pod_name)?;
    let pod_dir = root.join(pod_name);
    if !pod_dir.is_dir() {
        miette::bail!(
            "pod '{pod_name}' has no state at {} (`nau pod --name {pod_name} \
             add <package>` does)",
            pod_dir.display()
        );
    }
    let generation = crate::farm::current_generation(&pod_dir)?.ok_or_else(|| {
        miette::miette!(
            "pod '{pod_name}' has no active generation — sync the pod first \
             (`nau pod --name {pod_name} sync`)"
        )
    })?;
    let decl = crate::pod::load_declaration(root, pod_name)?;
    let refs = crate::pod::resolve_pod_secrets(root, pod_name, &decl)?;
    Ok(VerbInputs {
        pod_dir,
        generation,
        refs,
    })
}

// ── `pod secrets list` ──

/// One `pod secrets list` row: the reference and its cache state.
/// VALUES NEVER APPEAR (D8 — the exfiltration guard).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretsListRow {
    /// The env key the value resolves under.
    pub key: String,
    /// The reference, rendered value-free (`env VAR`, `exec prog …`).
    pub reference: String,
    /// `hit` (entry present, generation current), `stale` (entry's
    /// recorded generation is no longer active), or `miss` (no entry).
    pub cache: &'static str,
}

/// `pod secrets list`: the folded references + per-key cache state.
pub fn list_pod(
    root: &Path,
    pod_name: &str,
    cache_base_override: Option<&Path>,
) -> miette::Result<Vec<SecretsListRow>> {
    let inputs = verb_inputs(root, pod_name)?;
    if inputs.refs.is_empty() {
        return Ok(Vec::new());
    }
    let base = cache_base(cache_base_override)?;
    let hash = decl_hash(&inputs.refs)?;
    let state = cache_state(
        &pod_cache_entry_path(&base, pod_name, &hash),
        inputs.generation,
    )?;
    Ok(inputs
        .refs
        .iter()
        .map(|(key, source)| SecretsListRow {
            key: key.clone(),
            reference: render_reference(source),
            cache: state,
        })
        .collect())
}

/// Render one reference for display — references only (D8): these are
/// the declaration's own reviewable fields, never a resolved value.
fn render_reference(source: &SecretSource) -> String {
    match source {
        SecretSource::Bitwarden { id } => format!("bitwarden id {id}"),
        SecretSource::Vault { mount, path, field } => {
            format!("vault {mount}/{path}#{field}")
        }
        SecretSource::Libsecret { attributes } => {
            let pairs = attributes
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(",");
            format!("libsecret {pairs}")
        }
        SecretSource::Exec { command } => format!("exec {}", command.join(" ")),
        SecretSource::Env { var } => format!("env {var}"),
    }
}

/// Render `pod secrets list` output (the CLI prints this text verbatim).
pub fn render_list_rows(pod_name: &str, rows: &[SecretsListRow]) -> String {
    let mut out = format!("secret references for pod '{pod_name}':\n");
    let key_width = rows.iter().map(|r| r.key.len()).max().unwrap_or(3);
    let ref_width = rows.iter().map(|r| r.reference.len()).max().unwrap_or(8);
    for row in rows {
        out.push_str(&format!(
            "  {:<key_width$}  {:<ref_width$}  {}\n",
            row.key, row.reference, row.cache
        ));
    }
    out.push_str(
        "(cache: hit = current entry · stale = resolved for an older \
         generation · miss = not yet resolved this session; values never \
         print)\n",
    );
    out
}

// ── `pod secrets check` ──

/// One `pod secrets check` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretsCheckRow {
    /// The env key.
    pub key: String,
    /// Registry source name.
    pub source: String,
    /// `ok` (the probe resolved) or `failed` (the named failure, D7) —
    /// every D4 source is live since #186.
    pub status: &'static str,
    /// The named failure, empty on `ok`. Never a value (D8).
    pub note: String,
}

/// Whether every reference resolved (`ok`); rows empty = trivially
/// healthy.
pub fn check_healthy(rows: &[SecretsCheckRow]) -> bool {
    rows.iter().all(|r| r.status == "ok")
}

/// `pod secrets check`: resolve EVERY reference through its provider,
/// one probe per key (so the report names every failing key instead of
/// stopping at the first — D7 still holds for [`resolve_references`],
/// which is all-or-nothing). Never touches the session cache: a probe
/// is a probe, and a partial success must not land a partial entry.
pub fn check_pod(root: &Path, pod_name: &str) -> miette::Result<Vec<SecretsCheckRow>> {
    let inputs = verb_inputs(root, pod_name)?;
    let mut rows = Vec::new();
    for (key, source) in &inputs.refs {
        let name = source_name(source);
        match resolve_one(&inputs.pod_dir, key, source) {
            Ok(_) => rows.push(SecretsCheckRow {
                key: key.clone(),
                source: name.to_string(),
                status: "ok",
                note: String::new(),
            }),
            Err(e) => rows.push(SecretsCheckRow {
                key: key.clone(),
                source: name.to_string(),
                status: "failed",
                note: format!("{e}"),
            }),
        }
    }
    Ok(rows)
}

/// Render `pod secrets check` output.
pub fn render_check_rows(pod_name: &str, rows: &[SecretsCheckRow]) -> String {
    let mut out = format!("secret health for pod '{pod_name}':\n");
    let key_width = rows.iter().map(|r| r.key.len()).max().unwrap_or(3).max(3);
    let src_width = rows
        .iter()
        .map(|r| r.source.len())
        .max()
        .unwrap_or(6)
        .max(6);
    for row in rows {
        out.push_str(&format!(
            "  {:<key_width$}  {:<src_width$}  {:<11} {}\n",
            row.key, row.source, row.status, row.note,
        ));
    }
    if rows.is_empty() {
        out.push_str("  (no secret references declared)\n");
    }
    out
}

// ── `pod secrets refresh` ──

/// What `pod secrets refresh` did. Counts and sources only — never
/// values (D8).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecretsRefreshReport {
    /// References re-resolved.
    pub resolved: usize,
    /// Source kind → reference count.
    pub sources: BTreeMap<String, usize>,
    /// Cached entries the purge dropped.
    pub purged: usize,
    /// Secret-consuming units restarted: their envfile digest moved
    /// (ADR-0042 D3's rotate-restart contract, issue #224).
    pub restarted: Vec<String>,
    /// Secret-consuming units left running: the envfile bytes are
    /// unchanged, so a restart would be gratuitous.
    pub unchanged: Vec<String>,
    /// Consuming units whose restart was skipped — systemctl
    /// unavailable (the reconcile skip semantics: named, never silent;
    /// the next refresh with tools converges).
    pub skipped: Vec<String>,
}

/// `pod secrets refresh` (ADR-0042 D3's rotation verb): bust the pod's
/// cache subtree, re-resolve every reference through its provider, and
/// rewrite the active entry. With no references this touches nothing —
/// no purge, no tmpfs requirement (the D3 empty rule covers the verb).
/// After the rewrite, the pod's secret-consuming units whose envfile
/// digest changed get `systemctl --user restart` (issue #224): the
/// rotate-restart contract's restart half. The unit hash stays
/// package-only and sync never sees any of this — refresh is the ONLY
/// rotation mechanism.
pub fn refresh_pod(
    root: &Path,
    pod_name: &str,
    cache_base_override: Option<&Path>,
    tools: &crate::runtime::RuntimeTools,
) -> miette::Result<SecretsRefreshReport> {
    let inputs = verb_inputs(root, pod_name)?;
    let mut report = SecretsRefreshReport::default();
    if inputs.refs.is_empty() {
        return Ok(report);
    }
    let base = cache_base(cache_base_override)?;
    let hash = decl_hash(&inputs.refs)?;
    let envfile = pod_envfile_path(&base, pod_name, &hash);
    // The digest the consuming units last ran against, captured BEFORE
    // the purge (which drops the whole subtree, envfile included).
    // Missing file → no digest: every consumer is stale by
    // construction (started failed against the gone file — the D3 boot
    // story), so the rewrite below restarts them.
    let before = envfile_digest(&envfile);
    report.purged = purge_pod_cache(&base, pod_name)?;
    for source in inputs.refs.values() {
        *report
            .sources
            .entry(source_name(source).to_string())
            .or_insert(0) += 1;
    }
    let values = resolve_references(
        &inputs.pod_dir,
        pod_name,
        inputs.generation,
        &inputs.refs,
        Some(&base),
    )?;
    report.resolved = values.len();
    // Consumer duty (ADR-0042 D3, issues #184 and #224): refresh is the
    // rotation verb, so it re-materializes the 0600 runtime envfile the
    // service units reference, then restarts exactly the units whose
    // digest moved — the rotate-restart contract, both halves.
    write_pod_envfile(&envfile, &values)?;
    let after = envfile_digest(&envfile);
    let consumers = crate::services::units_referencing_envfile(
        &crate::pod::pod_store(&inputs.pod_dir),
        inputs.generation,
        pod_name,
        &envfile,
    )?;
    let restart = restart_on_digest_change(before.as_deref(), after.as_deref(), &consumers);
    report.unchanged = consumers
        .iter()
        .filter(|u| !restart.contains(*u))
        .cloned()
        .collect();
    let (restarted, skipped) = crate::services::restart_units(&restart, tools)?;
    report.restarted = restarted;
    report.skipped = skipped;
    Ok(report)
}

/// SHA-256 hex over a file's bytes; `None` when the file is missing
/// (the post-reboot tmpfs state — no bytes, no digest).
fn envfile_digest(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(sha256_hex(&bytes))
}

/// The digest-diff restart selection (issue #224): a consuming unit
/// restarts IFF the envfile bytes actually changed. `before` is the
/// digest the units last ran against (`None` = the file was gone — the
/// D3 boot story), `after` the digest of the rewritten file. Equal
/// digests select nothing (no gratuitous restarts); non-consumers
/// never appear (new units enter only through `consumers`, removed
/// ones only drop out of it).
fn restart_on_digest_change(
    before: Option<&str>,
    after: Option<&str>,
    consumers: &[String],
) -> Vec<String> {
    match (before, after) {
        (Some(b), Some(a)) if b == a => Vec::new(),
        _ => consumers.to_vec(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Every test that mutates process env (`XDG_RUNTIME_DIR`, probe
    /// vars, `PATH`) takes the shared crate-wide lock (src/test_env.rs)
    /// — env is process-global, cargo runs tests in parallel threads,
    /// and the per-module statics of the pre-#186 era excluded nothing
    /// across modules.
    use crate::test_env::ENV_LOCK;

    const SENTINEL: &str = "TOPSECRET-b183-VALUE";

    fn seed_pod(root: &Path, name: &str, body: &str) {
        std::fs::create_dir_all(root.join(name)).unwrap();
        std::fs::write(root.join(name).join("pod.lua"), body).unwrap();
    }

    /// Give the pod an active generation 3 (`current` →
    /// generations/3/farm); the verbs only parse the link.
    fn activate(root: &Path, name: &str) {
        let pod = root.join(name);
        std::fs::create_dir_all(pod.join("generations").join("3")).unwrap();
        std::os::unix::fs::symlink("generations/3/farm", pod.join("current")).unwrap();
    }

    /// A `+x` shell script; returns its absolute path (argv[0] form).
    fn script(dir: &Path, name: &str, body: &str) -> String {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.display().to_string()
    }

    /// The counting provider: appends one line to `counter` (invocation
    /// count), prints the sentinel + newline (trim case).
    fn counting_script(dir: &Path, counter: &Path) -> String {
        script(
            dir,
            "counting-provider",
            &format!(
                "n=$(cat {} 2>/dev/null || echo 0); echo $((n+1)) > {}; \
                 printf '{SENTINEL}\\n'\n",
                counter.display(),
                counter.display()
            ),
        )
    }

    fn calls(counter: &Path) -> u32 {
        std::fs::read_to_string(counter)
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    fn env_ref(var: &str) -> SecretSource {
        SecretSource::Env {
            var: var.to_string(),
        }
    }

    /// A dedicated pod state root under the fixture: resolve-level
    /// tests keep their scripts OUTSIDE it, because the D4 refusal
    /// treats everything under the pod root as off-limits.
    fn pod_state_root(tmp: &Path) -> PathBuf {
        let pod = tmp.join("pods").join("p");
        std::fs::create_dir_all(&pod).unwrap();
        pod
    }

    fn file_mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    // ── env source ──

    #[test]
    fn env_source_resolves_the_caller_var() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("NAU_SECRETS_TEST_OK", SENTINEL);
        let refs = BTreeMap::from([("K".to_string(), env_ref("NAU_SECRETS_TEST_OK"))]);
        let values = resolve_references(
            tmp.path(),
            "p",
            3,
            &refs,
            Some(tmp.path().join("cache").as_path()),
        )
        .unwrap();
        std::env::remove_var("NAU_SECRETS_TEST_OK");
        assert_eq!(values.get("K").map(String::as_str), Some(SENTINEL));
    }

    #[test]
    fn env_source_missing_var_fails_named_and_leaks_nothing() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("NAU_SECRETS_TEST_MISSING");
        let refs = BTreeMap::from([("API_TOKEN".to_string(), env_ref("NAU_SECRETS_TEST_MISSING"))]);
        let err = format!(
            "{}",
            resolve_references(Path::new("/nonexistent-pod"), "p", 3, &refs, None).unwrap_err()
        );
        assert!(err.contains("secret 'API_TOKEN'"), "{err}");
        assert!(err.contains("source 'env'"), "{err}");
        assert!(err.contains("NAU_SECRETS_TEST_MISSING"), "{err}");
        assert!(!err.contains(SENTINEL), "value leaked into error: {err}");
    }

    // ── exec source ──

    #[test]
    fn exec_source_runs_no_shell_and_trims_edges_only() {
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let path = script(tmp.path(), "pem-provider", "printf 'line1\nline2\n'\n");
        let refs = BTreeMap::from([(
            "PEM_KEY".to_string(),
            SecretSource::Exec {
                command: vec![path],
            },
        )]);
        let values = resolve_references(
            &pod,
            "p",
            3,
            &refs,
            Some(tmp.path().join("cache").as_path()),
        )
        .unwrap();
        assert_eq!(
            values.get("PEM_KEY").map(String::as_str),
            Some("line1\nline2"),
            "interior newline survives; only the edges are trimmed"
        );
    }

    #[test]
    fn exec_cache_hit_makes_zero_provider_calls() {
        // The counting provider shells out to `cat` (an EXTERNAL command
        // resolved via PATH), so the spawn window must exclude every
        // env-mutating test (PATH swaps) — same ENV_LOCK discipline.
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("cache");
        let counter = tmp.path().join("calls");
        let pod = pod_state_root(tmp.path());
        let path = counting_script(tmp.path(), &counter);
        let refs = BTreeMap::from([(
            "K".to_string(),
            SecretSource::Exec {
                command: vec![path],
            },
        )]);
        let once = resolve_references(&pod, "p", 3, &refs, Some(&cache)).unwrap();
        assert_eq!(once.get("K").map(String::as_str), Some(SENTINEL));
        assert_eq!(calls(&counter), 1);
        // Same references → same decl-hash → the cache answers, the
        // provider never runs again (D3).
        let twice = resolve_references(&pod, "p", 3, &refs, Some(&cache)).unwrap();
        assert_eq!(twice.get("K").map(String::as_str), Some(SENTINEL));
        assert_eq!(calls(&counter), 1);
        // ANY reference change → different hash → fresh fetch.
        let changed = BTreeMap::from([(
            "K".to_string(),
            SecretSource::Exec {
                command: vec![counting_script(tmp.path(), &counter), "extra".to_string()],
            },
        )]);
        resolve_references(&pod, "p", 3, &changed, Some(&cache)).unwrap();
        assert_eq!(calls(&counter), 2);
    }

    #[test]
    fn exec_nonzero_exit_fails_naming_key_and_program() {
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let path = script(tmp.path(), "broken-provider", "exit 3\n");
        let refs = BTreeMap::from([(
            "API_TOKEN".to_string(),
            SecretSource::Exec {
                command: vec![path],
            },
        )]);
        let err = format!(
            "{}",
            resolve_references(
                &pod,
                "p",
                3,
                &refs,
                Some(tmp.path().join("cache").as_path())
            )
            .unwrap_err()
        );
        assert!(err.contains("secret 'API_TOKEN'"), "{err}");
        assert!(err.contains("source 'exec'"), "{err}");
        assert!(err.contains("broken-provider"), "{err}");
        assert!(err.contains("3"), "exit status not named: {err}");
    }

    #[test]
    fn exec_empty_output_fails_loud_never_an_empty_value() {
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let path = script(tmp.path(), "silent-provider", "true\n");
        let refs = BTreeMap::from([(
            "K".to_string(),
            SecretSource::Exec {
                command: vec![path],
            },
        )]);
        let err = format!(
            "{}",
            resolve_references(
                &pod,
                "p",
                3,
                &refs,
                Some(tmp.path().join("cache").as_path())
            )
            .unwrap_err()
        );
        assert!(err.contains("no output"), "{err}");
    }

    // ── D4: argv[0] host-PATH scrub ──

    #[test]
    fn exec_argv0_ignores_pod_farm_and_uses_the_host_path_winner() {
        let tmp = tempfile::tempdir().unwrap();
        let pod = tmp.path().join("work");
        // A "farm" (and anything else) under the pod state root shipping
        // the same program name must lose the search.
        std::fs::create_dir_all(pod.join("current")).unwrap();
        script(&pod.join("current"), "shadow", "printf 'FROM-FARM\n'");
        let host = tmp.path().join("hostbin");
        std::fs::create_dir_all(&host).unwrap();
        let host_tool = script(&host, "shadow", "printf 'FROM-HOST\n'");
        let raw_path = format!("{}:{}", pod.join("current").display(), host.display());
        let dirs = host_path_dirs(&pod, &raw_path);
        assert_eq!(
            dirs,
            vec![host.clone()],
            "the pod-rooted PATH entry must be scrubbed"
        );
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved_path = std::env::var("PATH").ok();
        std::env::set_var("PATH", &raw_path);
        let resolved = resolve_exec_program(&pod, "K", "exec", "shadow");
        match saved_path {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }
        assert_eq!(resolved.unwrap(), PathBuf::from(&host_tool));
    }

    #[test]
    fn exec_program_resolving_inside_the_pod_root_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let pod = tmp.path().join("work");
        let farm = pod.join("current");
        std::fs::create_dir_all(&farm).unwrap();
        let tool = script(&farm, "bws", "printf 'x\n'");
        // (a) The search form: the farm is the ONLY holder of the name,
        // but the D4 scrub removes pod-rooted PATH entries before the
        // search, so the honest answer is "not found on the host PATH".
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved_path = std::env::var("PATH").ok();
        std::env::set_var("PATH", &farm);
        let err = format!(
            "{}",
            resolve_exec_program(&pod, "BW_ITEM", "exec", "bws").unwrap_err()
        );
        // (b) The symlink-escape form: an OUTSIDE PATH entry whose
        // binary links back into the pod root. The scrub passes the
        // entry; the post-search canonicalization catches it.
        let outside = tmp.path().join("outside-bin");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&tool, outside.join("bws")).unwrap();
        std::env::set_var("PATH", &outside);
        let err2 = format!(
            "{}",
            resolve_exec_program(&pod, "BW_ITEM", "exec", "bws").unwrap_err()
        );
        // (c) The absolute-path form hits the refusal directly.
        let err3 = format!(
            "{}",
            resolve_exec_program(&pod, "BW_ITEM", "exec", &tool).unwrap_err()
        );
        match saved_path {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }
        assert!(err.contains("not found on the host PATH"), "{err}");
        assert!(err2.contains("inside the pod state root"), "{err2}");
        assert!(err2.contains("bws"), "{err2}");
        assert!(err3.contains("inside the pod state root"), "{err3}");
    }

    #[test]
    fn exec_program_not_on_host_path_fails_named() {
        let tmp = tempfile::tempdir().unwrap();
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved_path = std::env::var("PATH").ok();
        std::env::set_var("PATH", tmp.path());
        let err = format!(
            "{}",
            resolve_exec_program(tmp.path(), "K", "exec", "definitely-not-on-path-183")
                .unwrap_err()
        );
        match saved_path {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }
        assert!(err.contains("not found on the host PATH"), "{err}");
        assert!(err.contains("definitely-not-on-path-183"), "{err}");
    }

    // ── cache shape ──

    #[test]
    fn cache_entry_is_0600_atomically_placed_and_generation_stamped() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("cache");
        let pod = pod_state_root(tmp.path());
        let path = script(tmp.path(), "provider", &format!("printf '{SENTINEL}\\n'\n"));
        let refs = BTreeMap::from([(
            "K".to_string(),
            SecretSource::Exec {
                command: vec![path],
            },
        )]);
        resolve_references(&pod, "work", 7, &refs, Some(&cache)).unwrap();
        let hash = decl_hash(&refs).unwrap();
        let entry_path = pod_cache_entry_path(&cache, "work", &hash);
        assert_eq!(file_mode(&entry_path), 0o600, "entry must be 0600");
        let entries: Vec<_> = std::fs::read_dir(pod_cache_dir(&cache, "work"))
            .unwrap()
            .collect();
        assert_eq!(entries.len(), 1, "no temp leftovers on the success path");
        let entry = read_cache_entry(&entry_path).unwrap().unwrap();
        assert_eq!(entry.generation, 7, "generation rides inside the body");
        assert_eq!(entry.values.get("K").map(String::as_str), Some(SENTINEL));
    }

    #[test]
    fn decl_hash_is_stable_and_moves_on_any_reference_change() {
        let a = BTreeMap::from([
            ("A".to_string(), env_ref("VAR_ONE")),
            (
                "B".to_string(),
                SecretSource::Exec {
                    command: vec!["op".to_string(), "read".to_string(), "x".to_string()],
                },
            ),
        ]);
        assert_eq!(decl_hash(&a).unwrap(), decl_hash(&a).unwrap());
        let same_map_other_order = BTreeMap::from([
            (
                "B".to_string(),
                SecretSource::Exec {
                    command: vec!["op".to_string(), "read".to_string(), "x".to_string()],
                },
            ),
            ("A".to_string(), env_ref("VAR_ONE")),
        ]);
        assert_eq!(
            decl_hash(&a).unwrap(),
            decl_hash(&same_map_other_order).unwrap(),
            "serialization is canonical (sorted keys)"
        );
        let variants = [
            BTreeMap::from([("A".to_string(), env_ref("VAR_TWO"))]),
            BTreeMap::from([("A2".to_string(), env_ref("VAR_ONE"))]),
            BTreeMap::from([(
                "A".to_string(),
                SecretSource::Bitwarden {
                    id: "8848".to_string(),
                },
            )]),
        ];
        for changed in variants {
            assert_ne!(
                decl_hash(&a).unwrap(),
                decl_hash(&changed).unwrap(),
                "any reference change must move the hash"
            );
        }
    }

    // ── refresh + prune lifecycle ──

    #[test]
    fn refresh_busts_the_cache_and_rewrites_the_entry() {
        // The counting provider shells out to `cat` (external, found
        // via PATH) — hold ENV_LOCK so concurrent PATH swaps cannot
        // break the provider spawn.
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("cache");
        let counter = tmp.path().join("calls");
        let provider = counting_script(tmp.path(), &counter);
        seed_pod(
            tmp.path(),
            "work",
            &format!(
                r#"pod {{
    secrets = {{ K = {{ source = "exec", command = {{ "{provider}" }} }} }},
}}
"#
            ),
        );
        activate(tmp.path(), "work");
        let first = refresh_pod(
            tmp.path(),
            "work",
            Some(&cache),
            &crate::runtime::RuntimeTools::default(),
        )
        .unwrap();
        assert_eq!(first.resolved, 1);
        assert_eq!(first.sources.get("exec"), Some(&1));
        assert_eq!(calls(&counter), 1);
        // A plain resolve between refreshes is a cache hit (zero calls).
        let pod_dir = tmp.path().join("work");
        let decl = crate::pod::load_declaration(tmp.path(), "work").unwrap();
        let refs = crate::pod::resolve_pod_secrets(tmp.path(), "work", &decl).unwrap();
        resolve_references(&pod_dir, "work", 3, &refs, Some(&cache)).unwrap();
        assert_eq!(calls(&counter), 1);
        // Refresh busts it: the provider runs again.
        let second = refresh_pod(
            tmp.path(),
            "work",
            Some(&cache),
            &crate::runtime::RuntimeTools::default(),
        )
        .unwrap();
        assert_eq!(second.purged, 1);
        assert_eq!(calls(&counter), 2);
        // The rewritten entry serves the ACTIVE generation.
        let hash = decl_hash(&refs).unwrap();
        let entry = read_cache_entry(&pod_cache_entry_path(&cache, "work", &hash))
            .unwrap()
            .unwrap();
        assert_eq!(entry.generation, 3);
    }

    #[test]
    fn prune_drops_entries_whose_generation_is_no_longer_active() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("cache");
        for (hash, generation) in [("aaa", 1), ("bbb", 2)] {
            write_cache_entry(
                &pod_cache_entry_path(&cache, "work", hash),
                &CacheEntry {
                    generation,
                    values: BTreeMap::new(),
                },
            )
            .unwrap();
        }
        assert_eq!(prune_stale_cache_entries(&cache, "work", 2), 1);
        assert!(pod_cache_entry_path(&cache, "work", "bbb").is_file());
        assert!(!pod_cache_entry_path(&cache, "work", "aaa").exists());
        // Idempotent: nothing left to prune at the same generation.
        assert_eq!(prune_stale_cache_entries(&cache, "work", 2), 0);
    }

    #[test]
    fn reconcile_prune_targets_the_active_generation_and_purges_when_cold() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("cache");
        for (hash, generation) in [("aaa", 1), ("bbb", 2)] {
            write_cache_entry(
                &pod_cache_entry_path(&cache, "work", hash),
                &CacheEntry {
                    generation,
                    values: BTreeMap::new(),
                },
            )
            .unwrap();
        }
        reconcile_cache_prune("work", Some(2), Some(&cache));
        assert!(pod_cache_entry_path(&cache, "work", "bbb").is_file());
        assert!(!pod_cache_entry_path(&cache, "work", "aaa").exists());
        reconcile_cache_prune("work", None, Some(&cache));
        assert!(!cache.join("work").exists(), "cold pod purges its subtree");
        // Best-effort by construction: unknown pods and missing bases
        // are silent no-ops.
        reconcile_cache_prune("ghost", Some(1), Some(&cache));
    }

    // ── rotate-restart (ADR-0042 D3, issue #224) ──

    /// A fake systemctl: appends its argv (one arg per line) to `log`,
    /// then exits `code` — the runtime.rs fake-tool pattern, extended
    /// to record WHAT it was asked to run.
    fn fake_systemctl(dir: &Path, log: &Path, code: i32) -> crate::runtime::RuntimeTools {
        let path = dir.join("fake-systemctl");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" >> {}\nexit {code}\n",
                log.display()
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        crate::runtime::RuntimeTools {
            systemctl: Some(path),
            ..Default::default()
        }
    }

    /// An exec provider whose value rotates: it prints the current
    /// contents of `valuefile` (trimmed by the resolve).
    fn valuefile_provider(dir: &Path, valuefile: &Path) -> String {
        script(
            dir,
            "valuefile-provider",
            &format!("cat {}", valuefile.display()),
        )
    }

    /// Record generation `gen`'s units.json with (service name, rendered
    /// text) pairs — the fixture shape `units_referencing_envfile` reads.
    fn seed_units(pod_dir: &Path, gen: u64, units: &[(&str, String)]) {
        let dir = pod_dir
            .join("generations")
            .join(gen.to_string())
            .join(crate::services::SERVICES_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        let units: Vec<serde_json::Value> = units
            .iter()
            .map(|(name, text)| {
                serde_json::json!({
                    "name": name, "pkg": "pkg", "layer": "own",
                    "daemon": "simple", "enabled": true, "exec": "/exec",
                    "args": [], "environment": {}, "after": [],
                    "text": text, "hash": "h",
                })
            })
            .collect();
        std::fs::write(
            dir.join("units.json"),
            serde_json::to_vec(&serde_json::json!({ "units": units })).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn digest_diff_selection_restarts_only_changed_consumers() {
        let web = "nau-pod-work-web.service".to_string();
        let side = "nau-pod-work-side.service".to_string();
        let both = vec![web.clone(), side.clone()];
        // Changed digest: every current consumer restarts…
        assert_eq!(
            restart_on_digest_change(Some("old"), Some("new"), &both),
            both
        );
        // …including a NEWLY-added consumer, and NOT a removed one.
        assert_eq!(
            restart_on_digest_change(Some("old"), Some("new"), std::slice::from_ref(&web)),
            vec![web.clone()]
        );
        // Unchanged digest: nothing restarts, whatever the set.
        assert!(restart_on_digest_change(Some("same"), Some("same"), &both).is_empty());
        assert!(
            restart_on_digest_change(Some("same"), Some("same"), std::slice::from_ref(&web))
                .is_empty()
        );
        // Missing before (the envfile was gone — the D3 boot story):
        // every consumer is stale by construction.
        assert_eq!(restart_on_digest_change(None, Some("new"), &both), both);
    }

    #[test]
    fn envfile_digest_tracks_bytes_and_missing_files() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("f.env");
        assert_eq!(envfile_digest(&file), None, "missing file, no digest");
        std::fs::write(&file, b"K=\"v1\"\n").unwrap();
        let first = envfile_digest(&file).unwrap();
        std::fs::write(&file, b"K=\"v1\"\n").unwrap();
        assert_eq!(envfile_digest(&file).unwrap(), first, "same bytes");
        std::fs::write(&file, b"K=\"v2\"\n").unwrap();
        assert_ne!(envfile_digest(&file).unwrap(), first, "moved bytes");
    }

    #[test]
    fn refresh_restarts_exactly_the_changed_digest_consumers() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("cache");
        let valuefile = tmp.path().join("value.txt");
        std::fs::write(&valuefile, "v1\n").unwrap();
        let provider = valuefile_provider(tmp.path(), &valuefile);
        seed_pod(
            tmp.path(),
            "work",
            &format!(
                r#"pod {{
    secrets = {{ K = {{ source = "exec", command = {{ "{provider}" }} }} }},
}}
"#
            ),
        );
        activate(tmp.path(), "work");
        let decl = crate::pod::load_declaration(tmp.path(), "work").unwrap();
        let refs = crate::pod::resolve_pod_secrets(tmp.path(), "work", &decl).unwrap();
        let hash = decl_hash(&refs).unwrap();
        let envfile = pod_envfile_path(&cache, "work", &hash);
        // One consumer ("web") and one non-consumer ("side").
        seed_units(
            &tmp.path().join("work"),
            3,
            &[
                (
                    "web",
                    format!(
                        "ExecStart=/bin/true\nEnvironmentFile=\"{}\"\n",
                        envfile.display()
                    ),
                ),
                ("side", "ExecStart=/bin/true\n".to_string()),
            ],
        );
        let log = tmp.path().join("systemctl.log");
        let tools = fake_systemctl(tmp.path(), &log, 0);

        // First refresh: no envfile existed, so the consumer is stale by
        // construction (the D3 boot story) — exactly "web" restarts.
        let first = refresh_pod(tmp.path(), "work", Some(&cache), &tools).unwrap();
        assert_eq!(
            first.restarted,
            vec!["nau-pod-work-web.service".to_string()]
        );
        assert!(first.unchanged.is_empty());

        // Second refresh, same value: the bytes are identical, so
        // nothing restarts — the consumer is reported unchanged.
        let second = refresh_pod(tmp.path(), "work", Some(&cache), &tools).unwrap();
        assert!(second.restarted.is_empty());
        assert_eq!(
            second.unchanged,
            vec!["nau-pod-work-web.service".to_string()]
        );

        // Rotate the value: the digest moves and "web" restarts again.
        std::fs::write(&valuefile, "v2\n").unwrap();
        let third = refresh_pod(tmp.path(), "work", Some(&cache), &tools).unwrap();
        assert_eq!(
            third.restarted,
            vec!["nau-pod-work-web.service".to_string()]
        );

        // The fake ran `--user restart <consumer>` exactly twice and
        // NEVER touched the non-consumer.
        let ran = std::fs::read_to_string(&log).unwrap();
        assert_eq!(ran.matches("nau-pod-work-web.service").count(), 2);
        assert!(!ran.contains("nau-pod-work-side.service"));
        assert!(ran.contains("--user"));
        assert!(ran.contains("restart"));
    }

    #[test]
    fn refresh_without_systemctl_skips_the_restart_named() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("cache");
        let provider = valuefile_provider(tmp.path(), &tmp.path().join("value.txt"));
        std::fs::write(tmp.path().join("value.txt"), "v1\n").unwrap();
        seed_pod(
            tmp.path(),
            "work",
            &format!(
                r#"pod {{
    secrets = {{ K = {{ source = "exec", command = {{ "{provider}" }} }} }},
}}
"#
            ),
        );
        activate(tmp.path(), "work");
        let decl = crate::pod::load_declaration(tmp.path(), "work").unwrap();
        let refs = crate::pod::resolve_pod_secrets(tmp.path(), "work", &decl).unwrap();
        let envfile = pod_envfile_path(&cache, "work", &decl_hash(&refs).unwrap());
        seed_units(
            &tmp.path().join("work"),
            3,
            &[(
                "web",
                format!("EnvironmentFile=\"{}\"\n", envfile.display()),
            )],
        );
        // Tools absent (RuntimeTools::default()): the restart is a named
        // skip — never a silent no-op, never a failure.
        let report = refresh_pod(
            tmp.path(),
            "work",
            Some(&cache),
            &crate::runtime::RuntimeTools::default(),
        )
        .unwrap();
        assert!(report.restarted.is_empty());
        assert_eq!(report.skipped, vec!["nau-pod-work-web.service".to_string()]);
    }

    #[test]
    fn refresh_fails_loud_naming_a_unit_the_restart_cannot_move() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("cache");
        let valuefile = tmp.path().join("value.txt");
        std::fs::write(&valuefile, "v1\n").unwrap();
        let provider = valuefile_provider(tmp.path(), &valuefile);
        seed_pod(
            tmp.path(),
            "work",
            &format!(
                r#"pod {{
    secrets = {{ K = {{ source = "exec", command = {{ "{provider}" }} }} }},
}}
"#
            ),
        );
        activate(tmp.path(), "work");
        let decl = crate::pod::load_declaration(tmp.path(), "work").unwrap();
        let refs = crate::pod::resolve_pod_secrets(tmp.path(), "work", &decl).unwrap();
        let envfile = pod_envfile_path(&cache, "work", &decl_hash(&refs).unwrap());
        seed_units(
            &tmp.path().join("work"),
            3,
            &[(
                "web",
                format!("EnvironmentFile=\"{}\"\n", envfile.display()),
            )],
        );
        // The fake exists but FAILS: refresh exits naming the unit (D7),
        // after the envfile write landed (the write half is done).
        let log = tmp.path().join("systemctl.log");
        let tools = fake_systemctl(tmp.path(), &log, 7);
        let err = refresh_pod(tmp.path(), "work", Some(&cache), &tools).unwrap_err();
        let err = format!("{err:#}");
        assert!(
            err.contains("nau-pod-work-web.service"),
            "the error must name the unit: {err}"
        );
        assert!(
            envfile.is_file(),
            "the envfile write half completed before the failed restart"
        );
    }

    // ── serve step + envfile (issue #184) ──

    #[test]
    fn serve_pod_resolves_and_materializes_the_envfile_0600() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("cache");
        let pod = pod_state_root(tmp.path());
        let counter = tmp.path().join("calls");
        let path = counting_script(tmp.path(), &counter);
        let refs = BTreeMap::from([
            ("A_KEY".to_string(), env_ref("NAU_SECRETS_TEST_SERVE")),
            (
                "B_KEY".to_string(),
                SecretSource::Exec {
                    command: vec![path],
                },
            ),
        ]);
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("NAU_SECRETS_TEST_SERVE", "plain");
        let served = serve_pod(&pod, "p", 5, &refs, Some(&cache)).unwrap();
        std::env::remove_var("NAU_SECRETS_TEST_SERVE");
        assert_eq!(calls(&counter), 1, "cold resolve calls the provider");
        assert_eq!(
            served.values.get("B_KEY").map(String::as_str),
            Some(SENTINEL)
        );
        let envfile = served.envfile.clone().unwrap();
        let hash = decl_hash(&refs).unwrap();
        let cache_entry = pod_cache_entry_path(&cache, "p", &hash);
        assert_eq!(
            envfile,
            cache_entry.with_extension("env"),
            "the envfile is the cache entry's .env sibling"
        );
        assert_eq!(file_mode(&envfile), 0o600);
        let body = std::fs::read_to_string(&envfile).unwrap();
        assert_eq!(
            body,
            format!("A_KEY=\"plain\"\nB_KEY=\"{SENTINEL}\"\n"),
            "sorted KEY=value lines, systemd double-quote wrapping"
        );
        // A warm serve: zero provider calls, envfile refreshed anyway.
        std::fs::remove_file(&envfile).unwrap();
        let again = serve_pod(&pod, "p", 5, &refs, Some(&cache)).unwrap();
        assert_eq!(calls(&counter), 1, "cache hit = zero provider calls");
        assert!(envfile.is_file(), "the serve re-materializes the envfile");
        assert_eq!(again.meta.get("B_KEY").unwrap().cache, "hit");
        assert_eq!(again.meta.get("B_KEY").unwrap().source, "exec");
        assert_eq!(again.meta.get("A_KEY").unwrap().source, "env");
    }

    /// The printf one-liner with every nasty byte: backslash, double
    /// quote, interior newline. Extracted so the test body stays a
    /// plain sequence (the complexity guard miscounts escape-heavy
    /// literals).
    fn nasty_provider_script() -> &'static str {
        r#"printf '%s\n' 'back\slash quote" nl
end'"#
    }

    /// The byte-exact envfile the escaper must produce for
    /// [`nasty_provider_script`]'s output.
    fn expected_envfile_body() -> &'static str {
        "K=\"back\\\\slash quote\\\" nl\\nend\"\n"
    }

    #[test]
    fn envfile_escapes_systemd_c_sequences_verbatim_backslashes_included() {
        let tmp = tempfile::tempdir().unwrap();
        let refs = BTreeMap::from([(
            "K".to_string(),
            SecretSource::Exec {
                command: vec![script(
                    tmp.path(),
                    "nasty-provider",
                    nasty_provider_script(),
                )],
            },
        )]);
        let pod = pod_state_root(tmp.path());
        let served = serve_pod(
            &pod,
            "p",
            1,
            &refs,
            Some(tmp.path().join("cache").as_path()),
        )
        .unwrap();
        let body = std::fs::read_to_string(served.envfile.unwrap()).unwrap();
        assert_eq!(
            body,
            expected_envfile_body(),
            "backslash doubled, quote escaped, newline folded to \\n"
        );
    }

    #[test]
    fn serve_pod_with_no_references_needs_no_runtime_dir() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::remove_var("XDG_RUNTIME_DIR");
        let refs: BTreeMap<String, SecretSource> = BTreeMap::new();
        let served = serve_pod(Path::new("/nonexistent-pod"), "p", 1, &refs, None).unwrap();
        if let Some(dir) = saved {
            std::env::set_var("XDG_RUNTIME_DIR", dir);
        }
        assert_eq!(served, ServedSecrets::default());
    }

    #[test]
    fn serve_pod_fails_loud_naming_the_var_before_any_envfile_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("cache");
        let pod = pod_state_root(tmp.path());
        let refs = BTreeMap::from([
            ("GOOD".to_string(), env_ref("NAU_SECRETS_TEST_GOOD")),
            ("BAD".to_string(), env_ref("NAU_SECRETS_TEST_ABSENT")),
        ]);
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("NAU_SECRETS_TEST_GOOD", "v");
        let err = format!(
            "{}",
            serve_pod(&pod, "p", 1, &refs, Some(&cache)).unwrap_err()
        );
        std::env::remove_var("NAU_SECRETS_TEST_GOOD");
        assert!(err.contains("NAU_SECRETS_TEST_ABSENT"), "{err}");
        assert!(err.contains("BAD"), "{err}");
        // D7: an all-or-nothing resolve means NOTHING landed — no cache
        // entry, no envfile, no partial export set downstream.
        assert!(read_dir_count(&cache).is_none() || read_dir_count(&cache) == Some(0));
        assert_eq!(
            std::fs::read_dir(pod_cache_entry_path(&cache, "p", "x").parent().unwrap())
                .map(|d| d.count())
                .unwrap_or(0),
            0,
            "no cache dir contents"
        );
    }

    fn read_dir_count(path: &Path) -> Option<usize> {
        std::fs::read_dir(path).ok().map(|d| d.count())
    }

    #[test]
    fn warm_cache_render_writes_the_envfile_without_any_provider_call() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("cache");
        let refs = BTreeMap::from([(
            "K".to_string(),
            SecretSource::Exec {
                command: vec!["/no/such/program-184".to_string()],
            },
        )]);
        // A WARM entry already in the cache (nothing resolves here —
        // the provider named above does not even exist).
        let hash = decl_hash(&refs).unwrap();
        write_cache_entry(
            &pod_cache_entry_path(&cache, "p", &hash),
            &CacheEntry {
                generation: 4,
                values: BTreeMap::from([("K".to_string(), "cached".to_string())]),
            },
        )
        .unwrap();
        let rendered = render_pod_envfile_from_warm_cache("p", &refs, Some(&cache));
        assert_eq!(rendered, 1);
        let envfile = pod_cache_entry_path(&cache, "p", &hash).with_extension("env");
        assert_eq!(std::fs::read_to_string(&envfile).unwrap(), "K=\"cached\"\n");
        assert_eq!(file_mode(&envfile), 0o600);
        // Idempotent: a second warm sync rewrites the same content.
        assert_eq!(
            render_pod_envfile_from_warm_cache("p", &refs, Some(&cache)),
            1
        );
        // A COLD cache writes nothing — the unit's start-time failure
        // is the designed state (D7).
        let cold = tmp.path().join("cold");
        assert_eq!(
            render_pod_envfile_from_warm_cache("p", &refs, Some(&cold)),
            0,
            "cache miss renders nothing"
        );
        assert!(!cold.join("p").join(format!("{hash}.env")).exists());
        // No references → nothing, no runtime dir required.
        let empty: BTreeMap<String, SecretSource> = BTreeMap::new();
        assert_eq!(
            render_pod_envfile_from_warm_cache("p", &empty, Some(&cache)),
            0
        );
    }

    #[test]
    fn pod_envfile_path_passive_derives_from_the_refs_and_fails_named_without_runtime_dir() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::remove_var("XDG_RUNTIME_DIR");
        let refs = BTreeMap::from([("K".to_string(), env_ref("ANY"))]);
        let err = format!(
            "{}",
            pod_envfile_path_passive("p", &refs, None).unwrap_err()
        );
        let empty: BTreeMap<String, SecretSource> = BTreeMap::new();
        let none = pod_envfile_path_passive("p", &empty, None).unwrap();
        if let Some(dir) = saved {
            std::env::set_var("XDG_RUNTIME_DIR", dir);
        }
        assert!(err.contains("XDG_RUNTIME_DIR"), "{err}");
        assert!(err.contains("p"), "{err}");
        assert!(none.is_none(), "secret-less pods get no envfile line");
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("run/nau/secrets");
        let some = pod_envfile_path_passive("p", &refs, Some(&base))
            .unwrap()
            .unwrap();
        let hash = decl_hash(&refs).unwrap();
        assert_eq!(some, base.join("p").join(format!("{hash}.env")));
    }

    // ── empty reference set + runtime-dir gate ──

    #[test]
    fn empty_reference_set_needs_no_runtime_dir_and_resolves_empty() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::remove_var("XDG_RUNTIME_DIR");
        let refs: BTreeMap<String, SecretSource> = BTreeMap::new();
        let values = resolve_references(Path::new("/nonexistent-pod"), "p", 3, &refs, None);
        if let Some(dir) = saved {
            std::env::set_var("XDG_RUNTIME_DIR", dir);
        }
        assert!(values.unwrap().is_empty());
    }

    #[test]
    fn xdg_runtime_dir_absent_is_a_hard_failure_naming_the_gap() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::remove_var("XDG_RUNTIME_DIR");
        let refs = BTreeMap::from([("K".to_string(), env_ref("ANY"))]);
        let err = format!(
            "{}",
            resolve_references(Path::new("/nonexistent-pod"), "p", 3, &refs, None).unwrap_err()
        );
        if let Some(dir) = saved {
            std::env::set_var("XDG_RUNTIME_DIR", dir);
        }
        assert!(err.contains("XDG_RUNTIME_DIR"), "{err}");
        assert!(err.contains("tmpfs"), "{err}");
    }

    #[test]
    fn tmpfs_gate_accepts_dev_shm_and_rejects_a_disk_dir() {
        assert!(is_tmpfs(Path::new("/dev/shm")).unwrap());
        assert!(
            !is_tmpfs(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap(),
            "the workspace is expected to sit on a non-tmpfs filesystem"
        );
    }

    // ── verbs: list ──

    /// A resolvable pod (env + exec only — warming must succeed
    /// all-or-nothing under D7) with its call counter path.
    fn list_fixture() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let counter = tmp.path().join("calls");
        let provider = counting_script(tmp.path(), &counter);
        seed_pod(
            tmp.path(),
            "work",
            &format!(
                r#"pod {{
    secrets = {{
        EXEC_VAR = {{ source = "exec", command = {{ "{provider}" }} }},
        ENV_VAR  = {{ source = "env", var = "NAU_SECRETS_TEST_LIST" }},
    }},
}}
"#
            ),
        );
        activate(tmp.path(), "work");
        (tmp, counter)
    }

    fn folded_refs(root: &Path, pod: &str) -> BTreeMap<String, SecretSource> {
        let decl = crate::pod::load_declaration(root, pod).unwrap();
        crate::pod::resolve_pod_secrets(root, pod, &decl).unwrap()
    }

    #[test]
    fn list_reports_references_and_cache_state_never_values() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, _counter) = list_fixture();
        let cache = tmp.path().join("cache");
        // Miss before resolve.
        let rows = list_pod(tmp.path(), "work", Some(&cache)).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.cache == "miss"));
        assert_eq!(
            rows.iter().find(|r| r.key == "ENV_VAR").unwrap().reference,
            "env NAU_SECRETS_TEST_LIST"
        );
        // Resolve (warms the entry at generation 3), then hit.
        std::env::set_var("NAU_SECRETS_TEST_LIST", SENTINEL);
        let refs = folded_refs(tmp.path(), "work");
        let pod_dir = tmp.path().join("work");
        resolve_references(&pod_dir, "work", 3, &refs, Some(&cache)).unwrap();
        let rows = list_pod(tmp.path(), "work", Some(&cache)).unwrap();
        assert!(rows.iter().all(|r| r.cache == "hit"));
        // An entry recorded for an older generation lists as stale.
        let hash = decl_hash(&refs).unwrap();
        write_cache_entry(
            &pod_cache_entry_path(&cache, "work", &hash),
            &CacheEntry {
                generation: 9,
                values: BTreeMap::new(),
            },
        )
        .unwrap();
        let rows = list_pod(tmp.path(), "work", Some(&cache)).unwrap();
        std::env::remove_var("NAU_SECRETS_TEST_LIST");
        assert!(rows.iter().all(|r| r.cache == "stale"));
        // The rendered output must not carry a single value substring.
        let text = render_list_rows("work", &rows);
        assert!(!text.contains(SENTINEL), "value leaked into list output");
        assert!(text.contains("EXEC_VAR") && text.contains("ENV_VAR"));
        assert!(text.contains("hit") && text.contains("stale"));
    }

    // ── vault (issue #186): loopback KV v2 harness ──

    /// One canned KV v2 response served over 127.0.0.1 HTTP on an
    /// OS-assigned port. Captures the request line and the
    /// `X-Vault-Token` header of the first request so a test can
    /// assert the exact wire shape. One request per connection, loop
    /// for the listener's life (the pod_declare source-server
    /// pattern); OpenBao compatibility rides the identical wire shape —
    /// no second live server.
    struct VaultServer {
        addr: String,
        captured: std::sync::Arc<std::sync::Mutex<Option<(String, String)>>>,
    }

    impl VaultServer {
        /// Bind, spawn the listener thread, answer every request with
        /// `status`/`body` (an HTTP status line reason + a JSON body).
        fn start(status: &str, body: &str) -> Self {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = format!("http://{}", listener.local_addr().unwrap());
            let canned = (status.to_string(), body.to_string());
            let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
            let slot = std::sync::Arc::clone(&captured);
            std::thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    vault_serve_one(stream, &canned, &slot);
                }
            });
            Self { addr, captured }
        }

        /// The first request's request line (`GET /v1/… HTTP/1.1`).
        fn request_line(&self) -> String {
            self.captured
                .lock()
                .unwrap()
                .as_ref()
                .map(|c| c.0.clone())
                .unwrap_or_default()
        }

        /// The first request's `X-Vault-Token` header value.
        fn token_header(&self) -> String {
            self.captured
                .lock()
                .unwrap()
                .as_ref()
                .map(|c| c.1.clone())
                .unwrap_or_default()
        }
    }

    /// Read one request head, capture request line + token header,
    /// answer with the canned response. Errors on the wire are
    /// swallowed — the test asserts through the capture.
    fn vault_serve_one(
        mut stream: std::net::TcpStream,
        canned: &(String, String),
        captured: &std::sync::Mutex<Option<(String, String)>>,
    ) {
        use std::io::{Read, Write};
        let mut data = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(n) = stream.read(&mut buf) {
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);
            if data.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let req = String::from_utf8_lossy(&data);
        let mut lines = req.split("\r\n");
        let request_line = lines.next().unwrap_or("").to_string();
        let token = lines
            .find_map(|l| {
                let (name, value) = l.split_once(':')?;
                name.eq_ignore_ascii_case("X-Vault-Token")
                    .then(|| value.trim().to_string())
            })
            .unwrap_or_default();
        *captured.lock().unwrap() = Some((request_line, token));
        let head = format!(
            "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            canned.0,
            canned.1.len()
        );
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(canned.1.as_bytes());
        let _ = stream.flush();
    }

    /// A KV v2 happy-path document with `field` under `.data.data`.
    fn vault_body(field_value: &str) -> String {
        format!(r#"{{"data":{{"data":{{"token":"{field_value}"}}}}}}"#)
    }

    fn vault_ref() -> SecretSource {
        SecretSource::Vault {
            mount: "secret".to_string(),
            path: "app".to_string(),
            field: "token".to_string(),
        }
    }

    fn vault_refs() -> BTreeMap<String, SecretSource> {
        BTreeMap::from([("V_TOKEN".to_string(), vault_ref())])
    }

    /// Scoped (VAULT_ADDR, VAULT_TOKEN) swap; restores on drop so a
    /// failing assert cannot poison the process env for sibling tests
    /// (every caller holds ENV_LOCK).
    struct VaultEnv {
        saved_addr: Option<String>,
        saved_token: Option<String>,
    }

    impl VaultEnv {
        /// `None` removes the variable; `Some` sets it.
        fn new(addr: Option<&str>, token: Option<&str>) -> Self {
            let saved_addr = std::env::var("VAULT_ADDR").ok();
            match addr {
                Some(a) => std::env::set_var("VAULT_ADDR", a),
                None => std::env::remove_var("VAULT_ADDR"),
            }
            let saved_token = std::env::var("VAULT_TOKEN").ok();
            match token {
                Some(t) => std::env::set_var("VAULT_TOKEN", t),
                None => std::env::remove_var("VAULT_TOKEN"),
            }
            Self {
                saved_addr,
                saved_token,
            }
        }
    }

    impl Drop for VaultEnv {
        fn drop(&mut self) {
            match self.saved_addr.take() {
                Some(a) => std::env::set_var("VAULT_ADDR", a),
                None => std::env::remove_var("VAULT_ADDR"),
            }
            match self.saved_token.take() {
                Some(t) => std::env::set_var("VAULT_TOKEN", t),
                None => std::env::remove_var("VAULT_TOKEN"),
            }
        }
    }

    #[test]
    fn vault_happy_path_reads_field_through_the_kv_v2_route() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let server = VaultServer::start("200 OK", &vault_body(SENTINEL));
        let _env = VaultEnv::new(Some(&server.addr), Some("caller-token"));
        let refs = vault_refs();
        let values = resolve_references(
            &pod,
            "p",
            3,
            &refs,
            Some(tmp.path().join("cache").as_path()),
        )
        .unwrap();
        assert_eq!(values.get("V_TOKEN").map(String::as_str), Some(SENTINEL));
        // The wire shape: KV v2 route + the token header.
        assert_eq!(server.request_line(), "GET /v1/secret/data/app HTTP/1.1");
        assert_eq!(server.token_header(), "caller-token");
    }

    #[test]
    fn vault_wrong_token_403_fails_named_and_the_body_never_leaks() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        // The canned body carries the sentinel AND the "wrong" token:
        // neither may reach the error string (D8).
        let server = VaultServer::start(
            "403 Forbidden",
            &format!("permission denied: {SENTINEL} token-t suspects"),
        );
        let _env = VaultEnv::new(Some(&server.addr), Some("wrong-token"));
        let err = format!(
            "{}",
            resolve_references(
                &pod,
                "p",
                3,
                &vault_refs(),
                Some(tmp.path().join("cache").as_path()),
            )
            .unwrap_err()
        );
        assert!(err.contains("403"), "{err}");
        assert!(err.contains("Forbidden"), "{err}");
        assert!(err.contains("source 'vault'"), "{err}");
        assert!(
            !err.contains(SENTINEL),
            "response body leaked into the error: {err}"
        );
        assert!(!err.contains("wrong-token"), "token leaked: {err}");
    }

    #[test]
    fn vault_missing_path_404_fails_named() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let server = VaultServer::start("404 Not Found", &format!("no such path {SENTINEL}"));
        let _env = VaultEnv::new(Some(&server.addr), Some("t"));
        let err = format!(
            "{}",
            resolve_references(
                &pod,
                "p",
                3,
                &vault_refs(),
                Some(tmp.path().join("cache").as_path()),
            )
            .unwrap_err()
        );
        assert!(err.contains("404"), "{err}");
        assert!(
            !err.contains(SENTINEL),
            "response body leaked into the error: {err}"
        );
    }

    #[test]
    fn vault_missing_field_fails_named() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        // The sentinel hides in a DIFFERENT field of the same secret.
        let body = format!(r#"{{"data":{{"data":{{"other":"{SENTINEL}"}}}}}}"#);
        let server = VaultServer::start("200 OK", &body);
        let _env = VaultEnv::new(Some(&server.addr), Some("t"));
        let err = format!(
            "{}",
            resolve_references(
                &pod,
                "p",
                3,
                &vault_refs(),
                Some(tmp.path().join("cache").as_path()),
            )
            .unwrap_err()
        );
        assert!(err.contains("no 'token' field"), "{err}");
        assert!(
            !err.contains(SENTINEL),
            "other field's value leaked into the error: {err}"
        );
    }

    #[test]
    fn vault_non_string_field_fails_named() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let body = format!(r#"{{"data":{{"data":{{"token":42,"other":"{SENTINEL}"}}}}}}"#);
        let server = VaultServer::start("200 OK", &body);
        let _env = VaultEnv::new(Some(&server.addr), Some("t"));
        let err = format!(
            "{}",
            resolve_references(
                &pod,
                "p",
                3,
                &vault_refs(),
                Some(tmp.path().join("cache").as_path()),
            )
            .unwrap_err()
        );
        assert!(err.contains("not a string"), "{err}");
        assert!(!err.contains(SENTINEL), "value leaked: {err}");
    }

    #[test]
    fn vault_empty_field_fails_named_never_an_empty_value() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let server = VaultServer::start("200 OK", &vault_body(""));
        let _env = VaultEnv::new(Some(&server.addr), Some("t"));
        let err = format!(
            "{}",
            resolve_references(
                &pod,
                "p",
                3,
                &vault_refs(),
                Some(tmp.path().join("cache").as_path()),
            )
            .unwrap_err()
        );
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn vault_malformed_json_body_fails_named() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let server = VaultServer::start("200 OK", &format!("totally not json {SENTINEL}"));
        let _env = VaultEnv::new(Some(&server.addr), Some("t"));
        let err = format!(
            "{}",
            resolve_references(
                &pod,
                "p",
                3,
                &vault_refs(),
                Some(tmp.path().join("cache").as_path()),
            )
            .unwrap_err()
        );
        assert!(err.contains("not valid JSON"), "{err}");
        assert!(
            !err.contains(SENTINEL),
            "body content leaked into the error: {err}"
        );
    }

    #[test]
    fn vault_data_levels_missing_or_non_object_fail_named() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let cases: [(&str, String); 4] = [
            ("no .data", "{}".to_string()),
            (".data not an object", r#"{"data":42}"#.to_string()),
            (
                "no .data.data",
                r#"{"data":{"metadata":{"version":2}}}"#.to_string(),
            ),
            (
                ".data.data not an object",
                r#"{"data":{"data":"flat"}}"#.to_string(),
            ),
        ];
        for (what, body) in cases {
            let server = VaultServer::start("200 OK", &body);
            let _env = VaultEnv::new(Some(&server.addr), Some("t"));
            let err = format!(
                "{}",
                resolve_references(
                    &pod,
                    "p",
                    3,
                    &vault_refs(),
                    Some(tmp.path().join("cache").as_path()),
                )
                .unwrap_err()
            );
            assert!(
                err.contains(".data"),
                "{what}: failure must name the JSON shape: {err}"
            );
        }
    }

    #[test]
    fn vault_trailing_slash_addr_is_normalized_before_joining() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let server = VaultServer::start("200 OK", &vault_body(SENTINEL));
        // A double slash would hit /v1//secret/... and 404 on real
        // Vault — the normalization must prevent it.
        let _env = VaultEnv::new(Some(&format!("{}/", server.addr)), Some("t"));
        resolve_references(
            &pod,
            "p",
            3,
            &vault_refs(),
            Some(tmp.path().join("cache").as_path()),
        )
        .unwrap();
        assert_eq!(
            server.request_line(),
            "GET /v1/secret/data/app HTTP/1.1",
            "no doubled slash in the request line"
        );
    }

    #[test]
    fn vault_addr_and_token_missing_or_empty_fail_named_separately() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let resolve_err = || -> String {
            format!(
                "{}",
                resolve_references(
                    &pod,
                    "p",
                    3,
                    &vault_refs(),
                    Some(tmp.path().join("cache").as_path()),
                )
                .unwrap_err()
            )
        };
        // (a) both unset → the ADDR failure is named first.
        let _env = VaultEnv::new(None, None);
        let err = resolve_err();
        assert!(err.contains("VAULT_ADDR is not set"), "{err}");
        assert!(!err.contains("VAULT_TOKEN"), "{err}");
        // (b) addr set, token unset → the TOKEN failure, distinctly.
        let _env = VaultEnv::new(Some("http://127.0.0.1:1"), None);
        let err = resolve_err();
        assert!(err.contains("VAULT_TOKEN is not set"), "{err}");
        assert!(
            !err.contains("VAULT_ADDR"),
            "the addr failure must not be named for a token failure: {err}"
        );
        // (c) addr set-but-empty.
        let _env = VaultEnv::new(Some(""), Some("t"));
        let err = resolve_err();
        assert!(err.contains("VAULT_ADDR is set but empty"), "{err}");
        // (d) token set-but-empty.
        let _env = VaultEnv::new(Some("http://127.0.0.1:1"), Some(""));
        let err = resolve_err();
        assert!(err.contains("VAULT_TOKEN is set but empty"), "{err}");
    }

    #[test]
    fn vault_transport_failure_fails_named_without_touching_values() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        // Port 1: nothing listens — a fast, deterministic refusal.
        let _env = VaultEnv::new(Some("http://127.0.0.1:1"), Some("t"));
        let err = format!(
            "{}",
            resolve_references(
                &pod,
                "p",
                3,
                &vault_refs(),
                Some(tmp.path().join("cache").as_path()),
            )
            .unwrap_err()
        );
        assert!(err.contains("transport failure"), "{err}");
        assert!(err.contains("source 'vault'"), "{err}");
    }

    #[test]
    fn vault_interior_newlines_in_the_value_survive() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let body = r#"{"data":{"data":{"token":"-----BEGIN\nLINE2\n-----END"}}}"#;
        let server = VaultServer::start("200 OK", body);
        let _env = VaultEnv::new(Some(&server.addr), Some("t"));
        let values = resolve_references(
            &pod,
            "p",
            3,
            &vault_refs(),
            Some(tmp.path().join("cache").as_path()),
        )
        .unwrap();
        assert_eq!(
            values.get("V_TOKEN").map(String::as_str),
            Some("-----BEGIN\nLINE2\n-----END"),
            "PEM shape rides verbatim (ADR-0042 D4)"
        );
    }

    // ── verbs: check ──

    /// A pod whose references cover the check statuses: vault resolves
    /// through the loopback KV v2 server (issue #186 — every D4 source
    /// is live), a failing env var, and a working exec provider. The
    /// server and the (VAULT_ADDR, VAULT_TOKEN) env swap live as long
    /// as the returned tuple.
    fn check_fixture() -> (tempfile::TempDir, VaultServer, VaultEnv) {
        let tmp = tempfile::tempdir().unwrap();
        let provider = script(
            tmp.path(),
            "ok-provider",
            &format!("printf '{SENTINEL}\\n'\n"),
        );
        seed_pod(
            tmp.path(),
            "work",
            &format!(
                r#"pod {{
    secrets = {{
        VAULT_ITEM = {{ source = "vault", mount = "secret", path = "app", field = "token" }},
        ENV_VAR    = {{ source = "env", var = "NAU_SECRETS_TEST_CHECK" }},
        EXEC_VAR   = {{ source = "exec", command = {{ "{provider}" }} }},
    }},
}}
"#
            ),
        );
        activate(tmp.path(), "work");
        let server = VaultServer::start("200 OK", &vault_body(SENTINEL));
        let env = VaultEnv::new(Some(&server.addr), Some("caller-token"));
        (tmp, server, env)
    }

    #[test]
    fn check_reports_per_source_health_and_fails_named() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, server, _env) = check_fixture();
        std::env::remove_var("NAU_SECRETS_TEST_CHECK");
        let rows = check_pod(tmp.path(), "work").unwrap();
        assert_eq!(rows.len(), 3);
        let by_key = |k: &str| rows.iter().find(|r| r.key == k).unwrap();
        assert_eq!(by_key("VAULT_ITEM").status, "ok");
        assert_eq!(by_key("ENV_VAR").status, "failed");
        assert!(
            by_key("ENV_VAR").note.contains("NAU_SECRETS_TEST_CHECK"),
            "{}",
            by_key("ENV_VAR").note
        );
        assert_eq!(by_key("EXEC_VAR").status, "ok");
        assert!(!check_healthy(&rows), "a failing reference means exit 1");
        // The vault probe really hit the KV v2 route with the token header.
        assert_eq!(server.request_line(), "GET /v1/secret/data/app HTTP/1.1");
        assert_eq!(server.token_header(), "caller-token");
        // No value reaches any report row (D8).
        let text = render_check_rows("work", &rows);
        assert!(!text.contains(SENTINEL), "value leaked into check output");
        // Everything goes green once the env var exists (exit-0 shape).
        std::env::set_var("NAU_SECRETS_TEST_CHECK", SENTINEL);
        let rows = check_pod(tmp.path(), "work").unwrap();
        std::env::remove_var("NAU_SECRETS_TEST_CHECK");
        assert!(
            check_healthy(&rows),
            "all three D4 sources are live → exit 0: {rows:?}"
        );
        assert!(
            !render_check_rows("work", &rows).contains(SENTINEL),
            "value leaked into check output"
        );
    }

    #[test]
    fn verbs_refuse_unknown_pods_and_generation_less_pods() {
        let tmp = tempfile::tempdir().unwrap();
        let err = format!(
            "{}",
            list_pod(
                tmp.path(),
                "ghost",
                Some(tmp.path().join("cache").as_path())
            )
            .unwrap_err()
        );
        assert!(err.contains("has no state"), "{err}");
        seed_pod(tmp.path(), "cold", "pod {}");
        let err = format!(
            "{}",
            list_pod(tmp.path(), "cold", Some(tmp.path().join("cache").as_path())).unwrap_err()
        );
        assert!(err.contains("no active generation"), "{err}");
    }

    #[test]
    fn refresh_with_no_references_needs_no_runtime_dir() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::remove_var("XDG_RUNTIME_DIR");
        let tmp = tempfile::tempdir().unwrap();
        seed_pod(tmp.path(), "cold", "pod {}");
        activate(tmp.path(), "cold");
        let report = refresh_pod(
            tmp.path(),
            "cold",
            None,
            &crate::runtime::RuntimeTools::default(),
        );
        if let Some(dir) = saved {
            std::env::set_var("XDG_RUNTIME_DIR", dir);
        }
        assert_eq!(report.unwrap(), SecretsRefreshReport::default());
    }

    // ── bitwarden (issue #185): fake bws on the host PATH ──

    /// Scoped (PATH, BWS_ACCESS_TOKEN) swap; restores on drop so a
    /// failing assert cannot poison the process env for sibling tests
    /// (every caller holds ENV_LOCK).
    struct BwsEnv {
        saved_path: Option<String>,
        saved_token: Option<String>,
    }

    impl BwsEnv {
        /// Put the fake bws dir FIRST on PATH (ambient PATH entries stay
        /// — concurrent spawn-heavy tests must keep finding git/cat).
        fn new(bws_dir: &Path, token: Option<&str>) -> Self {
            let saved_path = std::env::var("PATH").ok();
            let path = match &saved_path {
                Some(p) => format!("{}:{}", bws_dir.display(), p),
                None => bws_dir.display().to_string(),
            };
            std::env::set_var("PATH", &path);
            let saved_token = std::env::var("BWS_ACCESS_TOKEN").ok();
            match token {
                Some(t) => std::env::set_var("BWS_ACCESS_TOKEN", t),
                None => std::env::remove_var("BWS_ACCESS_TOKEN"),
            }
            Self {
                saved_path,
                saved_token,
            }
        }

        /// Full PATH replacement — only for the not-found case, where
        /// `bws` must be ABSENT from every entry.
        fn path_without_bws(dir: &Path, token: Option<&str>) -> Self {
            let saved_path = std::env::var("PATH").ok();
            std::env::set_var("PATH", dir);
            let saved_token = std::env::var("BWS_ACCESS_TOKEN").ok();
            match token {
                Some(t) => std::env::set_var("BWS_ACCESS_TOKEN", t),
                None => std::env::remove_var("BWS_ACCESS_TOKEN"),
            }
            Self {
                saved_path,
                saved_token,
            }
        }
    }

    impl Drop for BwsEnv {
        fn drop(&mut self) {
            match self.saved_path.take() {
                Some(p) => std::env::set_var("PATH", p),
                None => std::env::remove_var("PATH"),
            }
            match self.saved_token.take() {
                Some(t) => std::env::set_var("BWS_ACCESS_TOKEN", t),
                None => std::env::remove_var("BWS_ACCESS_TOKEN"),
            }
        }
    }

    /// The fake bws: counts its call (the counting-provider pattern),
    /// prints the canned body plus a trailing newline (the trim case),
    /// exits with the given status. The body must not carry single
    /// quotes (it is spliced into a shell literal).
    fn bws_script(dir: &Path, body: &str, exit: u32, counter: Option<&Path>) -> String {
        let count = match counter {
            Some(c) => format!(
                "n=$(cat {} 2>/dev/null || echo 0); echo $((n+1)) > {}; ",
                c.display(),
                c.display()
            ),
            None => String::new(),
        };
        script(
            dir,
            "bws",
            &format!("{count}printf '%s\\n' '{body}'\nexit {exit}\n"),
        )
    }

    fn bitwarden_ref(id: &str) -> SecretSource {
        SecretSource::Bitwarden { id: id.to_string() }
    }

    fn bitwarden_refs(id: &str) -> BTreeMap<String, SecretSource> {
        BTreeMap::from([("BW_TOKEN".to_string(), bitwarden_ref(id))])
    }

    #[test]
    fn bitwarden_happy_path_extracts_the_json_value_field() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let counter = tmp.path().join("calls");
        let body = format!(r#"{{"id":"8848da48","value":"{SENTINEL}"}}"#);
        let _bws = bws_script(tmp.path(), &body, 0, Some(&counter));
        let _env = BwsEnv::new(tmp.path(), Some("caller-token"));
        let refs = bitwarden_refs("8848da48");
        let values = resolve_references(
            &pod,
            "p",
            3,
            &refs,
            Some(tmp.path().join("cache").as_path()),
        )
        .unwrap();
        assert_eq!(values.get("BW_TOKEN").map(String::as_str), Some(SENTINEL));
        assert_eq!(calls(&counter), 1, "exactly one bws invocation");
    }

    #[test]
    fn bitwarden_calls_bws_with_the_exact_argv_shape() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let argv = tmp.path().join("argv");
        let body = r#"{"value":"v"}"#;
        script(
            tmp.path(),
            "bws",
            &format!(
                "printf '%s ' \"$@\" > {}\nprintf '%s\\n' '{body}'\n",
                argv.display()
            ),
        );
        let _env = BwsEnv::new(tmp.path(), Some("t"));
        let refs = bitwarden_refs("8848da48-aa");
        resolve_references(
            &pod,
            "p",
            3,
            &refs,
            Some(tmp.path().join("cache").as_path()),
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(&argv).unwrap(),
            "secret get 8848da48-aa ",
            "`bws secret get <id>` — argv array, no shell, no extra words"
        );
    }

    #[test]
    fn bitwarden_interior_newlines_in_the_value_survive() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        // The \n inside the literal is the JSON escape: the parsed
        // value carries the real newline (PEM shape). Only the stdout
        // EDGES are trimmed.
        let _bws = bws_script(tmp.path(), r#"{"value":"line1\nline2"}"#, 0, None);
        let _env = BwsEnv::new(tmp.path(), Some("t"));
        let refs = bitwarden_refs("x");
        let values = resolve_references(
            &pod,
            "p",
            3,
            &refs,
            Some(tmp.path().join("cache").as_path()),
        )
        .unwrap();
        assert_eq!(
            values.get("BW_TOKEN").map(String::as_str),
            Some("line1\nline2")
        );
    }

    #[test]
    fn bitwarden_nonzero_exit_fails_named_and_suppresses_stderr() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        // The failing fake leaks the sentinel on BOTH stderr and
        // stdout — neither may reach our error (D8).
        script(
            tmp.path(),
            "bws",
            &format!("printf '{SENTINEL}' >&2\nprintf '{SENTINEL}'\nexit 3\n"),
        );
        let _env = BwsEnv::new(tmp.path(), Some("t"));
        let refs = bitwarden_refs("8848da48");
        let err = format!(
            "{}",
            resolve_references(
                &pod,
                "p",
                3,
                &refs,
                Some(tmp.path().join("cache").as_path())
            )
            .unwrap_err()
        );
        assert!(err.contains("secret 'BW_TOKEN'"), "{err}");
        assert!(err.contains("source 'bitwarden'"), "{err}");
        assert!(err.contains("exited with"), "{err}");
        assert!(err.contains("3"), "exit status not named: {err}");
        assert!(!err.contains(SENTINEL), "provider output leaked: {err}");
    }

    #[test]
    fn bitwarden_malformed_json_fails_named() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let _bws = bws_script(tmp.path(), "not json at all", 0, None);
        let _env = BwsEnv::new(tmp.path(), Some("t"));
        let refs = bitwarden_refs("x");
        let err = format!(
            "{}",
            resolve_references(
                &pod,
                "p",
                3,
                &refs,
                Some(tmp.path().join("cache").as_path())
            )
            .unwrap_err()
        );
        assert!(err.contains("valid JSON"), "{err}");
        assert!(err.contains("source 'bitwarden'"), "{err}");
    }

    #[test]
    fn bitwarden_missing_value_field_fails_named() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let _bws = bws_script(tmp.path(), r#"{"id":"8848"}"#, 0, None);
        let _env = BwsEnv::new(tmp.path(), Some("t"));
        let refs = bitwarden_refs("x");
        let err = format!(
            "{}",
            resolve_references(
                &pod,
                "p",
                3,
                &refs,
                Some(tmp.path().join("cache").as_path())
            )
            .unwrap_err()
        );
        assert!(err.contains("no '.value'"), "{err}");
    }

    #[test]
    fn bitwarden_non_string_value_fails_named() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let _bws = bws_script(tmp.path(), r#"{"value":42}"#, 0, None);
        let _env = BwsEnv::new(tmp.path(), Some("t"));
        let refs = bitwarden_refs("x");
        let err = format!(
            "{}",
            resolve_references(
                &pod,
                "p",
                3,
                &refs,
                Some(tmp.path().join("cache").as_path())
            )
            .unwrap_err()
        );
        assert!(err.contains("not a string"), "{err}");
    }

    #[test]
    fn bitwarden_empty_value_fails_named_never_an_empty_secret() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let _bws = bws_script(tmp.path(), r#"{"value":""}"#, 0, None);
        let _env = BwsEnv::new(tmp.path(), Some("t"));
        let refs = bitwarden_refs("x");
        let err = format!(
            "{}",
            resolve_references(
                &pod,
                "p",
                3,
                &refs,
                Some(tmp.path().join("cache").as_path())
            )
            .unwrap_err()
        );
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn bitwarden_missing_token_fails_named_before_bws_runs() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let counter = tmp.path().join("calls");
        let body = format!(r#"{{"value":"{SENTINEL}"}}"#);
        let _bws = bws_script(tmp.path(), &body, 0, Some(&counter));
        let _env = BwsEnv::new(tmp.path(), None);
        let refs = bitwarden_refs("8848da48");
        let err = format!(
            "{}",
            resolve_references(
                &pod,
                "p",
                3,
                &refs,
                Some(tmp.path().join("cache").as_path())
            )
            .unwrap_err()
        );
        assert!(err.contains("BWS_ACCESS_TOKEN"), "{err}");
        assert!(err.contains("not set"), "{err}");
        assert!(
            !counter.is_file(),
            "the counter stays unwritten — bws must not run without a token"
        );
        assert!(!err.contains(SENTINEL), "{err}");
    }

    #[test]
    fn bitwarden_empty_token_fails_named() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let _bws = bws_script(tmp.path(), r#"{"value":"v"}"#, 0, None);
        let _env = BwsEnv::new(tmp.path(), Some(""));
        let refs = bitwarden_refs("x");
        let err = format!(
            "{}",
            resolve_references(
                &pod,
                "p",
                3,
                &refs,
                Some(tmp.path().join("cache").as_path())
            )
            .unwrap_err()
        );
        assert!(err.contains("BWS_ACCESS_TOKEN"), "{err}");
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn bitwarden_bws_missing_from_the_host_path_fails_named() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let empty = tempfile::tempdir().unwrap();
        let _env = BwsEnv::path_without_bws(empty.path(), Some("t"));
        let refs = bitwarden_refs("x");
        let err = format!(
            "{}",
            resolve_references(
                &pod,
                "p",
                3,
                &refs,
                Some(tmp.path().join("cache").as_path())
            )
            .unwrap_err()
        );
        assert!(err.contains("not found on the host PATH"), "{err}");
        assert!(err.contains("'bws'"), "{err}");
        assert!(err.contains("source 'bitwarden'"), "{err}");
    }

    // ── libsecret (issue #185): the Secret Service seam fake ──

    /// In-memory stand-in for the session-bus keyring, keyed by the
    /// EXACT attribute map. ENV_LOCK serializes all users.
    static FAKE_STORE: Mutex<BTreeMap<BTreeMap<String, String>, Vec<u8>>> =
        Mutex::new(BTreeMap::new());

    fn fake_lookup(attributes: &BTreeMap<String, String>) -> miette::Result<Option<Vec<u8>>> {
        Ok(FAKE_STORE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(attributes)
            .cloned())
    }

    fn failing_lookup(_attributes: &BTreeMap<String, String>) -> miette::Result<Option<Vec<u8>>> {
        miette::bail!("secret service: bus hole (injected transport failure)")
    }

    /// Swap the seam; returns the previous fn for restoration.
    fn reseat_lookup(f: AttributeLookup) -> AttributeLookup {
        // The seam static is crate-private in nau-pod (issue #326 PR 6);
        // the root suite swaps it through the doc-hidden reseat helper.
        nau_pod::secrets::reseat_secret_service_lookup(f)
    }

    fn seed_fake_store(pairs: &[(&str, &str)], value: &[u8]) -> BTreeMap<String, String> {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        FAKE_STORE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(map.clone(), value.to_vec());
        map
    }

    fn libsecret_ref(pairs: &[(&str, &str)]) -> SecretSource {
        SecretSource::Libsecret {
            attributes: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn libsecret_set_then_resolve_round_trips_through_the_seam() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let attrs = seed_fake_store(&[("bitwarden", "sm-access-token")], SENTINEL.as_bytes());
        let previous = reseat_lookup(fake_lookup);
        let refs = BTreeMap::from([(
            "LS_TOKEN".to_string(),
            SecretSource::Libsecret { attributes: attrs },
        )]);
        let values = resolve_references(
            &pod,
            "p",
            3,
            &refs,
            Some(tmp.path().join("cache").as_path()),
        )
        .unwrap();
        reseat_lookup(previous);
        FAKE_STORE.lock().unwrap_or_else(|e| e.into_inner()).clear();
        assert_eq!(
            values.get("LS_TOKEN").map(String::as_str),
            Some(SENTINEL),
            "the setup-bws interop shape reads back through the seam"
        );
    }

    #[test]
    fn libsecret_missing_entry_fails_named_and_distinct_from_transport() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let previous = reseat_lookup(fake_lookup);
        // (a) No such entry — the store is empty.
        let refs = BTreeMap::from([(
            "LS_TOKEN".to_string(),
            libsecret_ref(&[("bitwarden", "no-such-token")]),
        )]);
        let err = format!(
            "{}",
            resolve_references(
                &pod,
                "p",
                3,
                &refs,
                Some(tmp.path().join("cache").as_path())
            )
            .unwrap_err()
        );
        assert!(err.contains("no Secret Service entry matches"), "{err}");
        assert!(err.contains("LS_TOKEN"), "{err}");
        assert!(err.contains("source 'libsecret'"), "{err}");
        // (b) Transport failure — a DIFFERENT named failure.
        reseat_lookup(failing_lookup);
        let refs = BTreeMap::from([(
            "LS_TOKEN".to_string(),
            libsecret_ref(&[("bitwarden", "sm-access-token")]),
        )]);
        let err = format!(
            "{}",
            resolve_references(
                &pod,
                "p",
                3,
                &refs,
                Some(tmp.path().join("cache").as_path())
            )
            .unwrap_err()
        );
        reseat_lookup(previous);
        FAKE_STORE.lock().unwrap_or_else(|e| e.into_inner()).clear();
        assert!(err.contains("bus hole"), "{err}");
        assert!(!err.contains("no Secret Service entry"), "{err}");
    }

    #[test]
    fn libsecret_non_utf8_and_empty_content_fail_named_without_the_content() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pod = pod_state_root(tmp.path());
        let previous = reseat_lookup(fake_lookup);
        let non_utf8 = seed_fake_store(&[("k", "non-utf8")], &[0xff, 0xfe]);
        let refs = BTreeMap::from([(
            "LS_TOKEN".to_string(),
            SecretSource::Libsecret {
                attributes: non_utf8,
            },
        )]);
        let err = format!(
            "{}",
            resolve_references(
                &pod,
                "p",
                3,
                &refs,
                Some(tmp.path().join("cache").as_path())
            )
            .unwrap_err()
        );
        assert!(err.contains("not UTF-8"), "{err}");
        let empty = seed_fake_store(&[("k", "empty")], &[]);
        let refs = BTreeMap::from([(
            "LS_TOKEN".to_string(),
            SecretSource::Libsecret { attributes: empty },
        )]);
        let err = format!(
            "{}",
            resolve_references(
                &pod,
                "p",
                3,
                &refs,
                Some(tmp.path().join("cache").as_path())
            )
            .unwrap_err()
        );
        reseat_lookup(previous);
        FAKE_STORE.lock().unwrap_or_else(|e| e.into_inner()).clear();
        assert!(err.contains("empty"), "{err}");
    }

    /// Live-bus gate: NAU_SECRETS_LIVE_DBUS=1 opts into a REAL
    /// session bus + unlocked keyring. Writes a uniquely-attributed
    /// item, reads it back through the PRODUCTION seam fn, deletes it.
    #[test]
    fn live_dbus_secret_service_round_trip_when_gated_on() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if std::env::var("NAU_SECRETS_LIVE_DBUS").as_deref() != Ok("1") {
            return;
        }
        use dbus_secret_service::{EncryptionType, SecretService};
        let attrs: BTreeMap<String, String> = BTreeMap::from([
            ("nau-test".to_string(), "issue-185".to_string()),
            ("nonce".to_string(), std::process::id().to_string()),
        ]);
        let pairs: std::collections::HashMap<&str, &str> = attrs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let service = SecretService::connect(EncryptionType::Dh).unwrap();
        let collection = service.get_default_collection().unwrap();
        let item = collection
            .create_item(
                "nau issue-185 live test",
                pairs,
                SENTINEL.as_bytes(),
                true,
                "text/plain",
            )
            .unwrap();
        let found = secret_service_lookup(&attrs).unwrap();
        item.delete().unwrap();
        assert_eq!(found.as_deref(), Some(SENTINEL.as_bytes()));
    }

    // ── pod secrets check end-to-end (issue #185 scope 5, #186) ──

    /// One pod, three sources: bitwarden resolves through the fake bws,
    /// libsecret through the seam fake, vault through the loopback KV v2
    /// server — every D4 source is live since #186, so the healthy row
    /// set is the exit-0 shape.
    #[test]
    fn check_pod_end_to_end_bitwarden_libsecret_vault_ok_exit_0() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        seed_pod(
            tmp.path(),
            "work",
            r#"pod {
    secrets = {
        BW_ITEM    = { source = "bitwarden", id = "8848da48" },
        LS_TOKEN   = { source = "libsecret", attributes = { bitwarden = "sm-access-token" } },
        VAULT_ITEM = { source = "vault", mount = "secret", path = "app", field = "token" },
    },
}
"#,
        );
        activate(tmp.path(), "work");
        let body = format!(r#"{{"value":"{SENTINEL}"}}"#);
        let _bws = bws_script(tmp.path(), &body, 0, None);
        let _env = BwsEnv::new(tmp.path(), Some("caller-token"));
        let server = VaultServer::start("200 OK", &vault_body(SENTINEL));
        let _venv = VaultEnv::new(Some(&server.addr), Some("vault-caller-token"));
        let previous = reseat_lookup(fake_lookup);
        seed_fake_store(&[("bitwarden", "sm-access-token")], b"ring-stored");
        let rows = check_pod(tmp.path(), "work").unwrap();
        reseat_lookup(previous);
        FAKE_STORE.lock().unwrap_or_else(|e| e.into_inner()).clear();
        let by_key = |k: &str| rows.iter().find(|r| r.key == k).unwrap();
        assert_eq!(by_key("BW_ITEM").status, "ok");
        assert_eq!(by_key("LS_TOKEN").status, "ok");
        assert_eq!(by_key("VAULT_ITEM").status, "ok");
        assert!(check_healthy(&rows), "every D4 source live → exit 0");
        // The vault probe hit the KV v2 route with the token header.
        assert_eq!(server.request_line(), "GET /v1/secret/data/app HTTP/1.1");
        assert_eq!(server.token_header(), "vault-caller-token");
        // No resolved value reaches any check output (D8).
        let text = render_check_rows("work", &rows);
        assert!(!text.contains(SENTINEL), "bitwarden value leaked: {text}");
        assert!(
            !text.contains("ring-stored"),
            "keyring value leaked: {text}"
        );
    }

    /// The exit-1 shape survives #186 — the stub row is gone, so its
    /// story re-points at the transport-failure path: a dead
    /// VAULT_ADDR fails its row named while the other two stay green.
    #[test]
    fn check_pod_end_to_end_vault_transport_failure_is_the_exit_1_shape() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        seed_pod(
            tmp.path(),
            "work",
            r#"pod {
    secrets = {
        BW_ITEM    = { source = "bitwarden", id = "8848da48" },
        LS_TOKEN   = { source = "libsecret", attributes = { bitwarden = "sm-access-token" } },
        VAULT_ITEM = { source = "vault", mount = "secret", path = "app", field = "token" },
    },
}
"#,
        );
        activate(tmp.path(), "work");
        let body = format!(r#"{{"value":"{SENTINEL}"}}"#);
        let _bws = bws_script(tmp.path(), &body, 0, None);
        let _env = BwsEnv::new(tmp.path(), Some("caller-token"));
        // Port 1: nothing listens there — connection refused.
        let _venv = VaultEnv::new(Some("http://127.0.0.1:1"), Some("t"));
        let previous = reseat_lookup(fake_lookup);
        seed_fake_store(&[("bitwarden", "sm-access-token")], b"ring-stored");
        let rows = check_pod(tmp.path(), "work").unwrap();
        reseat_lookup(previous);
        FAKE_STORE.lock().unwrap_or_else(|e| e.into_inner()).clear();
        let by_key = |k: &str| rows.iter().find(|r| r.key == k).unwrap();
        assert_eq!(by_key("BW_ITEM").status, "ok");
        assert_eq!(by_key("LS_TOKEN").status, "ok");
        let vault = by_key("VAULT_ITEM");
        assert_eq!(vault.status, "failed");
        assert!(vault.note.contains("transport failure"), "{}", vault.note);
        assert!(!check_healthy(&rows), "this row set is the exit-1 shape");
        // The transport failure text carries no values (D8).
        let text = render_check_rows("work", &rows);
        assert!(!text.contains(SENTINEL), "value leaked: {text}");
        assert!(
            !text.contains("ring-stored"),
            "keyring value leaked: {text}"
        );
    }
}
