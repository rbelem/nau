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
mod tests;
