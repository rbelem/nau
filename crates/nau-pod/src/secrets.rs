//! Pod secret resolution (ADR-0042, issue #183) — the ONE resolve entry
//! point that turns a folded reference set
//! (`BTreeMap<String, pod::SecretSource>`, exactly the `secrets.json`
//! record) into values, plus the session-cache/serve machinery behind
//! `nau run`, the shellenv, and the sync-time envfile hygiene.
//!
//! Issue #326 PR 6 (crate extraction): this crate side hosts the
//! RESOLVE half — the provider registry, the reference resolution walk,
//! the decl-hash cache, the serve/envfile layer, and the
//! `SecretSource` grammar type (re-exported by this crate's `pod`
//! module, whose `PodDeclaration` carries it). The `pod secrets`
//! VERBS (list/check/refresh — eval- and systemd-coupled) stay in the
//! root crate's `secrets` module, which re-exports everything here.
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
use std::sync::Mutex;

use nau_infra::tools::{FETCH_CONNECT_TIMEOUT, FETCH_TOTAL_TIMEOUT};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── The reference grammar (moved from the root pod module, PR 6) ──

/// A declared secret reference (ADR-0042 D1/D4): which built-in
/// provider serves the value and what identifies it. Declarations carry
/// references only — a value never exists at parse, fold, or
/// generation-record time (D2); it resolves at serve time (D3). The
/// serialized shape is the `secrets.json` record shape: tagged by
/// `source`, keys canonical from the map's sorted iteration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "lowercase")]
pub enum SecretSource {
    /// Bitwarden Secrets Manager: `bws secret get <id>`, read `.value`.
    Bitwarden { id: String },
    /// Vault/OpenBao KV v2: `GET /v1/{mount}/data/{path}`, field `field`.
    Vault {
        mount: String,
        path: String,
        field: String,
    },
    /// Secret Service (libsecret): at least one attribute pair selects
    /// the item.
    Libsecret {
        attributes: BTreeMap<String, String>,
    },
    /// Arbitrary provider via argv — an array of non-empty strings,
    /// never a shell string. Run, trim stdout.
    Exec { command: Vec<String> },
    /// The caller's environment: read `var` at serve time.
    Env { var: String },
}

/// Pub for the root verb layer (`pod secrets check` names each key's
/// source); internals, not API.
#[doc(hidden)]
pub fn source_name(source: &SecretSource) -> &'static str {
    match source {
        SecretSource::Bitwarden { .. } => "bitwarden",
        SecretSource::Vault { .. } => "vault",
        SecretSource::Libsecret { .. } => "libsecret",
        SecretSource::Exec { .. } => "exec",
        SecretSource::Env { .. } => "env",
    }
}

// ── Resolution (D3/D7) ──

/// Resolve every folded reference to its live value. All-or-nothing
/// (D7): the first failure fails the whole resolve naming the key and
/// source. Cache-aware per D3; `cache_base_override` redirects the
/// `$XDG_RUNTIME_DIR`-derived base (tests; the override skips the tmpfs
/// gate — its caller owns the location choice).
pub fn resolve_references(
    pod_dir: &Path,
    pod_name: &str,
    generation: u64,
    refs: &BTreeMap<String, SecretSource>,
    cache_base_override: Option<&Path>,
) -> miette::Result<BTreeMap<String, String>> {
    if refs.is_empty() {
        // D3's empty rule: no references, no cache interaction, no
        // tmpfs requirement — an empty resolve needs no runtime dir.
        return Ok(BTreeMap::new());
    }
    let base = cache_base(cache_base_override)?;
    let entry_path = pod_cache_entry_path(&base, pod_name, &decl_hash(refs)?);
    if let Some(entry) = read_cache_entry(&entry_path)? {
        return Ok(entry.values);
    }
    let values = resolve_all(pod_dir, refs)?;
    write_cache_entry(
        &entry_path,
        &CacheEntry {
            generation,
            values: values.clone(),
        },
    )?;
    Ok(values)
}

/// Resolve every reference, failing on the first failure (D7): the map
/// only materializes when every key resolved.
fn resolve_all(
    pod_dir: &Path,
    refs: &BTreeMap<String, SecretSource>,
) -> miette::Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for (key, source) in refs {
        values.insert(key.clone(), resolve_one(pod_dir, key, source)?);
    }
    Ok(values)
}

/// The provider dispatch proper (D4: match-based, grows by arms).
/// Pub for the root verb layer (`pod secrets check` probes per key);
/// internals, not API.
#[doc(hidden)]
pub fn resolve_one(pod_dir: &Path, key: &str, source: &SecretSource) -> miette::Result<String> {
    match source {
        SecretSource::Env { var } => resolve_env(key, var),
        SecretSource::Exec { command } => resolve_exec(pod_dir, key, command),
        SecretSource::Bitwarden { id } => resolve_bitwarden(pod_dir, key, id),
        SecretSource::Libsecret { attributes } => resolve_libsecret(key, attributes),
        SecretSource::Vault { mount, path, field } => resolve_vault(key, mount, path, field),
    }
}

/// `env`: read the caller's environment (D5: no nested credentials).
fn resolve_env(key: &str, var: &str) -> miette::Result<String> {
    let value = match std::env::var(var) {
        Ok(v) => v,
        Err(std::env::VarError::NotPresent) => {
            miette::bail!("secret '{key}' (source 'env'): environment variable '{var}' is not set")
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            miette::bail!(
                "secret '{key}' (source 'env'): environment variable '{var}' \
                 is not valid UTF-8"
            )
        }
    };
    if value.is_empty() {
        // D7: never an empty value — an empty export is never a usable
        // credential, and a silent empty would truncate every consumer.
        miette::bail!(
            "secret '{key}' (source 'env'): environment variable '{var}' is \
             set but empty"
        )
    }
    Ok(value)
}

/// `exec`: run the argv array with NO shell (D4), trim stdout at the
/// edges only (interior newlines survive — PEM keys are a day-one
/// case), fail loud naming the key and program on nonzero exit or empty
/// output (D7). Child stderr is captured and never surfaces (D8).
fn resolve_exec(pod_dir: &Path, key: &str, command: &[String]) -> miette::Result<String> {
    let program = command
        .first()
        .ok_or_else(|| miette::miette!("secret '{key}' (source 'exec'): command array is empty"))?;
    let resolved = resolve_exec_program(pod_dir, key, "exec", program)?;
    let output = std::process::Command::new(resolved)
        .args(&command[1..])
        .output()
        .map_err(|e| {
            miette::miette!("secret '{key}' (source 'exec'): could not run '{program}': {e}")
        })?;
    if !output.status.success() {
        miette::bail!(
            "secret '{key}' (source 'exec'): program '{program}' exited with {} \
             — provider stderr suppressed (ADR-0042 D8 masking)",
            output.status
        );
    }
    let text = String::from_utf8(output.stdout).map_err(|_| {
        miette::miette!(
            "secret '{key}' (source 'exec'): program '{program}' wrote \
             non-UTF-8 output"
        )
    })?;
    let value = text.trim();
    if value.is_empty() {
        // D7: never an empty value.
        miette::bail!("secret '{key}' (source 'exec'): program '{program}' produced no output")
    }
    Ok(value.to_string())
}

/// Resolve one provider argv[0] against the HOST PATH (D4): every PATH
/// entry under the pod state root is dropped BEFORE the search, and a
/// win that lands under the pod state root anyway (symlinks included)
/// is refused. `source` labels the failures (`exec`, `bitwarden`).
/// Pub for the root verb/test layer (exec provider core); internals, not API.
#[doc(hidden)]
pub fn resolve_exec_program(
    pod_dir: &Path,
    key: &str,
    source: &str,
    program: &str,
) -> miette::Result<PathBuf> {
    let pod_root = std::fs::canonicalize(pod_dir).map_err(|e| {
        miette::miette!(
            "secret '{key}' (source '{source}'): pod state root {}: {e}",
            pod_dir.display()
        )
    })?;
    if program.contains('/') {
        let resolved = std::fs::canonicalize(program).map_err(|e| {
            miette::miette!(
                "secret '{key}' (source '{source}'): program '{program}' is \
                 not reachable: {e}"
            )
        })?;
        refuse_pod_rooted_program(&pod_root, key, source, program, &resolved)?;
        return Ok(resolved);
    }
    let raw_path = std::env::var("PATH").unwrap_or_default();
    for dir in host_path_dirs(pod_dir, &raw_path) {
        let candidate = dir.join(program);
        let Ok(meta) = std::fs::metadata(&candidate) else {
            continue;
        };
        if !meta.is_file() || !is_executable(&meta) {
            continue;
        }
        let resolved = std::fs::canonicalize(&candidate).map_err(|e| {
            miette::miette!(
                "secret '{key}' (source '{source}'): resolving {}: {e}",
                candidate.display()
            )
        })?;
        refuse_pod_rooted_program(&pod_root, key, source, program, &resolved)?;
        return Ok(resolved);
    }
    miette::bail!(
        "secret '{key}' (source '{source}'): program '{program}' not found \
         on the host PATH (pod farm entries are excluded per ADR-0042 D4)"
    )
}

/// D4's hard line: the resolved program must live OUTSIDE the pod state
/// root, or a pod package is shadowing a provider tool.
fn refuse_pod_rooted_program(
    pod_root: &Path,
    key: &str,
    source: &str,
    program: &str,
    resolved: &Path,
) -> miette::Result<()> {
    if resolved.starts_with(pod_root) {
        miette::bail!(
            "secret '{key}' (source '{source}'): program '{program}' resolves \
             to {} inside the pod state root — refusing (ADR-0042 D4: a pod \
             package must not shadow a provider program)",
            resolved.display()
        );
    }
    Ok(())
}

/// PATH with every entry under the pod state root removed — the pure,
/// directly-testable half of the D4 scrub. Entries that cannot be
/// canonicalized stay (the search will stat and skip them).
/// Pub for the root verb/test layer (exec argv-0 audit); internals, not API.
#[doc(hidden)]
pub fn host_path_dirs(pod_dir: &Path, raw_path: &str) -> Vec<PathBuf> {
    let pod_root = std::fs::canonicalize(pod_dir).ok();
    raw_path
        .split(':')
        .filter(|entry| !entry.is_empty())
        .map(PathBuf::from)
        .filter(|dir| match (&pod_root, std::fs::canonicalize(dir)) {
            (Some(root), Ok(canonical)) => !canonical.starts_with(root),
            _ => true,
        })
        .collect()
}

/// The exec-bit half of the PATH search.
fn is_executable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

// ── bitwarden (bws, issue #185) ──

/// `bitwarden`: `bws secret get <id>` as an ARGV ARRAY (no shell — D4),
/// parse the JSON stdout, extract `.value` (bws prints the secret as a
/// JSON document). `bws` resolves like every exec argv[0]: the HOST
/// PATH with pod-farm entries scrubbed, pod-rooted wins refused —
/// a pool package shipping a `bws` must not capture the token (D4).
///
/// Auth (D5): `BWS_ACCESS_TOKEN` is presence-checked here and rides the
/// caller env into the child by INHERITANCE — it is never read, stored,
/// forwarded, or logged. Named failures (D7): bws not on the host PATH,
/// token unset/empty, nonzero exit (provider stderr suppressed, D8),
/// malformed JSON, `.value` missing / non-string / empty. The secret
/// never enters an error string (D8).
fn resolve_bitwarden(pod_dir: &Path, key: &str, id: &str) -> miette::Result<String> {
    let bws = resolve_exec_program(pod_dir, key, "bitwarden", "bws")?;
    // D5 presence check — a boolean leaves this match; the token does not.
    match std::env::var("BWS_ACCESS_TOKEN") {
        Err(_) => miette::bail!(
            "secret '{key}' (source 'bitwarden'): BWS_ACCESS_TOKEN is not set \
             (it must ride the caller env per ADR-0042 D5)"
        ),
        Ok(token) if token.is_empty() => {
            miette::bail!(
                "secret '{key}' (source 'bitwarden'): BWS_ACCESS_TOKEN is set \
                 but empty"
            )
        }
        Ok(_) => {}
    }
    let output = std::process::Command::new(&bws)
        .arg("secret")
        .arg("get")
        .arg(id)
        .output()
        .map_err(|e| {
            miette::miette!("secret '{key}' (source 'bitwarden'): could not run 'bws': {e}")
        })?;
    if !output.status.success() {
        miette::bail!(
            "secret '{key}' (source 'bitwarden'): 'bws secret get' exited with \
             {} — provider stderr suppressed (ADR-0042 D8 masking)",
            output.status
        );
    }
    let text = String::from_utf8(output.stdout).map_err(|_| {
        miette::miette!("secret '{key}' (source 'bitwarden'): 'bws' wrote non-UTF-8 output")
    })?;
    bitwarden_value(key, text.trim())
}

/// Extract `.value` from the bws JSON body. Named failures only (D7);
/// the body and the value never appear in a failure string (D8).
fn bitwarden_value(key: &str, body: &str) -> miette::Result<String> {
    let json: serde_json::Value = serde_json::from_str(body).map_err(|e| {
        miette::miette!(
            "secret '{key}' (source 'bitwarden'): 'bws' did not return valid \
             JSON (serde position {e})"
        )
    })?;
    let value = match json.get("value") {
        Some(serde_json::Value::String(v)) => v.clone(),
        Some(_) => miette::bail!(
            "secret '{key}' (source 'bitwarden'): bws JSON field '.value' is \
             not a string"
        ),
        None => miette::bail!(
            "secret '{key}' (source 'bitwarden'): bws JSON has no '.value' \
             field"
        ),
    };
    if value.is_empty() {
        // D7: never an empty value.
        miette::bail!(
            "secret '{key}' (source 'bitwarden'): bws returned an empty \
             '.value'"
        )
    }
    Ok(value)
}

// ── libsecret (Secret Service, issue #185) ──

/// The Secret Service attribute-query seam. The ONE place the tree
/// touches the D-Bus session; tests reseat it to an in-memory fake,
/// production always runs [`secret_service_lookup`], live-bus tests
/// stay env-gated (`NAU_SECRETS_LIVE_DBUS=1`).
/// The reseatable Secret Service lookup fn shape (see
/// [`reseat_secret_service_lookup`] — the root verb suite's libsecret
/// end-to-end drives the seam through it).
#[doc(hidden)]
pub type AttributeLookup = fn(&BTreeMap<String, String>) -> miette::Result<Option<Vec<u8>>>;

static SECRET_SERVICE_LOOKUP: Mutex<AttributeLookup> = Mutex::new(secret_service_lookup);

/// The reseated lookup — the single call site in production paths.
fn attribute_lookup(attributes: &BTreeMap<String, String>) -> miette::Result<Option<Vec<u8>>> {
    let f = SECRET_SERVICE_LOOKUP
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    f(attributes)
}

/// The real Secret Service lookup: `secret-tool lookup` semantics over
/// the declared attribute pairs — search ALL collections for an item
/// matching EVERY attribute, fail named when nothing matches (`None`)
/// or when the match is ambiguous, unlock on demand, return the secret
/// bytes. Devbox interop: `{ bitwarden = "sm-access-token" }` reads the
/// token the setup-bws pipeline stores. The attribute map is the
/// declared, reviewable surface; the secret CONTENT never enters an
/// error string (D8).
/// Pub for the root verb/test layer (the live Secret Service lookup); internals, not API.
#[doc(hidden)]
pub fn secret_service_lookup(
    attributes: &BTreeMap<String, String>,
) -> miette::Result<Option<Vec<u8>>> {
    use dbus_secret_service::{EncryptionType, SecretService};
    let named =
        |what: &str, e: dbus_secret_service::Error| miette::miette!("secret service {what}: {e}");
    let service =
        SecretService::connect(EncryptionType::Dh).map_err(|e| named("connect failed", e))?;
    let query: std::collections::HashMap<&str, &str> = attributes
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let found = service
        .search_items(query)
        .map_err(|e| named("search failed", e))?;
    match found.unlocked.len() + found.locked.len() {
        0 => return Ok(None),
        1 => {}
        n => miette::bail!(
            "secret service: {n} entries match the attribute set — refine it \
             to one (ambiguous lookup, refusing)"
        ),
    }
    let item = found
        .unlocked
        .into_iter()
        .chain(found.locked)
        .next()
        .expect("exactly one match");
    Ok(Some(read_item_secret(&item)?))
}

/// Read one item's secret, unlocking on demand (the login-keyring
/// prompt flow). Named failures; the bytes never surface in errors (D8).
fn read_item_secret(item: &dbus_secret_service::Item<'_>) -> miette::Result<Vec<u8>> {
    if item
        .is_locked()
        .map_err(|e| miette::miette!("secret service: item lock state: {e}"))?
    {
        item.unlock()
            .map_err(|e| miette::miette!("secret service: unlock failed: {e}"))?;
    }
    item.get_secret()
        .map_err(|e| miette::miette!("secret service: could not read the secret: {e}"))
}

/// `libsecret`: map the attribute pairs (≥1 — the declaration validator
/// enforces shape) onto an exact Secret Service item match. Missing
/// entry = named failure, distinguishable from a transport failure by
/// construction (`Ok(None)` is "no such entry"; anything else names the
/// D-Bus error). Workstation-only caveat (survey §2): a headless host
/// has no session bus/keyring and fails named, never partially.
fn resolve_libsecret(key: &str, attributes: &BTreeMap<String, String>) -> miette::Result<String> {
    match attribute_lookup(attributes)? {
        Some(bytes) => libsecret_value(key, bytes),
        None => miette::bail!(
            "secret '{key}' (source 'libsecret'): no Secret Service entry \
             matches the attribute set (headless hosts carry no session \
             bus/keyring — ADR-0042 survey §2)"
        ),
    }
}

/// Bytes → value: UTF-8 and empty checks. The CONTENT is never part of
/// a failure string (D8); stored verbatim — no trimming (unlike CLI
/// stdout, a keyring secret is the bytes the writer chose).
fn libsecret_value(key: &str, bytes: Vec<u8>) -> miette::Result<String> {
    let value = String::from_utf8(bytes).map_err(|_| {
        miette::miette!("secret '{key}' (source 'libsecret'): entry content is not UTF-8")
    })?;
    if value.is_empty() {
        // D7: never an empty value.
        miette::bail!("secret '{key}' (source 'libsecret'): entry content is empty")
    }
    Ok(value)
}

// ── vault (KV v2 REST, issue #186) ──

/// `vault`: KV v2 REST read against `{VAULT_ADDR}` (D4; OpenBao shares
/// the wire shape — it is a fork of Vault's KV engine). One request:
/// `GET {VAULT_ADDR}/v1/{mount}/data/{path}` with the `X-Vault-Token`
/// header; the value lives at `.data.data.<field>`.
///
/// Implementation verdict (ADR-0042 Evidence, issue #186): raw REST on
/// the existing ureq host fetch stack — the `src/tools.rs` fetch-agent
/// shape — not the `vaultrs` crate, which would drag tokio into a tree
/// that bans it while the KV v2 wire shape is one GET + one header.
///
/// Auth (D5): `VAULT_ADDR` + `VAULT_TOKEN` from the caller env.
/// Named failures (D7): either variable unset/empty (named
/// separately), transport failure (short reason), non-2xx status
/// named (403 wrong token, 404 missing path), non-JSON body,
/// `.data`/`.data.data` missing or non-object, field missing,
/// field non-string, field empty (never an empty value). A response
/// BODY never enters an error string (D8: an error body can echo
/// field data) and the token never enters one either; mount/path/
/// field are declared surface and may appear.
fn resolve_vault(key: &str, mount: &str, path: &str, field: &str) -> miette::Result<String> {
    let (addr, token) = vault_env(key)?;
    let url = format!("{}/v1/{mount}/data/{path}", addr.trim_end_matches('/'));
    vault_read(key, field, &url, &token)
}

/// The D5 credential pair; each failure named separately (unset vs
/// set-but-empty, addr vs token).
fn vault_env(key: &str) -> miette::Result<(String, String)> {
    let addr = match std::env::var("VAULT_ADDR") {
        Err(_) => miette::bail!(
            "secret '{key}' (source 'vault'): VAULT_ADDR is not set (it must \
             ride the caller env per ADR-0042 D5)"
        ),
        Ok(a) if a.is_empty() => {
            miette::bail!("secret '{key}' (source 'vault'): VAULT_ADDR is set but empty")
        }
        Ok(a) => a,
    };
    let token = match std::env::var("VAULT_TOKEN") {
        Err(_) => miette::bail!(
            "secret '{key}' (source 'vault'): VAULT_TOKEN is not set (it must \
             ride the caller env per ADR-0042 D5)"
        ),
        Ok(t) if t.is_empty() => {
            miette::bail!("secret '{key}' (source 'vault'): VAULT_TOKEN is set but empty")
        }
        Ok(t) => t,
    };
    Ok((addr, token))
}

/// The KV v2 GET. Status and short reason only in failures — a
/// response BODY never enters an error string (D8), and `Error::Status`'s
/// dropped `Response` is never read.
fn vault_read(key: &str, field: &str, url: &str, token: &str) -> miette::Result<String> {
    let agent = vault_agent();
    let response = match agent.get(url).set("X-Vault-Token", token).call() {
        Ok(response) => response,
        Err(ureq::Error::Status(status, response)) => miette::bail!(
            "secret '{key}' (source 'vault'): KV v2 read returned HTTP {status} {} — \
             response body suppressed (ADR-0042 D8 masking)",
            response.status_text()
        ),
        Err(e) => miette::bail!(
            "secret '{key}' (source 'vault'): transport failure reaching the \
             KV v2 API: {e} (response body suppressed per ADR-0042 D8)"
        ),
    };
    let body = response.into_string().map_err(|e| {
        miette::miette!(
            "secret '{key}' (source 'vault'): could not read the KV v2 \
             response body: {e}"
        )
    })?;
    let json: serde_json::Value = serde_json::from_str(body.trim()).map_err(|e| {
        miette::miette!(
            "secret '{key}' (source 'vault'): KV v2 response was not valid \
             JSON (serde position {e})"
        )
    })?;
    vault_field(key, field, &json)
}

/// The ureq host fetch agent — the `src/tools.rs` fetch-agent shape
/// (same TLS/CA resolution: rustls with compiled-in webpki roots for
/// https; http stays plain, the loopback test host) and the same
/// connect/total timeouts.
fn vault_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(FETCH_CONNECT_TIMEOUT)
        .timeout(FETCH_TOTAL_TIMEOUT)
        .build()
}

/// Navigate `.data.data.<field>` in the KV v2 document. Named failures
/// only (D7); the body and the value never enter a failure string (D8).
fn vault_field(key: &str, field: &str, json: &serde_json::Value) -> miette::Result<String> {
    let data = json.get("data").ok_or_else(|| {
        miette::miette!("secret '{key}' (source 'vault'): KV v2 response has no '.data' object")
    })?;
    if !data.is_object() {
        miette::bail!(
            "secret '{key}' (source 'vault'): KV v2 response field '.data' is not an object"
        )
    }
    let inner = data.get("data").ok_or_else(|| {
        miette::miette!(
            "secret '{key}' (source 'vault'): KV v2 response has no '.data.data' object"
        )
    })?;
    if !inner.is_object() {
        miette::bail!(
            "secret '{key}' (source 'vault'): KV v2 response field '.data.data' is not an object"
        )
    }
    let value = match inner.get(field) {
        Some(serde_json::Value::String(v)) => v.clone(),
        Some(_) => {
            miette::bail!("secret '{key}' (source 'vault'): KV v2 field '{field}' is not a string")
        }
        None => {
            miette::bail!("secret '{key}' (source 'vault'): KV v2 secret has no '{field}' field")
        }
    };
    if value.is_empty() {
        // D7: never an empty value.
        miette::bail!("secret '{key}' (source 'vault'): KV v2 field '{field}' is empty")
    }
    Ok(value)
}

// ── The declaration hash (D3 cache key) ──

/// SHA-256 over the canonical reference bytes — the SAME serialization
/// `farm::write_generation_secrets` records, so the cache key and the
/// generation record can never disagree. Any reference change (a var
/// rename, an id, one argv word) is a different hash → a fresh fetch;
/// identical references hash identically.
pub fn decl_hash(refs: &BTreeMap<String, SecretSource>) -> miette::Result<String> {
    Ok(sha256_hex(&crate::farm::canonical_secrets_bytes(refs)?))
}

/// Pub for the root verb layer (digest helper); internals, not API.
#[doc(hidden)]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Session cache (D3) ──

/// One cache entry. The generation rides INSIDE the body for prune
/// bookkeeping; it is never part of the key (D3: a rollback must not
/// serve a dead generation's pre-rotation values).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CacheEntry {
    /// The generation the entry was resolved for.
    pub generation: u64,
    /// Key → resolved value. This map is the ONLY surface a value may
    /// occupy (D8).
    pub values: BTreeMap<String, String>,
}

/// The cache base: the caller's override, or
/// `$XDG_RUNTIME_DIR/nau/secrets` (created 0700, tmpfs-verified).
/// Pub for the root verb layer (cache-base derivation); internals, not API.
#[doc(hidden)]
pub fn cache_base(override_base: Option<&Path>) -> miette::Result<PathBuf> {
    match override_base {
        Some(base) => Ok(base.to_path_buf()),
        None => xdg_cache_base(),
    }
}

/// Derive the cache base from `$XDG_RUNTIME_DIR` — D7 hard-fails naming
/// the gap when it is absent/empty or not on tmpfs (no silent disk
/// fallback; WSL2-no-systemd and SysV hosts are out of scope for
/// secrets in v1).
fn xdg_cache_base() -> miette::Result<PathBuf> {
    let gap = || {
        miette::miette!(
            "XDG_RUNTIME_DIR is not set — secret values cache only on tmpfs \
             (ADR-0042 D3/D7: no disk fallback). A systemd user session \
             provides it; export XDG_RUNTIME_DIR to use pod secrets."
        )
    };
    let run = std::env::var("XDG_RUNTIME_DIR").map_err(|_| gap())?;
    if run.is_empty() {
        return Err(gap());
    }
    let base = Path::new(&run).join("nau").join("secrets");
    std::fs::create_dir_all(&base)
        .map_err(|e| miette::miette!("creating {}: {e}", base.display()))?;
    set_dir_mode(Path::new(&run).join("nau").as_path(), 0o700)?;
    set_dir_mode(&base, 0o700)?;
    if !is_tmpfs(&base)? {
        miette::bail!(
            "{} is not on tmpfs — secret values cache only on tmpfs \
             (ADR-0042 D3/D7: no disk fallback); point XDG_RUNTIME_DIR at \
             a tmpfs runtime dir",
            base.display()
        );
    }
    Ok(base)
}

/// Passive base for the sync-side prune: no creation, no tmpfs gate, no
/// failure — sync never resolves (D3) and hygiene must not block it.
fn xdg_cache_base_passive() -> Option<PathBuf> {
    let run = std::env::var_os("XDG_RUNTIME_DIR")?;
    if run.is_empty() {
        return None;
    }
    Some(Path::new(&run).join("nau").join("secrets"))
}

/// One pod's cache directory: `<base>/<pod>/`.
/// Pub for the root verb/test layer (cache layout); internals, not API.
#[doc(hidden)]
pub fn pod_cache_dir(base: &Path, pod_name: &str) -> PathBuf {
    base.join(pod_name)
}

/// One entry: `<base>/<pod>/<decl-hash>.json`.
/// Pub for the root verb/test layer (cache addressing); internals, not API.
#[doc(hidden)]
pub fn pod_cache_entry_path(base: &Path, pod_name: &str, hash: &str) -> PathBuf {
    pod_cache_dir(base, pod_name).join(format!("{hash}.json"))
}

/// Read one cache entry. A missing file is a miss; ANY other read or
/// parse failure fails loud (D7): the cache is 0600 operator-owned
/// tmpfs, so an unreadable or corrupt body is something to look at,
/// not something to silently overwrite. Failure text carries serde
/// positions only — never entry content (D8).
/// Pub for the root verb/test layer (cache reads); internals, not API.
#[doc(hidden)]
pub fn read_cache_entry(path: &Path) -> miette::Result<Option<CacheEntry>> {
    let body = match std::fs::read(path) {
        Ok(body) => body,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(miette::miette!(
                "reading secret cache {}: {e} — `pod secrets refresh` rewrites it",
                path.display()
            ))
        }
    };
    serde_json::from_slice(&body).map(Some).map_err(|e| {
        miette::miette!(
            "corrupt secret cache {}: {e} — `pod secrets refresh` rewrites it",
            path.display()
        )
    })
}

/// Write one entry ATOMICALLY (D3): temp file in the SAME directory,
/// mode 0600, rename into place. No temp leftovers survive either
/// outcome — `persist` renames, and a dropped `NamedTempFile` cleans up.
/// Pub for the root verb/test layer (cache writes); internals, not API.
#[doc(hidden)]
pub fn write_cache_entry(path: &Path, entry: &CacheEntry) -> miette::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let dir = path
        .parent()
        .ok_or_else(|| miette::miette!("secret cache entry {} has no parent", path.display()))?;
    std::fs::create_dir_all(dir).map_err(|e| miette::miette!("creating {}: {e}", dir.display()))?;
    set_dir_mode(dir, 0o700)?;
    let body = serde_json::to_vec(entry)
        .map_err(|e| miette::miette!("serializing secret cache entry: {e}"))?;
    let temp = tempfile::NamedTempFile::new_in(dir)
        .map_err(|e| miette::miette!("staging {}: {e}", path.display()))?;
    temp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| miette::miette!("staging {}: {e}", path.display()))?;
    temp.as_file()
        .write_all(&body)
        .map_err(|e| miette::miette!("staging {}: {e}", path.display()))?;
    temp.persist(path)
        .map_err(|e| miette::miette!("publishing {}: {}", path.display(), e.error))?;
    Ok(())
}

/// chmod 0700 a directory we created (create_dir_all applies the
/// process umask, not the mode we want).
fn set_dir_mode(dir: &Path, mode: u32) -> miette::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode))
        .map_err(|e| miette::miette!("setting mode on {}: {e}", dir.display()))
}

/// True when `path` sits on tmpfs (statfs `f_type == TMPFS_MAGIC`).
/// Pub for the root verb/test layer (the D3 tmpfs gate); internals, not API.
#[doc(hidden)]
pub fn is_tmpfs(path: &Path) -> miette::Result<bool> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| miette::miette!("path {} contains NUL bytes", path.display()))?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c_path` outlives the call and `stat` is a valid,
    // fully-initialized `statfs` the kernel writes into.
    let rc = unsafe { libc::statfs(c_path.as_ptr(), &mut stat) };
    if rc != 0 {
        return Err(miette::miette!(
            "statfs {} failed: {} — cannot verify the secret cache sits on \
             tmpfs (ADR-0042 D3)",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(stat.f_type == libc::TMPFS_MAGIC)
}

/// Prune the pod's cache entries whose recorded generation is no longer
/// `active_generation` (D3's lifecycle rule). Best-effort by design:
/// the cache is disposable tmpfs, sync never fails on hygiene, and an
/// unreadable entry has no recorded generation to classify it — it is
/// skipped (a refresh purge or the reboot drops it).
///
/// The `.env` sibling rides its entry's lifecycle: a stale entry's
/// envfile is pruned with it, and any file that is not a cache entry
/// (including an orphaned envfile) is left to the next purge/reboot —
/// hygiene never blocks sync.
pub fn prune_stale_cache_entries(base: &Path, pod_name: &str, active_generation: u64) -> usize {
    let dir = pod_cache_dir(base, pod_name);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return 0;
    };
    let mut pruned = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        let stale = std::fs::read(&path)
            .ok()
            .and_then(|body| serde_json::from_slice::<CacheEntry>(&body).ok())
            .map(|cache| cache.generation != active_generation);
        if stale == Some(true) && std::fs::remove_file(&path).is_ok() {
            // The envfile shares the entry's decl-hash key — it goes
            // when the entry goes (best-effort, same hygiene rule).
            let _ = std::fs::remove_file(path.with_extension("env"));
            pruned += 1;
        }
    }
    pruned
}

/// Drop the pod's whole cache subtree, returning how many ENTRIES went
/// (`.json` cache entries — the `.env` siblings ride the subtree and
/// are not counted). Errors fail loud — `refresh` is the explicit,
/// operator-facing cache lifecycle verb.
pub fn purge_pod_cache(base: &Path, pod_name: &str) -> miette::Result<usize> {
    let dir = pod_cache_dir(base, pod_name);
    let count = match std::fs::read_dir(&dir) {
        Ok(entries) => entries
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .count(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(miette::miette!("reading {}: {e}", dir.display())),
    };
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => Ok(count),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(miette::miette!("removing {}: {e}", dir.display())),
    }
}

/// Best-effort whole-subtree removal for pod removal (ADR-0042 D3's
/// closing sentence). Never fails: a dead pod's tmpfs residue is
/// bounded by the reboot, and removal must not fail for hygiene.
pub fn remove_pod_cache(base: &Path, pod_name: &str) {
    let _ = std::fs::remove_dir_all(pod_cache_dir(base, pod_name));
}

/// The sync-side cache lifecycle hook (D3), wired into the reconcile
/// staging tail beside `farm::write_generation_secrets`: prune entries
/// whose recorded generation is no longer active, or purge the subtree
/// when the pod went cold. Sync STILL NEVER RESOLVES — and never
/// touches the cache at all when `$XDG_RUNTIME_DIR` is unset.
pub fn reconcile_cache_prune(
    pod_name: &str,
    active_generation: Option<u64>,
    base_override: Option<&Path>,
) {
    let base = match base_override {
        Some(base) => base.to_path_buf(),
        None => match xdg_cache_base_passive() {
            Some(base) => base,
            None => return,
        },
    };
    match active_generation {
        Some(n) => {
            prune_stale_cache_entries(&base, pod_name, n);
        }
        None => remove_pod_cache(&base, pod_name),
    }
}

// ── Serve + the envfile (ADR-0042 D3's consumers, issue #184) ──

/// Per-key serve metadata: the registry source kind and the session
/// cache state. The ONLY thing `pod shellenv --json` carries about a
/// secret (D8: names + source kind + cache state, never a value — a CI
/// script dumping shellenv JSON must not become an exfiltration path).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SecretMeta {
    /// The registry source name (`bitwarden`, `exec`, `env`, …).
    pub source: String,
    /// `hit` / `stale` / `miss` — the session cache state after the
    /// serve resolve.
    pub cache: &'static str,
}

/// What one serve step hands a consumer: the resolved values (the ONLY
/// value surface, never serialized — [`SecretMeta`] is the `--json`
/// face), the per-key metadata, and the envfile path the resolve
/// materialized.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServedSecrets {
    /// Key → resolved value. Rendered as POSIX exports / overlaid onto
    /// the exec'd process / written to the envfile — nothing else.
    pub values: BTreeMap<String, String>,
    /// Key → serve metadata (the `--json` map).
    pub meta: BTreeMap<String, SecretMeta>,
    /// The 0600 runtime envfile path, when the pod declares secrets.
    /// `None` for a secret-less pod: no references, no envfile, no
    /// tmpfs requirement (the D3 empty rule).
    pub envfile: Option<PathBuf>,
}

/// The ONE serve step every exec-form consumer shares (ADR-0042 D3):
/// resolve the folded reference set (session cache first, providers
/// all-or-nothing — D7), then materialize the 0600 runtime envfile from
/// the resolved values. A cache hit costs zero provider calls and still
/// refreshes the envfile (idempotent same-content rewrite). Splitting
/// out of [`resolve_references`] would change nothing: this calls it —
/// one resolve entry point, three consumers.
pub fn serve_pod(
    pod_dir: &Path,
    pod_name: &str,
    generation: u64,
    refs: &BTreeMap<String, SecretSource>,
    cache_base_override: Option<&Path>,
) -> miette::Result<ServedSecrets> {
    if refs.is_empty() {
        return Ok(ServedSecrets::default());
    }
    let base = cache_base(cache_base_override)?;
    let hash = decl_hash(refs)?;
    let entry_path = pod_cache_entry_path(&base, pod_name, &hash);
    let values = resolve_references(pod_dir, pod_name, generation, refs, Some(&base))?;
    let meta = refs
        .keys()
        .map(|key| -> miette::Result<(String, SecretMeta)> {
            Ok((
                key.clone(),
                SecretMeta {
                    source: source_name(&refs[key]).to_string(),
                    cache: cache_state(&entry_path, generation)?,
                },
            ))
        })
        .collect::<miette::Result<BTreeMap<_, _>>>()?;
    let envfile = pod_envfile_path(&base, pod_name, &hash);
    write_pod_envfile(&envfile, &values)?;
    Ok(ServedSecrets {
        values,
        meta,
        envfile: Some(envfile),
    })
}

/// The envfile for one cache entry: a SIBLING of the cache entry
/// (`<base>/<pod>/<decl-hash>.env`, the `.json` swapped for `.env`).
/// Same decl-hash key, same rotation semantics: any reference change is
/// a fresh path AND a fresh fetch.
/// Pub for the root verb/test layer (envfile layout); internals, not API.
#[doc(hidden)]
pub fn pod_envfile_path(base: &Path, pod_name: &str, hash: &str) -> PathBuf {
    let entry = pod_cache_entry_path(base, pod_name, hash);
    entry.with_extension("env")
}

/// Derive the pod's canonical envfile path PASSIVELY (no creation, no
/// tmpfs gate): the sync side bakes it into unit TEXT without resolving
/// (D3), so it must be computable from the references alone. `None`
/// when the pod declares no secrets — a secret-less unit never gains an
/// `EnvironmentFile=` pointing at a file nothing will ever write. An
/// unset `$XDG_RUNTIME_DIR` with secrets declared is a named failure
/// (D7): sync must not record a secret-bearing pod it cannot point a
/// unit at — the alternative (recording the unit without the line)
/// silently starts without secrets, exactly what D7 forbids.
pub fn pod_envfile_path_passive(
    pod_name: &str,
    refs: &BTreeMap<String, SecretSource>,
    cache_base_override: Option<&Path>,
) -> miette::Result<Option<PathBuf>> {
    if refs.is_empty() {
        return Ok(None);
    }
    let base = match cache_base_override {
        Some(base) => base.to_path_buf(),
        None => match xdg_cache_base_passive() {
            Some(base) => base,
            None => {
                miette::bail!(
                    "pod '{pod_name}' declares secrets, but XDG_RUNTIME_DIR is \
                     not set — the service envfile lives under \
                     $XDG_RUNTIME_DIR/nau/secrets (ADR-0042 D3/D7: no \
                     disk fallback). Export XDG_RUNTIME_DIR and sync again."
                )
            }
        },
    };
    let hash = decl_hash(refs)?;
    Ok(Some(pod_envfile_path(&base, pod_name, &hash)))
}

/// Escape one secret value for the systemd `EnvironmentFile=` format
/// (ADR-0042 D4: values may carry newlines — PEM keys are a day-one
/// case). Double quotes with systemd's C-escape processing: backslash,
/// double quote, newline, carriage return, and tab are escaped, every
/// other byte lands verbatim. `$` needs no escape — systemd env files
/// never expand.
fn envfile_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Write the pod's 0600 runtime envfile (ADR-0042 D3): one `KEY=value`
/// line per resolved secret, sorted keys, values C-escaped per
/// [`envfile_value`]. ATOMIC like the cache entry — same-dir temp +
/// rename, 0600 — so a unit start never observes a half-written file.
/// Values only ever arrive from an in-process resolve (this map is the
/// D8 value surface; the envfile and the POSIX shellenv exports are the
/// only two value outputs in the whole surface). The file lives in the
/// tmpfs secrets tree, NEVER under `generations/<n>/` — ADR-0032's
/// emit-into-generation norm must not be read onto it (D3).
/// Pub for the root verb layer (envfile write); internals, not API.
#[doc(hidden)]
pub fn write_pod_envfile(path: &Path, values: &BTreeMap<String, String>) -> miette::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let dir = path
        .parent()
        .ok_or_else(|| miette::miette!("secret envfile {} has no parent", path.display()))?;
    std::fs::create_dir_all(dir).map_err(|e| miette::miette!("creating {}: {e}", dir.display()))?;
    set_dir_mode(dir, 0o700)?;
    let mut body = String::new();
    for (key, value) in values {
        body.push_str(&format!("{key}={}\n", envfile_value(value)));
    }
    let temp = tempfile::NamedTempFile::new_in(dir)
        .map_err(|e| miette::miette!("staging {}: {e}", path.display()))?;
    temp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| miette::miette!("staging {}: {e}", path.display()))?;
    temp.as_file()
        .write_all(body.as_bytes())
        .map_err(|e| miette::miette!("staging {}: {e}", path.display()))?;
    temp.persist(path)
        .map_err(|e| miette::miette!("publishing {}: {}", path.display(), e.error))?;
    Ok(())
}

/// The sync-side warm-cache envfile render (ADR-0042 D3's
/// sync-triggered resolve, with sync STILL NEVER resolving): when a
/// warm cache entry already exists for the pod's decl-hash, render the
/// envfile FROM THE CACHE — zero provider calls, zero network. On a
/// cache miss, write NOTHING: the unit's mandatory `EnvironmentFile=`
/// fails the start loud (D7), which is the designed cold-cache state
/// until a serve-time resolve or `pod secrets refresh` materializes the
/// file. Call AFTER [`reconcile_cache_prune`] — a surviving entry is
/// generation-current by construction. Best-effort on cache read
/// failures, by the same hygiene rule as the prune: sync never fails on
/// cache state, and a corrupt entry serves nothing rather than
/// something wrong. Returns 1 when the envfile was rendered, 0 when
/// not (no references, no runtime dir, cache miss, or read failure).
pub fn render_pod_envfile_from_warm_cache(
    pod_name: &str,
    refs: &BTreeMap<String, SecretSource>,
    cache_base_override: Option<&Path>,
) -> usize {
    if refs.is_empty() {
        return 0;
    }
    let base = match cache_base_override {
        Some(base) => base.to_path_buf(),
        None => match xdg_cache_base_passive() {
            Some(base) => base,
            None => return 0,
        },
    };
    let Ok(hash) = decl_hash(refs) else {
        return 0;
    };
    let rendered = read_cache_entry(&pod_cache_entry_path(&base, pod_name, &hash))
        .ok()
        .flatten()
        .map(|cache| {
            write_pod_envfile(&pod_envfile_path(&base, pod_name, &hash), &cache.values).is_ok()
        })
        .unwrap_or(false);
    usize::from(rendered)
}

// ── Verbs (`nau pod secrets …`) ──

/// Everything the `pod secrets` verbs read before touching providers:
/// the pod's state dir, its active generation, and the folded reference
/// The entry's state against the active generation.
/// Pub for the root verb layer (`pod secrets list` reports the state);
/// internals, not API.
#[doc(hidden)]
pub fn cache_state(entry_path: &Path, generation: u64) -> miette::Result<&'static str> {
    match read_cache_entry(entry_path)? {
        None => Ok("miss"),
        Some(entry) if entry.generation == generation => Ok("hit"),
        Some(_) => Ok("stale"),
    }
}

/// Swap the Secret Service lookup seam; returns the previous fn for
/// restoration. Test-support for the root verb suite's libsecret
/// end-to-end (the static itself stays crate-private).
#[doc(hidden)]
pub fn reseat_secret_service_lookup(f: AttributeLookup) -> AttributeLookup {
    let mut seam = SECRET_SERVICE_LOOKUP
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    std::mem::replace(&mut *seam, f)
}
