//! Pod secret resolution (ADR-0042, issue #183) — the ONE resolve entry
//! point that turns a folded reference set
//! (`BTreeMap<String, pod::SecretSource>`, exactly the `secrets.json`
//! record) into values, plus the `pod secrets` verbs.
//!
//! Governing decisions:
//!
//! - **D3 (serve-time resolve; session cache on tmpfs).** Values cache
//!   at `$XDG_RUNTIME_DIR/shuttle/secrets/<pod>/<decl-hash>.json`, mode
//!   0600, written ATOMICALLY (temp file in the same dir + rename). The
//!   cache key is the SHA-256 of the canonical reference bytes and
//!   DELIBERATELY drops the generation — a rollback to an old
//!   generation must not serve that generation's pre-rotation cached
//!   value. The generation number rides INSIDE the entry body
//!   (`{"generation": <n>, "values": {KEY: "…"}}`) for prune
//!   bookkeeping only. A cache hit makes zero provider calls.
//!   `$XDG_RUNTIME_DIR` absent/empty, or the base not on tmpfs, is a
//!   hard failure naming the gap — never a silent disk fallback. An
//!   EMPTY reference set resolves to an empty map with no cache
//!   interaction and no tmpfs requirement.
//! - **D4 (compiled-in provider registry, ADR-0014 shape).** A
//!   match-based dispatch inside [`resolve_one`] plus a small
//!   source-name table — no trait hierarchy for five sources where
//!   three are stubs; it grows by arms when the network sources land.
//!   `env` reads the caller's environment; `exec` runs an argv array
//!   with NO shell. argv[0] resolves against the HOST PATH with every
//!   entry under the pod state root removed first (shells that eval the
//!   shellenv carry the pod farm ahead; a pool package shipping a
//!   binary named `op`/`bws` must not shadow the host tool and capture
//!   tokens), and a win that lands under the pod state root anyway
//!   (symlinks included) is refused. Stdout is trimmed at the edges
//!   only — interior newlines (PEM keys) survive verbatim.
//! - **D5 (provider credentials from the caller env).** Nothing nested,
//!   nothing stored: `exec` children inherit the caller's environment.
//! - **D7 (fail loud, never partial).** Any resolution failure fails
//!   the WHOLE resolve naming the var key and the source kind. Never a
//!   partial map, never an empty value, no `optional` flag.
//! - **D8 (masking).** Values never reach a log line, an error
//!   `Display` string, or any verb output — the cache file write is
//!   their only surface. `list` prints references and cache state only;
//!   provider child stderr is captured and deliberately suppressed in
//!   failures (a provider echoing the value to stderr must not leak
//!   through our errors).
//!
//! Sync NEVER resolves (D3): the sync side only prunes cache entries
//! whose recorded generation is no longer active
//! ([`reconcile_cache_prune`], wired into the reconcile staging tail
//! beside `farm::write_generation_secrets`). `pod remove` prunes the
//! pod's whole subtree via [`remove_pod_cache`].

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::pod::SecretSource;

// ── Provider registry (D4: compiled-in, ADR-0014 shape) ──

/// The registry name of a source.
fn source_name(source: &SecretSource) -> &'static str {
    match source {
        SecretSource::Bitwarden { .. } => "bitwarden",
        SecretSource::Vault { .. } => "vault",
        SecretSource::Libsecret { .. } => "libsecret",
        SecretSource::Exec { .. } => "exec",
        SecretSource::Env { .. } => "env",
    }
}

/// Whether the source can resolve in this build. The network sources
/// land with their own tickets; until then every attempt fails loud
/// naming the ticket ([`source_issue`]) — `pod secrets check` reports
/// them as unavailable, `list` still lists the references.
fn source_available(source: &SecretSource) -> bool {
    matches!(source, SecretSource::Env { .. } | SecretSource::Exec { .. })
}

/// Where an unavailable source ships.
fn source_issue(source: &SecretSource) -> &'static str {
    match source {
        SecretSource::Bitwarden { .. } | SecretSource::Libsecret { .. } => "issue #185",
        SecretSource::Vault { .. } => "issue #186",
        _ => "a future ticket",
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
fn resolve_one(pod_dir: &Path, key: &str, source: &SecretSource) -> miette::Result<String> {
    match source {
        SecretSource::Env { var } => resolve_env(key, var),
        SecretSource::Exec { command } => resolve_exec(pod_dir, key, command),
        other => miette::bail!(
            "secret '{key}' (source '{}'): the '{}' provider is not available \
             in this build — network sources land with {}",
            source_name(other),
            source_name(other),
            source_issue(other)
        ),
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
    let resolved = resolve_exec_program(pod_dir, key, program)?;
    let output = std::process::Command::new(&resolved)
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

/// Resolve one `exec` argv[0] against the HOST PATH (D4): every PATH
/// entry under the pod state root is dropped BEFORE the search, and a
/// win that lands under the pod state root anyway (symlinks included)
/// is refused.
fn resolve_exec_program(pod_dir: &Path, key: &str, program: &str) -> miette::Result<PathBuf> {
    let pod_root = std::fs::canonicalize(pod_dir).map_err(|e| {
        miette::miette!(
            "secret '{key}' (source 'exec'): pod state root {}: {e}",
            pod_dir.display()
        )
    })?;
    if program.contains('/') {
        let resolved = std::fs::canonicalize(program).map_err(|e| {
            miette::miette!(
                "secret '{key}' (source 'exec'): program '{program}' is not \
                 reachable: {e}"
            )
        })?;
        refuse_pod_rooted_program(&pod_root, key, program, &resolved)?;
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
                "secret '{key}' (source 'exec'): resolving {}: {e}",
                candidate.display()
            )
        })?;
        refuse_pod_rooted_program(&pod_root, key, program, &resolved)?;
        return Ok(resolved);
    }
    miette::bail!(
        "secret '{key}' (source 'exec'): program '{program}' not found on the \
         host PATH (pod farm entries are excluded per ADR-0042 D4)"
    )
}

/// D4's hard line: the resolved program must live OUTSIDE the pod state
/// root, or a pod package is shadowing a provider tool.
fn refuse_pod_rooted_program(
    pod_root: &Path,
    key: &str,
    program: &str,
    resolved: &Path,
) -> miette::Result<()> {
    if resolved.starts_with(pod_root) {
        miette::bail!(
            "secret '{key}' (source 'exec'): program '{program}' resolves to {} \
             inside the pod state root — refusing (ADR-0042 D4: a pod package \
             must not shadow a provider program)",
            resolved.display()
        );
    }
    Ok(())
}

/// PATH with every entry under the pod state root removed — the pure,
/// directly-testable half of the D4 scrub. Entries that cannot be
/// canonicalized stay (the search will stat and skip them).
fn host_path_dirs(pod_dir: &Path, raw_path: &str) -> Vec<PathBuf> {
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

// ── The declaration hash (D3 cache key) ──

/// SHA-256 over the canonical reference bytes — the SAME serialization
/// `farm::write_generation_secrets` records, so the cache key and the
/// generation record can never disagree. Any reference change (a var
/// rename, an id, one argv word) is a different hash → a fresh fetch;
/// identical references hash identically.
pub fn decl_hash(refs: &BTreeMap<String, SecretSource>) -> miette::Result<String> {
    Ok(sha256_hex(&crate::farm::canonical_secrets_bytes(refs)?))
}

fn sha256_hex(bytes: &[u8]) -> String {
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
/// `$XDG_RUNTIME_DIR/shuttle/secrets` (created 0700, tmpfs-verified).
fn cache_base(override_base: Option<&Path>) -> miette::Result<PathBuf> {
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
    let base = Path::new(&run).join("shuttle").join("secrets");
    std::fs::create_dir_all(&base)
        .map_err(|e| miette::miette!("creating {}: {e}", base.display()))?;
    set_dir_mode(Path::new(&run).join("shuttle").as_path(), 0o700)?;
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
    Some(Path::new(&run).join("shuttle").join("secrets"))
}

/// One pod's cache directory: `<base>/<pod>/`.
fn pod_cache_dir(base: &Path, pod_name: &str) -> PathBuf {
    base.join(pod_name)
}

/// One entry: `<base>/<pod>/<decl-hash>.json`.
fn pod_cache_entry_path(base: &Path, pod_name: &str, hash: &str) -> PathBuf {
    pod_cache_dir(base, pod_name).join(format!("{hash}.json"))
}

/// Read one cache entry. A missing file is a miss; ANY other read or
/// parse failure fails loud (D7): the cache is 0600 operator-owned
/// tmpfs, so an unreadable or corrupt body is something to look at,
/// not something to silently overwrite. Failure text carries serde
/// positions only — never entry content (D8).
fn read_cache_entry(path: &Path) -> miette::Result<Option<CacheEntry>> {
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
fn write_cache_entry(path: &Path, entry: &CacheEntry) -> miette::Result<()> {
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
fn is_tmpfs(path: &Path) -> miette::Result<bool> {
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
            pruned += 1;
        }
    }
    pruned
}

/// Drop the pod's whole cache subtree, returning how many entries went.
/// Errors fail loud — `refresh` is the explicit, operator-facing cache
/// lifecycle verb.
pub fn purge_pod_cache(base: &Path, pod_name: &str) -> miette::Result<usize> {
    let dir = pod_cache_dir(base, pod_name);
    let count = match std::fs::read_dir(&dir) {
        Ok(entries) => entries.flatten().filter(|e| e.path().is_file()).count(),
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

// ── Verbs (`shuttle pod secrets …`) ──

/// Everything the `pod secrets` verbs read before touching providers:
/// the pod's state dir, its active generation, and the folded reference
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
            "pod '{pod_name}' has no state at {} (`shuttle pod --name {pod_name} \
             add <package>` does)",
            pod_dir.display()
        );
    }
    let generation = crate::farm::current_generation(&pod_dir)?.ok_or_else(|| {
        miette::miette!(
            "pod '{pod_name}' has no active generation — sync the pod first \
             (`shuttle pod --name {pod_name} sync`)"
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

/// The entry's state against the active generation.
fn cache_state(entry_path: &Path, generation: u64) -> miette::Result<&'static str> {
    match read_cache_entry(entry_path)? {
        None => Ok("miss"),
        Some(entry) if entry.generation == generation => Ok("hit"),
        Some(_) => Ok("stale"),
    }
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
    /// `ok`, `unavailable` (provider ships with a later ticket), or
    /// `failed` (the named failure, D7).
    pub status: &'static str,
    /// The named failure, or where an unavailable provider ships. Never
    /// a value (D8).
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
        if !source_available(source) {
            rows.push(SecretsCheckRow {
                key: key.clone(),
                source: name.to_string(),
                status: "unavailable",
                note: format!("provider lands with {}", source_issue(source)),
            });
            continue;
        }
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
}

/// `pod secrets refresh` (ADR-0042 D3's rotation verb): bust the pod's
/// cache subtree, re-resolve every reference through its provider, and
/// rewrite the active entry. With no references this touches nothing —
/// no purge, no tmpfs requirement (the D3 empty rule covers the verb).
pub fn refresh_pod(
    root: &Path,
    pod_name: &str,
    cache_base_override: Option<&Path>,
) -> miette::Result<SecretsRefreshReport> {
    let inputs = verb_inputs(root, pod_name)?;
    let mut report = SecretsRefreshReport::default();
    if inputs.refs.is_empty() {
        return Ok(report);
    }
    let base = cache_base(cache_base_override)?;
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
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Every test that mutates process env (`XDG_RUNTIME_DIR`, probe
    /// vars, `PATH`) takes this lock — env is process-global and cargo
    /// runs tests in parallel threads.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

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
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("SHUTTLE_SECRETS_TEST_OK", SENTINEL);
        let refs = BTreeMap::from([("K".to_string(), env_ref("SHUTTLE_SECRETS_TEST_OK"))]);
        let values = resolve_references(
            tmp.path(),
            "p",
            3,
            &refs,
            Some(tmp.path().join("cache").as_path()),
        )
        .unwrap();
        std::env::remove_var("SHUTTLE_SECRETS_TEST_OK");
        assert_eq!(values.get("K").map(String::as_str), Some(SENTINEL));
    }

    #[test]
    fn env_source_missing_var_fails_named_and_leaks_nothing() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SHUTTLE_SECRETS_TEST_MISSING");
        let refs = BTreeMap::from([(
            "API_TOKEN".to_string(),
            env_ref("SHUTTLE_SECRETS_TEST_MISSING"),
        )]);
        let err = format!(
            "{}",
            resolve_references(Path::new("/nonexistent-pod"), "p", 3, &refs, None).unwrap_err()
        );
        assert!(err.contains("secret 'API_TOKEN'"), "{err}");
        assert!(err.contains("source 'env'"), "{err}");
        assert!(err.contains("SHUTTLE_SECRETS_TEST_MISSING"), "{err}");
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
        let _lock = ENV_LOCK.lock().unwrap();
        let saved_path = std::env::var("PATH").ok();
        std::env::set_var("PATH", &raw_path);
        let resolved = resolve_exec_program(&pod, "K", "shadow");
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
        let _lock = ENV_LOCK.lock().unwrap();
        let saved_path = std::env::var("PATH").ok();
        std::env::set_var("PATH", &farm);
        let err = format!(
            "{}",
            resolve_exec_program(&pod, "BW_ITEM", "bws").unwrap_err()
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
            resolve_exec_program(&pod, "BW_ITEM", "bws").unwrap_err()
        );
        // (c) The absolute-path form hits the refusal directly.
        let err3 = format!(
            "{}",
            resolve_exec_program(&pod, "BW_ITEM", &tool).unwrap_err()
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
        let _lock = ENV_LOCK.lock().unwrap();
        let saved_path = std::env::var("PATH").ok();
        std::env::set_var("PATH", tmp.path());
        let err = format!(
            "{}",
            resolve_exec_program(tmp.path(), "K", "definitely-not-on-path-183").unwrap_err()
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
        let first = refresh_pod(tmp.path(), "work", Some(&cache)).unwrap();
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
        let second = refresh_pod(tmp.path(), "work", Some(&cache)).unwrap();
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

    // ── empty reference set + runtime-dir gate ──

    #[test]
    fn empty_reference_set_needs_no_runtime_dir_and_resolves_empty() {
        let _lock = ENV_LOCK.lock().unwrap();
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
        let _lock = ENV_LOCK.lock().unwrap();
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
        ENV_VAR  = {{ source = "env", var = "SHUTTLE_SECRETS_TEST_LIST" }},
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
        let _lock = ENV_LOCK.lock().unwrap();
        let (tmp, _counter) = list_fixture();
        let cache = tmp.path().join("cache");
        // Miss before resolve.
        let rows = list_pod(tmp.path(), "work", Some(&cache)).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.cache == "miss"));
        assert_eq!(
            rows.iter().find(|r| r.key == "ENV_VAR").unwrap().reference,
            "env SHUTTLE_SECRETS_TEST_LIST"
        );
        // Resolve (warms the entry at generation 3), then hit.
        std::env::set_var("SHUTTLE_SECRETS_TEST_LIST", SENTINEL);
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
        std::env::remove_var("SHUTTLE_SECRETS_TEST_LIST");
        assert!(rows.iter().all(|r| r.cache == "stale"));
        // The rendered output must not carry a single value substring.
        let text = render_list_rows("work", &rows);
        assert!(!text.contains(SENTINEL), "value leaked into list output");
        assert!(text.contains("EXEC_VAR") && text.contains("ENV_VAR"));
        assert!(text.contains("hit") && text.contains("stale"));
    }

    // ── verbs: check ──

    /// A pod whose references cover all three check statuses: an
    /// unavailable stub (bitwarden), a failing env var, and a working
    /// exec provider.
    fn check_fixture() -> tempfile::TempDir {
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
        BW_ITEM  = {{ source = "bitwarden", id = "8848da48" }},
        ENV_VAR  = {{ source = "env", var = "SHUTTLE_SECRETS_TEST_CHECK" }},
        EXEC_VAR = {{ source = "exec", command = {{ "{provider}" }} }},
    }},
}}
"#
            ),
        );
        activate(tmp.path(), "work");
        tmp
    }

    #[test]
    fn check_reports_per_source_health_and_fails_named() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = check_fixture();
        std::env::remove_var("SHUTTLE_SECRETS_TEST_CHECK");
        let rows = check_pod(tmp.path(), "work").unwrap();
        assert_eq!(rows.len(), 3);
        let by_key = |k: &str| rows.iter().find(|r| r.key == k).unwrap();
        assert_eq!(by_key("BW_ITEM").status, "unavailable");
        assert!(
            by_key("BW_ITEM").note.contains("#185"),
            "{}",
            by_key("BW_ITEM").note
        );
        assert_eq!(by_key("ENV_VAR").status, "failed");
        assert!(
            by_key("ENV_VAR")
                .note
                .contains("SHUTTLE_SECRETS_TEST_CHECK"),
            "{}",
            by_key("ENV_VAR").note
        );
        assert_eq!(by_key("EXEC_VAR").status, "ok");
        assert!(!check_healthy(&rows), "a failing reference means exit 1");
        // No value reaches any report row (D8).
        let text = render_check_rows("work", &rows);
        assert!(!text.contains(SENTINEL), "value leaked into check output");
        // Everything resolvable goes green once the env var exists.
        std::env::set_var("SHUTTLE_SECRETS_TEST_CHECK", SENTINEL);
        let rows = check_pod(tmp.path(), "work").unwrap();
        std::env::remove_var("SHUTTLE_SECRETS_TEST_CHECK");
        let failed: Vec<_> = rows
            .iter()
            .filter(|r| r.status == "failed")
            .map(|r| r.key.as_str())
            .collect();
        assert_eq!(failed, Vec::<&str>::new(), "only BW_ITEM stays unavailable");
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
        let _lock = ENV_LOCK.lock().unwrap();
        let saved = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::remove_var("XDG_RUNTIME_DIR");
        let tmp = tempfile::tempdir().unwrap();
        seed_pod(tmp.path(), "cold", "pod {}");
        activate(tmp.path(), "cold");
        let report = refresh_pod(tmp.path(), "cold", None);
        if let Some(dir) = saved {
            std::env::set_var("XDG_RUNTIME_DIR", dir);
        }
        assert_eq!(report.unwrap(), SecretsRefreshReport::default());
    }
}
