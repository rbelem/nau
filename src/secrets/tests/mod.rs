
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

fn read_dir_count(path: &Path) -> Option<usize> {
    std::fs::read_dir(path).ok().map(|d| d.count())
}

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

/// In-memory stand-in for the session-bus keyring, keyed by the
/// EXACT attribute map. ENV_LOCK serializes all users.
static FAKE_STORE: Mutex<BTreeMap<BTreeMap<String, String>, Vec<u8>>> = Mutex::new(BTreeMap::new());

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

mod bitwarden_calls;
mod check_pod;
mod env_source;
mod envfile_digest;
mod list_reports;
