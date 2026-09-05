//! OCI registry client — push/pull build artifacts to/from plain OCI
//! registries (Phase 25).
//!
//! Transport is the codebase convention: a `curl` subprocess behind an
//! injectable command seam ([`CommandRunner`], the
//! [`RuntimeTools`][crate::runtime::RuntimeTools] precedent). Zero new
//! dependencies; the default runner shells out to the same `curl`
//! `doctor.rs` already requires.
//!
//! # Protocol (the minimal distribution-spec surface)
//!
//! - `GET /v2/` — API version check (401 → `WWW-Authenticate` Bearer
//!   challenge, token fetch, one retry).
//! - `GET {realm}?service=&scope=` — bearer token (`{token}` or
//!   `{access_token}`), cached in memory for the client's lifetime.
//! - `HEAD /v2/<repo>/blobs/<digest>` — dedup probe (200 → skip upload).
//! - `POST /v2/<repo>/blobs/uploads/?digest=<digest>` — monolithic blob
//!   upload (201 = done; 202 = follow `Location` with a finalizing empty
//!   `PUT ...&digest=`). Cross-repo mount (`?mount=&from=`, tried first
//!   with `--mount-from`) is implemented; chunked uploads remain a
//!   documented follow-up.
//! - `PUT /v2/<repo>/manifests/<tag>` — the bundle manifest.
//! - `GET /v2/<repo>/manifests/<ref>` + `GET .../blobs/<digest>` — pull,
//!   every blob digest-verified on receipt (fail-closed).
//!
//! Digests are `sha256:<64 lowercase hex>`. Manifests are plain OCI image
//! manifests with a custom `artifactType` and custom config/layer media
//! types, accepted by Docker Hub / GHCR / zot / distribution / Harbor.
//!
//! # Security posture (fail-closed)
//!
//! - No implicit `docker.io` registry: a reference without an explicit
//!   host is rejected with a named error.
//! - Plain `http://` only with `--insecure-http` (intended for local
//!   registries); an `http://` token realm is refused unless the flag is
//!   set.
//! - Every pulled blob's sha256 is recomputed and compared to the
//!   manifest descriptor; a mismatch deletes the file and errors.
//! - `curl` runs WITHOUT `-f`: the Bearer handshake must read the 401
//!   response body/headers, which `-f` discards. Fail-closed is enforced
//!   one level up instead — every response path checks the status, and
//!   every downloaded artifact is digest-verified, so truncated or
//!   spoofed bodies cannot pass silently.
//!
//! # Timeouts
//!
//! All curl invocations carry `--max-time` (30 s metadata, 300 s blob
//! transfers) plus `--connect-timeout`. This deliberately deviates from
//! the older store.rs/assert.rs calls, which have no timeouts — registry
//! pushes can hang mid-transfer and must fail bounded.
//!
//! # Manual test (no automated registry test in the suite)
//!
//! ```text
//! docker run -d -p 5000:5000 registry:2
//! shuttle build && shuttle push localhost:5000/demo/myapp --insecure-http
//! curl -s localhost:5000/v2/_catalog
//! shuttle pull localhost:5000/demo/myapp:v1 --out-dir ./pulled --insecure-http
//! # (insecure-http only needed because registry:2 ships without TLS)
//! ```
//!
//! The signed binding of pushed artifacts to build facts uses the
//! manifest.rs `Artifact` extension ([`BuiltBlob`]): `push --record`
//! writes the host-side built-manifest record, `pull --expect` verifies
//! received blobs against it fail-closed; `pull --install` resolves
//! revisions from `shuttle.lock` pins and hands [`PendingSnap`]s to
//! `install_batch`.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use miette::miette;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::lock::LockFile;
use crate::manifest::{Artifact, ArtifactState, BuiltBlob, MANIFEST_VERSION};
use crate::output;
use crate::runtime::PendingSnap;
use crate::store::sha3_384_file;

// ── Media types ──

/// The manifest envelope itself.
pub const MEDIA_TYPE_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
/// `artifactType` of a shuttle bundle (snap + optional disk image).
pub const MEDIA_TYPE_ARTIFACT: &str = "application/vnd.shuttle.bundle.v1";
/// Custom (non-image-config) media type for the inline descriptor blob.
pub const MEDIA_TYPE_CONFIG: &str = "application/vnd.shuttle.config.v1+json";
/// A `.snap` payload layer.
pub const MEDIA_TYPE_SNAP: &str = "application/vnd.shuttle.snap.v1";
/// A disk image (`.img`) payload layer.
pub const MEDIA_TYPE_DISK_IMG: &str = "application/vnd.shuttle.disk-img.v1";

// ── Timeouts (bounded transfers; see module docs) ──

pub const METADATA_TIMEOUT_SECS: u64 = 30;
pub const BLOB_TIMEOUT_SECS: u64 = 300;
pub const CONNECT_TIMEOUT_SECS: u64 = 10;

/// Standard annotation carrying the on-disk file name of a layer.
const TITLE_ANNOTATION: &str = "org.opencontainers.image.title";

// ── Reference parsing ──

/// A parsed OCI reference: `[registry[:port]/]repo[:tag|@digest]`.
///
/// The registry host is REQUIRED (the docker.io implicit default is out
/// of scope by design — implicit semantics are how supply-chain mistakes
/// happen). A reference carries either a tag or a digest, never both.
#[derive(Debug, Clone)]
pub struct Reference {
    /// Registry host, `host` or `host:port` (e.g. `localhost:5000`,
    /// `ghcr.io`).
    pub registry: String,
    /// Repository path, one or more `[A-Za-z0-9._-]` segments.
    pub repo: String,
    pub tag: Option<String>,
    /// `sha256:<64 hex>` when the reference was pinned by digest.
    pub digest: Option<String>,
}

impl Reference {
    pub fn parse(input: &str) -> miette::Result<Reference> {
        let s = input.trim();
        if s.is_empty() {
            miette::bail!("empty registry reference");
        }
        if s.contains("://") {
            miette::bail!(
                "reference '{input}' must not include a scheme — \
                 use host[:port]/repo[:tag|@digest]"
            );
        }

        let (rest, digest) = match s.rsplit_once('@') {
            Some((r, d)) => (r, Some(d)),
            None => (s, None),
        };
        if let Some(d) = digest {
            validate_digest(d)?;
        }

        let Some((registry_raw, repo_tail)) = rest.split_once('/') else {
            miette::bail!(
                "reference '{input}' has no explicit registry host — the \
                 docker.io implicit default is out of scope; name one, e.g. \
                 'localhost:5000/{input}' or 'ghcr.io/owner/{input}'"
            );
        };
        let registry = validate_registry(registry_raw, input)?;
        if repo_tail.is_empty() {
            miette::bail!("reference '{input}' has an empty repository path");
        }

        // Tag colon = the last colon AFTER the final '/' (registry ports
        // live before it and must not be mistaken for tags).
        let last_slash = repo_tail.rfind('/').unwrap_or(0);
        let (repo, tag) = match repo_tail.rfind(':') {
            Some(pos) if pos > last_slash => (&repo_tail[..pos], Some(&repo_tail[pos + 1..])),
            _ => (repo_tail, None),
        };
        if repo.is_empty() {
            miette::bail!("reference '{input}' has an empty repository path");
        }
        if let Some(t) = tag {
            validate_tag(t)?;
        }
        if tag.is_some() && digest.is_some() {
            miette::bail!(
                "reference '{input}' carries both a tag and a digest — \
                 use one or the other"
            );
        }
        validate_repo(repo)?;

        Ok(Reference {
            registry,
            repo: repo.to_string(),
            tag: tag.map(str::to_string),
            digest: digest.map(str::to_string),
        })
    }

    /// `https://host` (or `http://` only with the explicit insecure flag).
    pub fn base_url(&self, insecure_http: bool) -> String {
        let scheme = if insecure_http { "http" } else { "https" };
        format!("{scheme}://{}", self.registry)
    }

    /// Human-readable form used in errors and reports.
    pub fn display(&self) -> String {
        let mut s = format!("{}/{}", self.registry, self.repo);
        if let Some(t) = &self.tag {
            s.push(':');
            s.push_str(t);
        }
        if let Some(d) = &self.digest {
            s.push('@');
            s.push_str(d);
        }
        s
    }
}

fn validate_registry(raw: &str, full: &str) -> miette::Result<String> {
    let (host, port) = match raw.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (raw, None),
    };
    if let Some(p) = port {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            miette::bail!("registry '{raw}' in reference '{full}' has a non-numeric port");
        }
    }
    if host.is_empty() {
        miette::bail!("reference '{full}' has an empty registry host");
    }
    let host_like =
        host.eq_ignore_ascii_case("localhost") || host.contains('.') || host.starts_with('['); // IPv6 literal
    if !host_like {
        miette::bail!(
            "reference '{full}' has no explicit registry host ('{raw}' is \
             not host[:port]) — the docker.io implicit default is out of \
             scope; use e.g. 'localhost:5000/{full}' or 'ghcr.io/{full}'"
        );
    }
    Ok(raw.to_string())
}

fn validate_repo(repo: &str) -> miette::Result<()> {
    for seg in repo.split('/') {
        if seg.is_empty() {
            miette::bail!("repository '{repo}' has an empty path segment");
        }
        if !seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            miette::bail!("repository '{repo}' contains characters outside [A-Za-z0-9._-]");
        }
    }
    Ok(())
}

fn validate_tag(tag: &str) -> miette::Result<()> {
    let first = tag.chars().next();
    match first {
        Some(c) if c.is_ascii_alphanumeric() || c == '_' => {}
        _ => miette::bail!("invalid tag '{tag}': must start with [A-Za-z0-9_]"),
    }
    if tag.len() > 128 {
        miette::bail!("invalid tag '{tag}': longer than 128 characters");
    }
    if !tag
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    {
        miette::bail!("invalid tag '{tag}': characters outside [A-Za-z0-9._-]");
    }
    Ok(())
}

/// Validate `sha256:<64 lowercase hex>`; any other algorithm is refused.
pub fn validate_digest(digest: &str) -> miette::Result<()> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        miette::bail!("unsupported digest '{digest}' — only sha256:<hex> is supported");
    };
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        miette::bail!("malformed sha256 digest '{digest}' — expected 64 hex characters");
    }
    if hex.bytes().any(|b| b.is_ascii_uppercase()) {
        miette::bail!("sha256 digest '{digest}' must be lowercase hex");
    }
    Ok(())
}

// ── WWW-Authenticate (Bearer challenge) parsing ──

/// A parsed `WWW-Authenticate: Bearer ...` challenge.
#[derive(Debug, Clone, PartialEq)]
pub struct WwwAuthenticate {
    pub realm: String,
    pub service: Option<String>,
    pub scope: Option<String>,
}

impl WwwAuthenticate {
    /// Parse a challenge value; `None` when it is not Bearer or has no
    /// realm (the only mandatory parameter).
    pub fn parse(value: &str) -> Option<WwwAuthenticate> {
        let rest = value.trim().strip_prefix("Bearer")?;
        if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
            return None; // "Bearerxyz" is not a Bearer challenge
        }
        let mut realm = None;
        let mut service = None;
        let mut scope = None;
        for part in split_params(rest.trim()) {
            let (k, v) = part.split_once('=')?;
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|x| x.strip_suffix('"'))
                .unwrap_or(v);
            match k.trim().to_ascii_lowercase().as_str() {
                "realm" => realm = Some(v.to_string()),
                "service" => service = Some(v.to_string()),
                "scope" => scope = Some(v.to_string()),
                _ => {} // unknown auth parameters are tolerated
            }
        }
        Some(WwwAuthenticate {
            realm: realm?,
            service,
            scope,
        })
    }
}

/// Split `k="v",k2="v,2"` on commas that are not inside quotes.
fn split_params(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut in_quotes = false;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out.into_iter().filter(|p| !p.trim().is_empty()).collect()
}

// ── Command runner seam ──

/// Result of one injected command run.
#[derive(Debug, Clone)]
pub struct RunnerOutput {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

/// Injectable command seam (the `RuntimeTools` precedent): production
/// uses [`CurlRunner`] (a real `curl` subprocess); hermetic tests inject
/// fakes.
///
/// # Fake contract
///
/// The client parses response data from FILES, never from stdout:
/// - `argv[0]` is the program name (`curl`), the URL is the last argument;
/// - `-D <path>`: the HTTP status line + headers must be written there;
/// - `-o <path>`: the response body must be written there.
pub trait CommandRunner {
    fn run(&self, argv: &[String]) -> std::io::Result<RunnerOutput>;
}

/// The real runner: executes `curl` with the exact argv the client built.
pub struct CurlRunner;

impl CommandRunner for CurlRunner {
    fn run(&self, argv: &[String]) -> std::io::Result<RunnerOutput> {
        let (program, args) = argv.split_first().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty command argv")
        })?;
        let out = std::process::Command::new(program).args(args).output()?;
        Ok(RunnerOutput {
            code: out.status.code().unwrap_or(-1),
            stdout: out.stdout,
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

// ── Authentication ──

/// Registry credentials. Both halves or neither — enforced in
/// [`Client::with_runner`].
#[derive(Debug, Clone, Default)]
pub struct Auth {
    pub username: Option<String>,
    pub password: Option<String>,
}

// ── Client ──

/// Outcome of one blob upload ([`Client::upload_blob`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobUpload {
    /// Bytes were transferred (monolithic POST, or a 202 upload session
    /// finalized via the Location PUT).
    Uploaded,
    /// The registry mounted the blob cross-repo — no bytes transferred.
    Mounted,
}

enum Method {
    Get,
    Head,
    Post,
    Put,
}

enum Body {
    None,
    File(PathBuf),
    Empty,
}

struct Request {
    method: Method,
    url: String,
    headers: Vec<(String, String)>,
    body: Body,
    timeout: u64,
    follow_redirects: bool,
    /// Token scope fallback when the challenge does not name one:
    /// `"pull"` or `"pull,push"`.
    scope: &'static str,
}

struct RawResponse {
    status: u16,
    /// Header names lowercased.
    headers: Vec<(String, String)>,
    body_file: PathBuf,
}

impl RawResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn body(&self) -> miette::Result<Vec<u8>> {
        std::fs::read(&self.body_file).map_err(|e| miette!("failed to read response body: {e}"))
    }

    fn body_text(&self) -> miette::Result<String> {
        let bytes = self.body()?;
        String::from_utf8(bytes).map_err(|e| miette!("response body is not valid UTF-8: {e}"))
    }
}

/// A distribution-registry client bound to one [`Reference`]. Holds the
/// bearer token in memory for its lifetime; sync + single-threaded by
/// construction (the CLI is sync).
pub struct Client {
    runner: Box<dyn CommandRunner>,
    reference: Reference,
    auth: Auth,
    insecure_http: bool,
    /// Set when the registry answered 401 without a Bearer challenge and
    /// credentials exist: retry once with HTTP Basic.
    basic_mode: Cell<bool>,
    token: RefCell<Option<String>>,
    scratch: tempfile::TempDir,
}

impl Client {
    pub fn new(reference: Reference, auth: Auth, insecure_http: bool) -> miette::Result<Client> {
        Self::with_runner(reference, auth, insecure_http, Box::new(CurlRunner))
    }

    fn with_runner(
        reference: Reference,
        auth: Auth,
        insecure_http: bool,
        runner: Box<dyn CommandRunner>,
    ) -> miette::Result<Client> {
        if auth.username.is_some() != auth.password.is_some() {
            miette::bail!("--username and --password-stdin must be provided together");
        }
        let scratch =
            tempfile::tempdir().map_err(|e| miette!("failed to create scratch dir: {e}"))?;
        Ok(Client {
            runner,
            reference,
            auth,
            insecure_http,
            basic_mode: Cell::new(false),
            token: RefCell::new(None),
            scratch,
        })
    }

    fn base_url(&self) -> String {
        self.reference.base_url(self.insecure_http)
    }

    // ── request plumbing ──

    fn exec(&self, req: &Request, auth_args: &[String]) -> miette::Result<RawResponse> {
        let header_file = self.scratch.path().join("headers.txt");
        let body_file = self.scratch.path().join("body.bin");
        let mut argv: Vec<String> = vec![
            "curl".into(),
            "-sS".into(),
            "--connect-timeout".into(),
            CONNECT_TIMEOUT_SECS.to_string(),
            "--max-time".into(),
            req.timeout.to_string(),
        ];
        match req.method {
            Method::Get => {}
            Method::Head => argv.push("--head".into()),
            Method::Post => argv.extend(["-X".into(), "POST".into()]),
            Method::Put => argv.extend(["-X".into(), "PUT".into()]),
        }
        if req.follow_redirects {
            argv.push("-L".into());
        }
        for (k, v) in &req.headers {
            argv.extend(["-H".into(), format!("{k}: {v}")]);
        }
        argv.extend_from_slice(auth_args);
        match &req.body {
            Body::None => {}
            Body::File(p) => argv.extend(["--data-binary".into(), format!("@{}", p.display())]),
            Body::Empty => argv.extend(["--data-binary".into(), String::new()]),
        }
        argv.extend(["-D".into(), header_file.to_string_lossy().into_owned()]);
        argv.extend(["-o".into(), body_file.to_string_lossy().into_owned()]);
        argv.push(req.url.clone());

        let out = self
            .runner
            .run(&argv)
            .map_err(|e| miette!("curl not found: {e}"))?;
        if out.code != 0 {
            return Err(miette!(
                "registry request to {} failed (curl exit {}{}): {}",
                req.url,
                out.code,
                curl_failure_hint(out.code),
                out.stderr.trim()
            ));
        }
        let text = std::fs::read_to_string(&header_file)
            .map_err(|e| miette!("failed to read curl header dump: {e}"))?;
        let (status, headers) = parse_headers(&text);
        if status == 0 {
            miette::bail!(
                "could not parse HTTP status from registry response for {}",
                req.url
            );
        }
        Ok(RawResponse {
            status,
            headers,
            body_file,
        })
    }

    fn auth_args(&self) -> Vec<String> {
        if let Some(t) = self.token.borrow().as_deref() {
            return vec!["-H".into(), format!("Authorization: Bearer {t}")];
        }
        if self.basic_mode.get() {
            if let (Some(u), Some(p)) = (&self.auth.username, &self.auth.password) {
                // Note: credentials are visible in the curl argv (process
                // list) — the standard curl -u tradeoff, over TLS by default.
                return vec!["-u".into(), format!("{u}:{p}")];
            }
        }
        Vec::new()
    }

    /// One request with the Bearer handshake: on 401, authenticate and
    /// retry ONCE; a second 401 fails closed.
    fn request(&self, req: &Request) -> miette::Result<RawResponse> {
        let mut resp = self.exec(req, &self.auth_args())?;
        if resp.status == 401 {
            let challenge = resp.header("www-authenticate").map(str::to_string);
            self.authorize(challenge.as_deref(), req)?;
            resp = self.exec(req, &self.auth_args())?;
            if resp.status == 401 {
                miette::bail!(
                    "registry returned 401 for {} even after authentication — \
                     check credentials/scopes",
                    req.url
                );
            }
        }
        Ok(resp)
    }

    fn authorize(&self, challenge: Option<&str>, req: &Request) -> miette::Result<()> {
        match challenge.and_then(WwwAuthenticate::parse) {
            Some(ch) => self.fetch_token(&ch, req),
            None => {
                if self.auth.username.is_some() {
                    self.basic_mode.set(true);
                    Ok(())
                } else {
                    Err(miette!(
                        "registry requires authentication (HTTP 401) and no \
                         credentials were provided — pass --username with \
                         --password-stdin"
                    ))
                }
            }
        }
    }

    fn fetch_token(&self, ch: &WwwAuthenticate, req: &Request) -> miette::Result<()> {
        if ch.realm.starts_with("http://") && !self.insecure_http {
            miette::bail!(
                "token realm '{}' is plain http — refusing to send credentials \
                 over an unencrypted connection (pass --insecure-http only for \
                 local registries)",
                ch.realm
            );
        }
        let scope = ch
            .scope
            .clone()
            .unwrap_or_else(|| format!("repository:{}:{}", self.reference.repo, req.scope));
        let sep = if ch.realm.contains('?') { '&' } else { '?' };
        let mut url = format!("{}{}scope={scope}", ch.realm, sep);
        if let Some(svc) = &ch.service {
            url.push_str(&format!("&service={svc}"));
        }
        let token_req = Request {
            method: Method::Get,
            url,
            headers: Vec::new(),
            body: Body::None,
            timeout: METADATA_TIMEOUT_SECS,
            follow_redirects: true,
            scope: req.scope,
        };
        let basic: Vec<String> = match (&self.auth.username, &self.auth.password) {
            (Some(u), Some(p)) => vec!["-u".into(), format!("{u}:{p}")],
            _ => Vec::new(),
        };
        let resp = self.exec(&token_req, &basic)?;
        if resp.status != 200 {
            miette::bail!(
                "token endpoint {} returned HTTP {} — credentials likely invalid",
                ch.realm,
                resp.status
            );
        }

        #[derive(Deserialize)]
        struct TokenResponse {
            token: Option<String>,
            #[serde(rename = "access_token")]
            access_token: Option<String>,
        }
        let parsed: TokenResponse = serde_json::from_str(&resp.body_text()?)
            .map_err(|e| miette!("invalid token response from {}: {e}", ch.realm))?;
        let token = parsed
            .token
            .or(parsed.access_token)
            .filter(|t| !t.is_empty());
        match token {
            Some(t) => {
                *self.token.borrow_mut() = Some(t);
                Ok(())
            }
            None => Err(miette!("token endpoint {} returned no token", ch.realm)),
        }
    }

    // ── public operations ──

    /// `GET /v2/` — must ultimately answer 200 (401 handling included).
    pub fn version_check(&self) -> miette::Result<()> {
        let url = format!("{}/v2/", self.base_url());
        let req = Request {
            method: Method::Get,
            url: url.clone(),
            headers: Vec::new(),
            body: Body::None,
            timeout: METADATA_TIMEOUT_SECS,
            follow_redirects: true,
            scope: "pull",
        };
        let resp = self.request(&req)?;
        if resp.status == 200 {
            Ok(())
        } else {
            Err(miette!(
                "registry version check failed: GET {url} returned HTTP {}",
                resp.status
            ))
        }
    }

    /// `HEAD /v2/<repo>/blobs/<digest>` — dedup probe.
    pub fn blob_exists(&self, digest: &str) -> miette::Result<bool> {
        validate_digest(digest)?;
        let url = format!(
            "{}/v2/{}/blobs/{digest}",
            self.base_url(),
            self.reference.repo
        );
        let req = Request {
            method: Method::Head,
            url: url.clone(),
            headers: Vec::new(),
            body: Body::None,
            timeout: METADATA_TIMEOUT_SECS,
            follow_redirects: false,
            scope: "pull",
        };
        let resp = self.request(&req)?;
        match resp.status {
            200 => Ok(true),
            404 => Ok(false),
            s => Err(miette!(
                "unexpected HTTP {s} checking blob {digest} at {url}"
            )),
        }
    }

    /// Upload one blob, optionally attempting a cross-repo mount first:
    /// `POST .../blobs/uploads/?mount=<digest>&from=<from_repo>`.
    /// 201 = the registry mounted the blob from `from_repo` (no bytes
    /// transferred) → [`BlobUpload::Mounted`]. 202 = no mount; the
    /// returned `Location` names the upload session, finalized with the
    /// digest PUT → [`BlobUpload::Uploaded`]. Without `mount_from` this
    /// is the plain monolithic upload (`?digest=<digest>`), always
    /// [`BlobUpload::Uploaded`]. (Chunked uploads remain a documented
    /// follow-up.)
    pub fn upload_blob(
        &self,
        file: &Path,
        digest: &str,
        mount_from: Option<&str>,
    ) -> miette::Result<BlobUpload> {
        validate_digest(digest)?;
        let url = match mount_from {
            Some(from) => format!(
                "{}/v2/{}/blobs/uploads/?mount={digest}&from={from}",
                self.base_url(),
                self.reference.repo
            ),
            None => format!(
                "{}/v2/{}/blobs/uploads/?digest={digest}",
                self.base_url(),
                self.reference.repo
            ),
        };
        let req = Request {
            method: Method::Post,
            url: url.clone(),
            headers: vec![("Content-Type".into(), "application/octet-stream".into())],
            body: Body::File(file.to_path_buf()),
            timeout: BLOB_TIMEOUT_SECS,
            follow_redirects: false,
            scope: "pull,push",
        };
        let resp = self.request(&req)?;
        match resp.status {
            201 => Ok(if mount_from.is_some() {
                BlobUpload::Mounted
            } else {
                BlobUpload::Uploaded
            }),
            202 => {
                let location = resp
                    .header("location")
                    .ok_or_else(|| miette!("registry returned 202 without an upload Location"))?
                    .to_string();
                let finalize = Request {
                    method: Method::Put,
                    url: self.finalize_url(&location, digest),
                    headers: Vec::new(),
                    body: Body::Empty,
                    timeout: BLOB_TIMEOUT_SECS,
                    follow_redirects: false,
                    scope: "pull,push",
                };
                let r2 = self.request(&finalize)?;
                if r2.status == 201 {
                    Ok(BlobUpload::Uploaded)
                } else {
                    Err(miette!(
                        "blob finalize PUT returned HTTP {} for {digest}",
                        r2.status
                    ))
                }
            }
            s => Err(miette!("blob upload POST returned HTTP {s} for {digest}")),
        }
    }

    /// Resolve a possibly-relative upload Location and guarantee the
    /// `digest` query parameter is present.
    fn finalize_url(&self, location: &str, digest: &str) -> String {
        let base = self.base_url();
        let url = if location.starts_with("http://") || location.starts_with("https://") {
            location.to_string()
        } else if location.starts_with('/') {
            format!("{base}{location}")
        } else {
            format!("{base}/{location}")
        };
        if url.contains("digest=") {
            url
        } else if url.contains('?') {
            format!("{url}&digest={digest}")
        } else {
            format!("{url}?digest={digest}")
        }
    }

    /// `PUT /v2/<repo>/manifests/<tag>` — returns the manifest digest.
    pub fn push_manifest(&self, manifest: &[u8], tag: &str) -> miette::Result<String> {
        let path = self.scratch.path().join("manifest.json");
        std::fs::write(&path, manifest).map_err(|e| miette!("failed to stage manifest: {e}"))?;
        let url = format!(
            "{}/v2/{}/manifests/{tag}",
            self.base_url(),
            self.reference.repo
        );
        let req = Request {
            method: Method::Put,
            url: url.clone(),
            headers: vec![("Content-Type".into(), MEDIA_TYPE_MANIFEST.into())],
            body: Body::File(path),
            timeout: METADATA_TIMEOUT_SECS,
            follow_redirects: false,
            scope: "pull,push",
        };
        let resp = self.request(&req)?;
        if resp.status == 201 {
            Ok(format!("sha256:{}", sha256_hex(manifest)))
        } else {
            let detail = resp.body_text().unwrap_or_default();
            Err(miette!(
                "manifest PUT returned HTTP {} for {url}: {}",
                resp.status,
                detail.trim()
            ))
        }
    }

    /// `GET /v2/<repo>/manifests/<ref>` with the OCI manifest Accept
    /// header. When `expected_digest` is set (pulled by `@digest`), the
    /// received body's sha256 must match — fail-closed otherwise.
    pub fn pull_manifest(
        &self,
        tag_or_digest: &str,
        expected_digest: Option<&str>,
    ) -> miette::Result<PulledManifest> {
        let url = format!(
            "{}/v2/{}/manifests/{tag_or_digest}",
            self.base_url(),
            self.reference.repo
        );
        let req = Request {
            method: Method::Get,
            url: url.clone(),
            headers: vec![("Accept".into(), MEDIA_TYPE_MANIFEST.into())],
            body: Body::None,
            timeout: METADATA_TIMEOUT_SECS,
            follow_redirects: true,
            scope: "pull",
        };
        let resp = self.request(&req)?;
        if resp.status != 200 {
            miette::bail!("manifest GET returned HTTP {} for {url}", resp.status);
        }
        let bytes = resp.body()?;
        let digest = format!("sha256:{}", sha256_hex(&bytes));
        if let Some(exp) = expected_digest {
            validate_digest(exp)?;
            if exp != digest {
                miette::bail!(
                    "manifest digest mismatch: expected {exp}, received sha256:{digest} — \
                     the registry content was tampered with or the reference is stale"
                );
            }
        }
        let manifest: OciManifest = serde_json::from_slice(&bytes)
            .map_err(|e| miette!("invalid OCI manifest from {url}: {e}"))?;
        Ok(PulledManifest { digest, manifest })
    }

    /// `GET /v2/<repo>/blobs/<digest>`, copied to `dest`, sha256-verified
    /// on receipt. A mismatch deletes the file and fails closed.
    pub fn pull_blob(&self, digest: &str, dest: &Path) -> miette::Result<u64> {
        validate_digest(digest)?;
        let url = format!(
            "{}/v2/{}/blobs/{digest}",
            self.base_url(),
            self.reference.repo
        );
        let req = Request {
            method: Method::Get,
            url: url.clone(),
            headers: Vec::new(),
            body: Body::None,
            timeout: BLOB_TIMEOUT_SECS,
            follow_redirects: true,
            scope: "pull",
        };
        let resp = self.request(&req)?;
        if resp.status != 200 {
            miette::bail!("blob GET returned HTTP {} for {digest}", resp.status);
        }
        std::fs::copy(&resp.body_file, dest)
            .map_err(|e| miette!("failed to write {}: {e}", dest.display()))?;
        let actual = sha256_file(dest)?;
        let expected_hex = digest.strip_prefix("sha256:").unwrap_or(digest);
        if actual != expected_hex {
            let _ = std::fs::remove_file(dest);
            miette::bail!(
                "blob digest mismatch for {digest}: received sha256:{actual} — \
                 failing closed (file removed)"
            );
        }
        let size = std::fs::metadata(dest)
            .map(|m| m.len())
            .map_err(|e| miette!("failed to stat {}: {e}", dest.display()))?;
        Ok(size)
    }
}

/// A manifest as received from the registry.
#[derive(Debug)]
pub struct PulledManifest {
    /// sha256 of the received manifest bytes.
    pub digest: String,
    pub manifest: OciManifest,
}

/// Subset of the OCI image manifest this tool consumes.
#[derive(Debug, Deserialize)]
pub struct OciManifest {
    #[serde(rename = "mediaType")]
    pub media_type: Option<String>,
    #[serde(rename = "artifactType")]
    pub artifact_type: Option<String>,
    #[serde(default)]
    pub config: OciDescriptor,
    #[serde(default)]
    pub layers: Vec<OciDescriptor>,
    #[serde(default)]
    pub annotations: HashMap<String, String>,
}

/// One OCI content descriptor.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct OciDescriptor {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub annotations: HashMap<String, String>,
}

fn curl_failure_hint(code: i32) -> &'static str {
    match code {
        6 => " — DNS resolution failed",
        7 => " — connection refused",
        28 => " — timed out",
        35 => " — TLS handshake failed",
        60 => " — TLS certificate verification failed",
        _ => "",
    }
}

/// Parse a curl `-D` header dump. Redirect chains emit several responses;
/// the LAST status line wins and its header block is kept.
fn parse_headers(text: &str) -> (u16, Vec<(String, String)>) {
    let mut status = 0u16;
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if line.starts_with("HTTP/") {
            status = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            headers.clear();
        } else if line.starts_with(' ') || line.starts_with('\t') {
            if let Some((_, v)) = headers.last_mut() {
                v.push(' ');
                v.push_str(line.trim());
            }
        } else if let Some((k, v)) = line.split_once(':') {
            if status != 0 {
                headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
            }
        }
    }
    (status, headers)
}

// ── Digests ──

/// Hex sha256 of in-memory bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Hex sha256 of a file (streaming, memory-efficient) — the sha2 twin of
/// `store.rs::sha3_384_file`.
pub fn sha256_file(path: &Path) -> miette::Result<String> {
    let mut file =
        std::fs::File::open(path).map_err(|e| miette!("failed to open {}: {e}", path.display()))?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| miette!("failed to read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let hash = hasher.finalize();
    Ok(hash.iter().map(|b| format!("{b:02x}")).collect())
}

// ── Artifacts & manifest building ──

/// One discovered artifact ready to become a layer.
#[derive(Debug, Clone)]
pub struct ArtifactFile {
    pub path: PathBuf,
    /// On-disk file name (the layer `org.opencontainers.image.title`).
    pub title: String,
    pub media_type: &'static str,
    pub digest: String,
    pub size: u64,
}

/// Name/version/architecture shared by every artifact in a bundle.
#[derive(Debug, Clone)]
pub struct BundleMeta {
    pub name: String,
    pub version: String,
    pub arch: String,
}

/// Map a file extension to its shuttle layer media type.
pub fn media_type_for_path(path: &Path) -> miette::Result<&'static str> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("snap") => Ok(MEDIA_TYPE_SNAP),
        Some("img") => Ok(MEDIA_TYPE_DISK_IMG),
        other => Err(miette!(
            "unsupported artifact extension {other:?} on {} — only .snap and .img are pushed",
            path.display()
        )),
    }
}

/// Derive `(name, version, arch?)` from `{name}_{version}_{arch}.snap` /
/// `.img`, or `(name, version)` from `{name}_{version}.img`.
///
/// Underscore-separated parts beyond the third are ambiguous (a version
/// like `1.0_beta` breaks the shape) and are rejected — push those with
/// an explicit `--tag` instead.
pub fn parse_artifact_filename(path: &Path) -> miette::Result<(String, String, Option<String>)> {
    let file = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| miette!("{}: non-UTF-8 file name", path.display()))?;
    let stem = file.rsplit_once('.').map(|(s, _)| s).unwrap_or(file);
    let parts: Vec<&str> = stem.split('_').collect();
    let (name, version, arch) = match parts.as_slice() {
        [n, v] => (*n, *v, None),
        [n, v, a] => (*n, *v, Some(*a)),
        _ => miette::bail!(
            "{file}: cannot derive name/version/arch — expected \
             {{name}}_{{version}}_{{arch}}.snap or {{name}}_{{version}}.img \
             (file names with extra '_' components are ambiguous; push with \
             an explicit --tag)"
        ),
    };
    if name.is_empty() || version.is_empty() {
        miette::bail!("{file}: empty name or version component");
    }
    Ok((
        name.to_string(),
        version.to_string(),
        arch.map(str::to_string),
    ))
}

/// Non-recursive `*.snap` / `*.img` discovery, sorted for determinism.
pub fn discover_artifacts(dir: &Path) -> miette::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(dir)
        .map_err(|e| miette!("failed to read artifact directory {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| miette!("failed to read {}: {e}", dir.display()))?;
        let p = entry.path();
        if p.is_file()
            && matches!(
                p.extension().and_then(|e| e.to_str()),
                Some("snap") | Some("img")
            )
        {
            out.push(p);
        }
    }
    out.sort();
    if out.is_empty() {
        miette::bail!(
            "no .snap or .img artifacts found in '{}' — build first, or pass \
             --snap/--image/--dir",
            dir.display()
        );
    }
    Ok(out)
}

/// Every artifact must share one name/version/arch — a bundle is one
/// versioned unit.
fn bundle_meta(files: &[(String, String, Option<String>)]) -> miette::Result<BundleMeta> {
    let Some(first) = files.first() else {
        miette::bail!("internal: no artifacts in bundle");
    };
    for (n, v, _) in files {
        if n != &first.0 || v != &first.1 {
            miette::bail!(
                "bundle mixes artifacts with different name/version \
                 ('{}_{}' vs '{}_{}') — push one version at a time",
                first.0,
                first.1,
                n,
                v
            );
        }
    }
    let mut arch: Option<&str> = None;
    for (_, _, a) in files {
        if let Some(a) = a {
            match arch {
                None => arch = Some(a),
                Some(prev) if prev != a => {
                    miette::bail!("bundle mixes architectures ({prev} vs {a})");
                }
                _ => {}
            }
        }
    }
    let arch = arch.ok_or_else(|| {
        miette!(
            "cannot determine bundle architecture — no artifact file name \
             carries an _arch component (e.g. use {{name}}_{{version}}_{{arch}}.snap)"
        )
    })?;
    Ok(BundleMeta {
        name: first.0.clone(),
        version: first.1.clone(),
        arch: arch.to_string(),
    })
}

/// Map a human string to the registry tag charset
/// `[A-Za-z0-9_][A-Za-z0-9._-]{0,127}`: disallowed characters become
/// '-', leading '-'/'.' are dropped, the result is capped at 128 chars,
/// and a fully-erased input becomes `untitled`.
pub fn sanitize_tag(input: &str) -> String {
    let mapped: String = input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = mapped.trim_start_matches(['-', '.']);
    let tag: String = trimmed.chars().take(128).collect();
    if tag.is_empty() {
        "untitled".into()
    } else {
        tag
    }
}

fn default_tag(meta: &BundleMeta) -> String {
    sanitize_tag(&format!("{}-{}", meta.name, meta.version))
}

// ── Timestamps (no chrono dependency) ──

/// Current UTC time, RFC 3339 (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn rfc3339_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_rfc3339(secs)
}

fn format_rfc3339(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let sod = secs % 86400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

/// Days-since-epoch → `(year, month, day)` (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ── Manifest assembly ──

#[derive(Serialize)]
struct ShuttleConfigJson {
    name: String,
    version: String,
    arch: String,
    created: String,
    shuttle_manifest_version: u32,
}

#[derive(Serialize)]
struct DescriptorJson {
    #[serde(rename = "mediaType")]
    media_type: String,
    digest: String,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    annotations: Option<BTreeMap<String, String>>,
}

#[derive(Serialize)]
struct ManifestJson {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    #[serde(rename = "mediaType")]
    media_type: &'static str,
    #[serde(rename = "artifactType")]
    artifact_type: &'static str,
    config: DescriptorJson,
    layers: Vec<DescriptorJson>,
    annotations: BTreeMap<String, String>,
}

/// The inline config blob WE generate (NOT the eval manifest): identity
/// metadata + the shuttle manifest IR version this bundle was built
/// from. Returns (bytes, sha256).
///
/// Binding these artifacts cryptographically to the signed eval manifest
/// is the documented follow-up (requires the manifest.rs `Artifact`
/// extension); this config is registry-visible identity only.
pub fn build_config(meta: &BundleMeta, created: &str) -> miette::Result<(Vec<u8>, String)> {
    let config = ShuttleConfigJson {
        name: meta.name.clone(),
        version: meta.version.clone(),
        arch: meta.arch.clone(),
        created: created.to_string(),
        shuttle_manifest_version: MANIFEST_VERSION,
    };
    let bytes = serde_json::to_vec(&config).map_err(|e| miette!("config serialization: {e}"))?;
    let digest = sha256_hex(&bytes);
    Ok((bytes, digest))
}

/// Build the OCI image manifest for a bundle. Returns (json bytes,
/// sha256 digest).
///
/// NOTE: the manifest carries a wall-clock `created` timestamp, so the
/// PUSH MANIFEST is not byte-reproducible. Reproducibility lives in the
/// payload blobs (content-addressed) and the deterministic config body;
/// the registry manifest is transport, not the artifact of record.
pub fn build_manifest(
    meta: &BundleMeta,
    artifacts: &[ArtifactFile],
    created: &str,
) -> miette::Result<(Vec<u8>, String)> {
    let (config_bytes, config_digest) = build_config(meta, created)?;
    let layers = artifacts
        .iter()
        .map(|a| DescriptorJson {
            media_type: a.media_type.to_string(),
            digest: a.digest.clone(),
            size: a.size,
            annotations: Some(BTreeMap::from([(
                TITLE_ANNOTATION.to_string(),
                a.title.clone(),
            )])),
        })
        .collect();
    let manifest = ManifestJson {
        schema_version: 2,
        media_type: MEDIA_TYPE_MANIFEST,
        artifact_type: MEDIA_TYPE_ARTIFACT,
        config: DescriptorJson {
            media_type: MEDIA_TYPE_CONFIG.into(),
            digest: format!("sha256:{config_digest}"),
            size: config_bytes.len() as u64,
            annotations: None,
        },
        layers,
        annotations: BTreeMap::from([
            (
                "org.opencontainers.image.created".into(),
                created.to_string(),
            ),
            (TITLE_ANNOTATION.into(), meta.name.clone()),
            (
                "org.opencontainers.image.version".into(),
                meta.version.clone(),
            ),
        ]),
    };
    let bytes =
        serde_json::to_vec(&manifest).map_err(|e| miette!("manifest serialization: {e}"))?;
    let digest = format!("sha256:{}", sha256_hex(&bytes));
    Ok((bytes, digest))
}

// ── Push / pull orchestration ──

/// A fully planned push: agreed identity, resolved tag, hashed artifacts.
#[derive(Debug, Clone)]
pub struct PushPlan {
    pub meta: BundleMeta,
    pub tag: String,
    pub artifacts: Vec<ArtifactFile>,
}

/// Assemble the push plan. Explicit files win over `--dir` discovery;
/// the tag resolves as `--tag` > reference tag > `<name>-<version>`
/// (sanitized). Pushing to a `@digest` reference is refused.
pub fn plan_push(
    dir: &Path,
    explicit: &[PathBuf],
    tag_override: Option<&str>,
    reference: &Reference,
) -> miette::Result<PushPlan> {
    if reference.digest.is_some() {
        miette::bail!(
            "cannot push to a digest reference '{}' — pushing addresses a tag",
            reference.display()
        );
    }
    let paths: Vec<PathBuf> = if explicit.is_empty() {
        discover_artifacts(dir)?
    } else {
        explicit.to_vec()
    };
    let mut artifacts = Vec::new();
    let mut triples = Vec::new();
    for p in &paths {
        let media_type = media_type_for_path(p)?;
        let (name, version, arch) = parse_artifact_filename(p)?;
        let digest = format!("sha256:{}", sha256_file(p)?);
        let size = std::fs::metadata(p)
            .map_err(|e| miette!("failed to stat {}: {e}", p.display()))?
            .len();
        let title = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        triples.push((name, version, arch));
        artifacts.push(ArtifactFile {
            path: p.clone(),
            title,
            media_type,
            digest,
            size,
        });
    }
    let meta = bundle_meta(&triples)?;
    let tag = tag_override
        .map(str::to_string)
        .or_else(|| reference.tag.clone())
        .unwrap_or_else(|| default_tag(&meta));
    validate_tag(&tag)?;
    Ok(PushPlan {
        meta,
        tag,
        artifacts,
    })
}

// ── JSON reports ──

/// One blob's push outcome.
#[derive(Debug, Serialize)]
pub struct PushedBlobJson {
    pub file: String,
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    /// True when the HEAD probe found the blob already in the registry.
    pub existed: bool,
    /// True when the registry mounted the blob cross-repo
    /// (`--mount-from`) instead of receiving the bytes (deduped-reused).
    pub mounted: bool,
}

/// `shuttle push --json` payload.
#[derive(Debug, Serialize)]
pub struct PushReportJson {
    pub command: String,
    pub reference: String,
    pub tag: String,
    pub manifest_digest: String,
    pub blobs: Vec<PushedBlobJson>,
}

/// One pulled file.
#[derive(Debug, Serialize)]
pub struct PulledFileJson {
    pub path: String,
    pub digest: String,
    pub size: u64,
}

/// `shuttle pull --json` payload.
#[derive(Debug, Serialize)]
pub struct PullReportJson {
    pub command: String,
    pub reference: String,
    pub manifest_digest: String,
    pub files: Vec<PulledFileJson>,
    /// Present when `pull --install` installed the pulled `.snap`
    /// payloads into a state root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install: Option<crate::runtime::InstallReport>,
}

/// Push a bundle (real client). See [`push_with`] for the injected form.
/// `mount_from` (the `--mount-from` repository) attempts cross-repo blob
/// mounts before uploading; `None` (or an empty repo) skips mounts.
pub fn push(
    reference: &Reference,
    plan: &PushPlan,
    auth: Auth,
    insecure_http: bool,
    mount_from: Option<&str>,
) -> miette::Result<PushReportJson> {
    let client = Client::new(reference.clone(), auth, insecure_http)?;
    push_with(&client, reference, plan, mount_from)
}

fn push_with(
    client: &Client,
    reference: &Reference,
    plan: &PushPlan,
    mount_from: Option<&str>,
) -> miette::Result<PushReportJson> {
    let mount_from = mount_from.filter(|r| !r.is_empty());
    let sp = output::spinner("checking registry API version...");
    client.version_check()?;
    output::finish_ok(
        &sp,
        &format!("{} — OCI v2 endpoint reachable", reference.registry),
    );

    let mut blobs = Vec::new();
    for a in &plan.artifacts {
        let short = &a.digest[..19.min(a.digest.len())];
        let sp = output::spinner(&format!("checking blob {short}..."));
        let existed = client.blob_exists(&a.digest)?;
        let mut mounted = false;
        if existed {
            output::finish_ok(&sp, &format!("{} already in registry", a.title));
        } else {
            sp.set_message(format!("uploading {} ({} bytes)...", a.title, a.size));
            let upload = client.upload_blob(&a.path, &a.digest, mount_from)?;
            mounted = upload == BlobUpload::Mounted;
            match upload {
                BlobUpload::Mounted => output::finish_ok(
                    &sp,
                    &format!(
                        "{} mounted from registry (cross-repo dedup via '{}')",
                        a.title,
                        mount_from.unwrap_or_default()
                    ),
                ),
                BlobUpload::Uploaded => output::finish_ok(&sp, &format!("{} uploaded", a.title)),
            }
        }
        blobs.push(PushedBlobJson {
            file: a.title.clone(),
            media_type: a.media_type.to_string(),
            digest: a.digest.clone(),
            size: a.size,
            existed,
            mounted,
        });
    }

    let created = rfc3339_now();
    let (bytes, manifest_digest) = build_manifest(&plan.meta, &plan.artifacts, &created)?;
    client.push_manifest(&bytes, &plan.tag)?;
    output::ok(format!(
        "pushed {}:{} — manifest {}",
        reference.display(),
        plan.tag,
        &manifest_digest[..19.min(manifest_digest.len())]
    ));

    Ok(PushReportJson {
        command: "push".into(),
        reference: reference.display(),
        tag: plan.tag.clone(),
        manifest_digest,
        blobs,
    })
}

/// Pull a bundle (real client). See [`pull_with`] for the injected form.
/// `expect` (from `pull --expect`) verifies received blobs against a
/// built-manifest record IN ADDITION to the OCI descriptors.
pub fn pull(
    reference: &Reference,
    out_dir: &Path,
    auth: Auth,
    insecure_http: bool,
    expect: Option<&Artifact>,
) -> miette::Result<PullReportJson> {
    let client = Client::new(reference.clone(), auth, insecure_http)?;
    pull_with(&client, reference, out_dir, expect)
}

/// Pull a bundle: manifest → per-blob digest-verified download into
/// `out_dir`, files named by their `org.opencontainers.image.title`
/// annotation (i.e. the original `{name}_{version}_{arch}.snap` names —
/// shaped for the `--install` PendingSnap wiring). When `expect` is
/// given, every layer must appear in the record with matching size and
/// media type, and every record blob must arrive — any deviation fails
/// closed (fail-closed on top of the OCI descriptor sha256 checks).
fn pull_with(
    client: &Client,
    reference: &Reference,
    out_dir: &Path,
    expect: Option<&Artifact>,
) -> miette::Result<PullReportJson> {
    let ref_part = match (reference.tag.as_deref(), reference.digest.as_deref()) {
        (Some(t), _) => t.to_string(),
        (None, Some(d)) => d.to_string(),
        (None, None) => {
            miette::bail!(
                "pull reference '{}' needs a tag or @digest — there is no \
                 default tag",
                reference.display()
            );
        }
    };

    let sp = output::spinner("checking registry API version...");
    client.version_check()?;
    output::finish_ok(
        &sp,
        &format!("{} — OCI v2 endpoint reachable", reference.registry),
    );

    let pulled = client.pull_manifest(&ref_part, reference.digest.as_deref())?;
    if pulled.manifest.layers.is_empty() {
        miette::bail!("manifest {} has no layers — nothing to pull", pulled.digest);
    }
    output::ok(format!(
        "manifest {} — {} layer(s)",
        &pulled.digest[..19.min(pulled.digest.len())],
        pulled.manifest.layers.len()
    ));

    std::fs::create_dir_all(out_dir)
        .map_err(|e| miette!("failed to create {}: {e}", out_dir.display()))?;
    let expect_map: Option<HashMap<&str, &BuiltBlob>> =
        expect.map(|e| e.blobs.iter().map(|b| (b.digest.as_str(), b)).collect());
    let mut matched: HashSet<&str> = HashSet::new();
    let mut seen = HashSet::new();
    let mut files = Vec::new();
    for layer in &pulled.manifest.layers {
        validate_digest(&layer.digest)?;
        let title = layer.annotations.get(TITLE_ANNOTATION).ok_or_else(|| {
            miette!(
                "layer {} has no '{TITLE_ANNOTATION}' annotation — refusing to \
                 invent a file name",
                layer.digest
            )
        })?;
        if !seen.insert(title.clone()) {
            miette::bail!("manifest contains duplicate title '{title}'");
        }
        let dest = out_dir.join(title);
        let sp = output::spinner(&format!("fetching {title}..."));
        let size = client.pull_blob(&layer.digest, &dest)?;
        output::finish_ok(&sp, &format!("{title} — sha256 verified"));
        if let Some(map) = &expect_map {
            let Some(blob) = map.get(layer.digest.as_str()) else {
                let _ = std::fs::remove_file(&dest);
                miette::bail!(
                    "pulled blob {} ('{title}') is not in the expected \
                     built-manifest record — refusing to accept it (fail-closed; \
                     file removed)",
                    layer.digest
                );
            };
            if blob.size != layer.size {
                let _ = std::fs::remove_file(&dest);
                miette::bail!(
                    "blob {} size {} disagrees with the built-manifest record \
                     ({}) — refusing (fail-closed; file removed)",
                    layer.digest,
                    layer.size,
                    blob.size
                );
            }
            if blob.media_type != layer.media_type {
                let _ = std::fs::remove_file(&dest);
                miette::bail!(
                    "blob {} media type '{}' disagrees with the built-manifest \
                     record ('{}') — refusing (fail-closed; file removed)",
                    layer.digest,
                    layer.media_type,
                    blob.media_type
                );
            }
            matched.insert(layer.digest.as_str());
        }
        files.push(PulledFileJson {
            path: dest.to_string_lossy().into_owned(),
            digest: layer.digest.clone(),
            size,
        });
    }
    if let Some(map) = &expect_map {
        let missing: Vec<&str> = map
            .keys()
            .filter(|d| !matched.contains(*d))
            .copied()
            .collect();
        if !missing.is_empty() {
            miette::bail!(
                "built-manifest record not satisfied — {} expected blob(s) \
                 missing from the pulled manifest: {} (fail-closed)",
                missing.len(),
                missing.join(", ")
            );
        }
    }

    Ok(PullReportJson {
        command: "pull".into(),
        reference: reference.display(),
        manifest_digest: pulled.digest,
        files,
        install: None,
    })
}

// ── pull --install wiring ──

/// Resolve one pulled `.snap` blob into a [`PendingSnap`].
///
/// # Revision-resolution rule (the Phase 25 documented follow-up)
///
/// The artifact filename carries `{name}_{version}_{arch}` — the store
/// revision is NOT in the filename. It is resolved from the local
/// lockfile ([`LockFile`]) by matching the blob's sha3-384 against the
/// pinned entry for the parsed name:
///
/// - name pinned and sha3-384 matches → that pin's revision;
/// - name pinned but sha3-384 differs → named refusal (the pulled
///   content diverged from the lock — installing it would put a
///   foreign payload behind a trusted dedup key);
/// - name absent from the lockfile → named refusal to install an
///   unpinned blob; plain `pull` (without `--install`) still writes
///   the files.
///
/// [`install_batch`][crate::runtime::RuntimeStore::install_batch]'s
/// dedup key (name+revision+sha3-384) therefore only ever sees
/// lockfile-backed revisions. The filename parser is the SAME one push
/// uses ([`parse_artifact_filename`], ambiguous-underscore rejection
/// included); the payload path is passed through untouched and install
/// re-verifies sha3-384 fail-closed on its own.
pub fn pending_from_blob(payload: &Path, lockfile: &LockFile) -> miette::Result<PendingSnap> {
    let (name, _version, _arch) = parse_artifact_filename(payload)?;
    let sha3_384 = sha3_384_file(payload)?;
    let entry = lockfile.snaps.get(&name).ok_or_else(|| {
        miette!(
            "'{name}' has no {pin} entry — refusing to install a blob whose \
             store revision cannot be established; use plain `pull` (without \
             --install) or `shuttle lock` the snap first",
            pin = LockFile::FILENAME
        )
    })?;
    if entry.sha3_384 != sha3_384 {
        miette::bail!(
            "'{name}' pulled blob sha3-384 {sha3_384} does not match the \
             lockfile pin ({}) — refusing to install (fail-closed)",
            entry.sha3_384
        );
    }
    Ok(PendingSnap {
        name,
        revision: entry.revision,
        sha3_384,
        payload_path: payload.to_path_buf(),
    })
}

// ── Built-manifest record (the manifest.rs Artifact extension, host-side) ──

/// The [`Artifact`] record for a pushed plan: `built`, with one
/// [`BuiltBlob`] (sha256 content address, size, media type) per artifact.
pub fn built_record(plan: &PushPlan) -> Artifact {
    Artifact {
        state: ArtifactState::Built,
        blobs: plan
            .artifacts
            .iter()
            .map(|a| BuiltBlob {
                digest: a.digest.clone(),
                size: a.size,
                media_type: a.media_type.to_string(),
            })
            .collect(),
    }
}

/// Write the host-side built-manifest record (`shuttle push --record`):
/// the [`Artifact`] extension JSON for the pushed blobs.
pub fn write_built_record(path: &Path, plan: &PushPlan) -> miette::Result<()> {
    let mut json = serde_json::to_vec_pretty(&built_record(plan))
        .map_err(|e| miette!("built-manifest record serialization: {e}"))?;
    json.push(b'\n');
    std::fs::write(path, json).map_err(|e| miette!("failed to write {}: {e}", path.display()))?;
    Ok(())
}

/// Load a built-manifest record (`pull --expect`), refusing anything that
/// is not a populated built artifact (fail-closed).
pub fn read_built_record(path: &Path) -> miette::Result<Artifact> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| miette!("failed to read {}: {e}", path.display()))?;
    let artifact: Artifact = serde_json::from_str(&text)
        .map_err(|e| miette!("invalid built-manifest record {}: {e}", path.display()))?;
    if artifact.state != ArtifactState::Built || artifact.blobs.is_empty() {
        miette::bail!(
            "{}: not a built-manifest record — needs state \"built\" and at \
             least one blob",
            path.display()
        );
    }
    Ok(artifact)
}

// ── Tests (hermetic — fake CommandRunner, no network) ──

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    // ── fake runner ──

    type Matcher = Box<dyn Fn(&[String]) -> Option<RunnerOutput> + Send>;

    struct FakeRunner {
        matchers: Mutex<Vec<Matcher>>,
    }

    impl FakeRunner {
        fn new() -> FakeRunner {
            FakeRunner {
                matchers: Mutex::new(Vec::new()),
            }
        }

        /// First matching predicate wins; no match panics (unexpected call).
        fn when(
            &self,
            pred: impl Fn(&[String]) -> bool + Send + 'static,
            respond: impl Fn(&[String]) -> RunnerOutput + Send + 'static,
        ) {
            self.matchers.lock().unwrap().push(Box::new(move |argv| {
                if pred(argv) {
                    Some(respond(argv))
                } else {
                    None
                }
            }));
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, argv: &[String]) -> std::io::Result<RunnerOutput> {
            let matchers = self.matchers.lock().unwrap();
            for m in matchers.iter() {
                if let Some(out) = m(argv) {
                    return Ok(out);
                }
            }
            panic!("unexpected curl invocation: {argv:?}");
        }
    }

    /// Runner that records every argv (and answers 200) — for assertions
    /// on the exact curl invocation.
    struct RecordingRunner {
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl RecordingRunner {
        fn new() -> RecordingRunner {
            RecordingRunner {
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl CommandRunner for RecordingRunner {
        fn run(&self, argv: &[String]) -> std::io::Result<RunnerOutput> {
            if let Some(p) = arg_after(argv, "-D") {
                std::fs::write(p, "HTTP/1.1 200 OK\r\n\r\n").unwrap();
            }
            if let Some(p) = arg_after(argv, "-o") {
                std::fs::write(p, b"").unwrap();
            }
            self.calls.lock().unwrap().push(argv.to_vec());
            Ok(RunnerOutput {
                code: 0,
                stdout: Vec::new(),
                stderr: String::new(),
            })
        }
    }

    /// Adapter so a test can keep a handle to a boxed runner.
    struct Shared<ArcT>(Arc<ArcT>);

    impl<T: CommandRunner + Send + Sync + 'static> CommandRunner for Shared<T> {
        fn run(&self, argv: &[String]) -> std::io::Result<RunnerOutput> {
            self.0.run(argv)
        }
    }

    // ── fake helpers ──

    fn arg_after<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
        argv.iter()
            .position(|a| a == flag)
            .and_then(|i| argv.get(i + 1))
            .map(String::as_str)
    }

    fn url_of(argv: &[String]) -> &str {
        argv.last().map(String::as_str).unwrap_or("")
    }

    fn has_flag(argv: &[String], flag: &str) -> bool {
        argv.iter().any(|a| a == flag)
    }

    fn has_flag_value(argv: &[String], flag: &str, value: &str) -> bool {
        argv.windows(2).any(|w| w[0] == flag && w[1] == value)
    }

    /// Build a scripted HTTP response, written into the `-D`/`-o` files
    /// exactly where real curl would put them.
    fn responder(
        status: u16,
        headers: &'static [(&'static str, &'static str)],
        body: Vec<u8>,
    ) -> impl for<'a> Fn(&'a [String]) -> RunnerOutput + Send {
        move |argv| {
            let hdr_path = arg_after(argv, "-D").expect("argv must contain -D");
            let body_path = arg_after(argv, "-o").expect("argv must contain -o");
            let mut text = format!("HTTP/1.1 {status} STATUS\r\n");
            for (k, v) in headers {
                text.push_str(&format!("{k}: {v}\r\n"));
            }
            text.push_str("\r\n");
            std::fs::write(hdr_path, text).unwrap();
            std::fs::write(body_path, &body).unwrap();
            RunnerOutput {
                code: 0,
                stdout: Vec::new(),
                stderr: String::new(),
            }
        }
    }

    fn ok_200() -> impl for<'a> Fn(&'a [String]) -> RunnerOutput + Send {
        responder(200, &[], Vec::new())
    }

    fn test_client(reference: &str, runner: FakeRunner) -> Client {
        Client::with_runner(
            Reference::parse(reference).unwrap(),
            Auth::default(),
            false,
            Box::new(runner),
        )
        .unwrap()
    }

    fn manifest_bytes(layer_digest: &str, title: &str) -> Vec<u8> {
        manifest_bytes_with_size(layer_digest, title, 5)
    }

    fn manifest_bytes_with_size(layer_digest: &str, title: &str, size: u64) -> Vec<u8> {
        serde_json::json!({
            "schemaVersion": 2,
            "mediaType": MEDIA_TYPE_MANIFEST,
            "artifactType": MEDIA_TYPE_ARTIFACT,
            "config": {
                "mediaType": MEDIA_TYPE_CONFIG,
                "digest": format!("sha256:{}", "a".repeat(64)),
                "size": 2
            },
            "layers": [{
                "mediaType": MEDIA_TYPE_SNAP,
                "digest": layer_digest,
                "size": size,
                "annotations": { TITLE_ANNOTATION: title }
            }]
        })
        .to_string()
        .into_bytes()
    }

    fn write_artifact(dir: &Path, file: &str, content: &[u8]) -> PathBuf {
        let p = dir.join(file);
        std::fs::write(&p, content).unwrap();
        p
    }

    // ── reference parsing ──

    #[test]
    fn reference_parse_valid() {
        let r = Reference::parse("localhost:5000/team/app:v1").unwrap();
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.repo, "team/app");
        assert_eq!(r.tag.as_deref(), Some("v1"));
        assert!(r.digest.is_none());
        assert_eq!(r.base_url(false), "https://localhost:5000");

        let r = Reference::parse("ghcr.io/owner/repo").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repo, "owner/repo");
        assert!(r.tag.is_none() && r.digest.is_none());

        let dgst = format!("sha256:{}", "a".repeat(64));
        let r = Reference::parse(&format!("registry.example:443/a@{dgst}")).unwrap();
        assert_eq!(r.registry, "registry.example:443");
        assert_eq!(r.digest.as_deref(), Some(dgst.as_str()));
        assert!(r.tag.is_none());

        let r = Reference::parse("127.0.0.1:5000/x").unwrap();
        assert_eq!(r.repo, "x");
    }

    #[test]
    fn reference_parse_invalid() {
        let cases: Vec<String> = vec![
            "myrepo".into(),                                           // no host at all
            "foo/bar".into(),                                          // single label, no dot/port
            "localhost:5000/".into(),                                  // empty repo
            "https://ghcr.io/a".into(),                                // scheme in reference
            "host:port/a".into(),                                      // non-numeric port
            "localhost:5000/a:bad tag".into(),                         // space in tag
            format!("localhost:5000/a:tag@sha256:{}", "a".repeat(64)), // tag AND digest
            format!("localhost:5000/a@sha512:{}", "a".repeat(128)),    // wrong algorithm
            format!("localhost:5000/a@sha256:{}", "XYZ"),              // malformed digest
        ];
        for bad in &cases {
            assert!(Reference::parse(bad).is_err(), "'{bad}' should not parse");
        }
        let err = Reference::parse("myrepo").unwrap_err().to_string();
        assert!(err.contains("registry"), "{err}");
        let err = Reference::parse("foo/bar").unwrap_err().to_string();
        assert!(err.contains("explicit registry host"), "{err}");
    }

    // ── WWW-Authenticate parsing ──

    #[test]
    fn www_auth_parse() {
        let w = WwwAuthenticate::parse(
            r#"Bearer realm="https://auth/token",service="registry",scope="repository:a/b:pull""#,
        )
        .unwrap();
        assert_eq!(w.realm, "https://auth/token");
        assert_eq!(w.service.as_deref(), Some("registry"));
        assert_eq!(w.scope.as_deref(), Some("repository:a/b:pull"));

        // extra spaces + unknown params tolerated
        let w =
            WwwAuthenticate::parse(r#"Bearer realm="https://auth/token" , error="invalid_token""#)
                .unwrap();
        assert_eq!(w.realm, "https://auth/token");

        // unquoted value tolerated
        let w = WwwAuthenticate::parse("Bearer realm=https://auth/token").unwrap();
        assert_eq!(w.realm, "https://auth/token");

        assert_eq!(WwwAuthenticate::parse(r#"Basic realm="x""#), None);
        assert_eq!(WwwAuthenticate::parse(r#"Bearer service="s""#), None); // no realm
        assert_eq!(WwwAuthenticate::parse("Bearerish realm=\"x\""), None);
    }

    // ── artifact discovery / naming ──

    #[test]
    fn unsupported_extension_rejected() {
        let err = media_type_for_path(Path::new("x.txt"))
            .unwrap_err()
            .to_string();
        assert!(err.contains(".snap"), "{err}");
        let err = parse_artifact_filename(Path::new("a_b_c_d.snap"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("ambiguous"), "{err}");
    }

    // ── manifest shape ──

    #[test]
    fn manifest_json_shape() {
        let dir = tempfile::tempdir().unwrap();
        write_artifact(dir.path(), "app_1.0.0_amd64.snap", b"payload");
        write_artifact(dir.path(), "app_1.0.0_amd64.img", b"diskbytes");

        let reference = Reference::parse("localhost:5000/team/app").unwrap();
        let plan = plan_push(dir.path(), &[], None, &reference).unwrap();
        assert_eq!(plan.tag, "app-1.0.0"); // default tag from name-version
        assert_eq!(plan.artifacts.len(), 2);
        assert_eq!(plan.meta.arch, "amd64");

        let created = "2026-01-01T00:00:00Z";
        let (bytes, digest) = build_manifest(&plan.meta, &plan.artifacts, created).unwrap();
        assert_eq!(digest, format!("sha256:{}", sha256_hex(&bytes)));

        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["schemaVersion"], 2);
        assert_eq!(v["mediaType"], MEDIA_TYPE_MANIFEST);
        assert_eq!(v["artifactType"], MEDIA_TYPE_ARTIFACT);

        // config: custom media type (NOT the image-config type), digest
        // matches the config body build_config produces.
        assert_eq!(v["config"]["mediaType"], MEDIA_TYPE_CONFIG);
        let (config_bytes, config_digest) = build_config(&plan.meta, created).unwrap();
        assert_eq!(v["config"]["digest"], format!("sha256:{config_digest}"));
        assert_eq!(v["config"]["size"], config_bytes.len());
        let cfg: serde_json::Value = serde_json::from_slice(&config_bytes).unwrap();
        assert_eq!(cfg["name"], "app");
        assert_eq!(cfg["version"], "1.0.0");
        assert_eq!(cfg["arch"], "amd64");
        assert_eq!(cfg["created"], created);
        assert_eq!(
            cfg["shuttle_manifest_version"],
            crate::manifest::MANIFEST_VERSION
        );

        // layers: one per artifact, media type by extension, title annotation.
        // (Discovery sorts paths — .img sorts before .snap.)
        let layers = v["layers"].as_array().unwrap();
        assert_eq!(layers.len(), 2);
        assert_eq!(layers[0]["mediaType"], MEDIA_TYPE_DISK_IMG);
        assert_eq!(
            layers[0]["annotations"]["org.opencontainers.image.title"],
            "app_1.0.0_amd64.img"
        );
        assert_eq!(layers[1]["mediaType"], MEDIA_TYPE_SNAP);
        assert_eq!(
            layers[1]["annotations"]["org.opencontainers.image.title"],
            "app_1.0.0_amd64.snap"
        );
        assert_eq!(
            layers[1]["digest"],
            format!("sha256:{}", sha256_hex(b"payload"))
        );

        // annotations: created + identity.
        assert_eq!(
            v["annotations"]["org.opencontainers.image.created"],
            created
        );
        assert_eq!(v["annotations"]["org.opencontainers.image.title"], "app");
        assert_eq!(
            v["annotations"]["org.opencontainers.image.version"],
            "1.0.0"
        );
    }

    // ── push flows ──

    #[test]
    fn push_skips_existing_blobs() {
        let dir = tempfile::tempdir().unwrap();
        write_artifact(dir.path(), "app_1.0.0_amd64.snap", b"payload");

        let fr = FakeRunner::new();
        fr.when(|a| url_of(a).ends_with("/v2/"), ok_200());
        fr.when(
            |a| has_flag(a, "--head") && url_of(a).contains("/blobs/"),
            responder(200, &[], Vec::new()), // exists → skip
        );
        fr.when(
            |a| has_flag_value(a, "-X", "PUT") && url_of(a).contains("/manifests/"),
            responder(201, &[], Vec::new()),
        );
        // NOTE: no POST matcher — a POST attempt would panic the fake.

        let reference = Reference::parse("localhost:5000/team/app").unwrap();
        let plan = plan_push(dir.path(), &[], None, &reference).unwrap();
        let client = test_client("localhost:5000/team/app", fr);
        let report = push_with(&client, &reference, &plan, None).unwrap();

        assert_eq!(report.blobs.len(), 1);
        assert!(report.blobs[0].existed);
        assert_eq!(
            report.blobs[0].digest,
            format!("sha256:{}", sha256_hex(b"payload"))
        );
        assert_eq!(report.tag, "app-1.0.0");
    }

    #[test]
    fn push_uploads_missing_blob_with_202_finalize() {
        let dir = tempfile::tempdir().unwrap();
        write_artifact(dir.path(), "app_1.0.0_amd64.snap", b"payload");

        let fr = FakeRunner::new();
        fr.when(|a| url_of(a).ends_with("/v2/"), ok_200());
        fr.when(
            |a| has_flag(a, "--head") && url_of(a).contains("/blobs/"),
            responder(404, &[], Vec::new()), // missing → upload
        );
        fr.when(
            |a| has_flag_value(a, "-X", "POST") && url_of(a).contains("/blobs/uploads/"),
            responder(
                202,
                &[("Location", "/v2/team/app/blobs/uploads/uuid1")],
                Vec::new(),
            ),
        );
        // Finalize PUT must carry the digest param — if the client forgot
        // it, this matcher misses and the fake panics.
        fr.when(
            |a| {
                has_flag_value(a, "-X", "PUT")
                    && url_of(a).contains("uploads/uuid1")
                    && url_of(a).contains("digest=sha256:")
            },
            responder(201, &[], Vec::new()),
        );
        fr.when(
            |a| has_flag_value(a, "-X", "PUT") && url_of(a).contains("/manifests/"),
            responder(201, &[], Vec::new()),
        );

        let reference = Reference::parse("localhost:5000/team/app").unwrap();
        let plan = plan_push(dir.path(), &[], None, &reference).unwrap();
        let client = test_client("localhost:5000/team/app", fr);
        let report = push_with(&client, &reference, &plan, None).unwrap();

        assert!(!report.blobs[0].existed);
        assert!(report.manifest_digest.starts_with("sha256:"));
    }

    // ── pull flows ──

    #[test]
    fn pull_writes_title_named_files_and_verifies() {
        let out = tempfile::tempdir().unwrap();
        let payload = b"payload";
        let digest = sha256_hex(payload);

        let fr = FakeRunner::new();
        fr.when(|a| url_of(a).ends_with("/v2/"), ok_200());
        fr.when(
            |a| url_of(a).contains("/manifests/v1"),
            responder(
                200,
                &[("Content-Type", MEDIA_TYPE_MANIFEST)],
                manifest_bytes(&format!("sha256:{digest}"), "app_1.0.0_amd64.snap"),
            ),
        );
        fr.when(
            |a| url_of(a).contains("/blobs/sha256:"),
            responder(200, &[], payload.to_vec()),
        );

        let reference = Reference::parse("localhost:5000/team/app:v1").unwrap();
        let client = test_client("localhost:5000/team/app:v1", fr);
        let report = pull_with(&client, &reference, out.path(), None).unwrap();

        let dest = out.path().join("app_1.0.0_amd64.snap");
        assert_eq!(std::fs::read(&dest).unwrap(), payload);
        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].digest, format!("sha256:{digest}"));
        assert_eq!(report.files[0].size, payload.len() as u64);
        assert!(report.manifest_digest.starts_with("sha256:"));
    }

    #[test]
    fn pull_fails_closed_on_blob_tamper() {
        let out = tempfile::tempdir().unwrap();
        // Manifest promises hash(good); the registry serves something else.
        let promised = format!("sha256:{}", sha256_hex(b"good"));

        let fr = FakeRunner::new();
        fr.when(|a| url_of(a).ends_with("/v2/"), ok_200());
        fr.when(
            |a| url_of(a).contains("/manifests/v1"),
            responder(200, &[], manifest_bytes(&promised, "app_1.0.0_amd64.snap")),
        );
        fr.when(
            |a| url_of(a).contains("/blobs/sha256:"),
            responder(200, &[], b"tampered".to_vec()),
        );

        let reference = Reference::parse("localhost:5000/team/app:v1").unwrap();
        let client = test_client("localhost:5000/team/app:v1", fr);
        let err = pull_with(&client, &reference, out.path(), None).unwrap_err();
        assert!(err.to_string().contains("digest mismatch"), "{err}");
        assert!(!out.path().join("app_1.0.0_amd64.snap").exists());
    }

    #[test]
    fn pull_manifest_digest_mismatch_fails() {
        let out = tempfile::tempdir().unwrap();
        let expected = format!("sha256:{}", sha256_hex(b"correct-manifest"));
        let served = manifest_bytes(
            &format!("sha256:{}", sha256_hex(b"payload")),
            "app_1.0.0_amd64.snap",
        );

        let fr = FakeRunner::new();
        fr.when(|a| url_of(a).ends_with("/v2/"), ok_200());
        fr.when(
            |a| url_of(a).contains("/manifests/sha256:"),
            responder(200, &[], served), // hash(served) != expected
        );

        let reference = Reference::parse(&format!("localhost:5000/team/app@{expected}")).unwrap();
        let client = test_client(&format!("localhost:5000/team/app@{expected}"), fr);
        let err = pull_with(&client, &reference, out.path(), None).unwrap_err();
        assert!(
            err.to_string().contains("manifest digest mismatch"),
            "{err}"
        );
    }

    #[test]
    fn pull_requires_tag_or_digest() {
        let out = tempfile::tempdir().unwrap();
        let fr = FakeRunner::new();
        let client = test_client("localhost:5000/team/app", fr);
        let reference = Reference::parse("localhost:5000/team/app").unwrap();
        let err = pull_with(&client, &reference, out.path(), None).unwrap_err();
        assert!(err.to_string().contains("tag or @digest"), "{err}");
    }

    // ── authentication ──

    #[test]
    fn auth_bearer_handshake_success() {
        let fr = FakeRunner::new();
        fr.when(
            |a| url_of(a).ends_with("/v2/") && !has_flag_value(a, "-H", "Authorization: Bearer tok"),
            responder(
                401,
                &[(
                    "Www-Authenticate",
                    r#"Bearer realm="https://auth.test/token",service="registry",scope="repository:team/app:pull,push""#,
                )],
                Vec::new(),
            ),
        );
        fr.when(
            |a| url_of(a).starts_with("https://auth.test/token"),
            responder(200, &[], br#"{"token":"tok"}"#.to_vec()),
        );
        fr.when(
            |a| url_of(a).ends_with("/v2/") && has_flag_value(a, "-H", "Authorization: Bearer tok"),
            ok_200(),
        );
        let client = test_client("localhost:5000/team/app", fr);
        client.version_check().unwrap();
    }

    #[test]
    fn auth_retry_once_then_fail() {
        let fr = FakeRunner::new();
        fr.when(
            |a| {
                url_of(a).ends_with("/v2/") && !has_flag_value(a, "-H", "Authorization: Bearer tok")
            },
            responder(
                401,
                &[(
                    "Www-Authenticate",
                    r#"Bearer realm="https://auth.test/token",service="registry""#,
                )],
                Vec::new(),
            ),
        );
        fr.when(
            |a| url_of(a).starts_with("https://auth.test/token"),
            responder(200, &[], br#"{"token":"tok"}"#.to_vec()),
        );
        fr.when(
            |a| url_of(a).ends_with("/v2/") && has_flag_value(a, "-H", "Authorization: Bearer tok"),
            responder(401, &[], Vec::new()), // even with the token: refused
        );
        let client = test_client("localhost:5000/team/app", fr);
        let err = client.version_check().unwrap_err();
        assert!(err.to_string().contains("401"), "{err}");
    }

    #[test]
    fn http_token_realm_rejected_without_flag() {
        let fr = FakeRunner::new();
        fr.when(
            |a| url_of(a).ends_with("/v2/"),
            responder(
                401,
                &[(
                    "Www-Authenticate",
                    r#"Bearer realm="http://auth.test/token",service="registry""#,
                )],
                Vec::new(),
            ),
        );
        let client = test_client("localhost:5000/team/app", fr);
        let err = client.version_check().unwrap_err();
        assert!(err.to_string().contains("insecure"), "{err}");
    }

    // ── scheme selection ──

    #[test]
    fn insecure_http_flag_controls_scheme() {
        for (insecure, expected) in [
            (false, "https://localhost:5000/v2/"),
            (true, "http://localhost:5000/v2/"),
        ] {
            let shared = Arc::new(RecordingRunner::new());
            let client = Client::with_runner(
                Reference::parse("localhost:5000/team/app").unwrap(),
                Auth::default(),
                insecure,
                Box::new(Shared(shared.clone())),
            )
            .unwrap();
            let _ = client.version_check(); // response parsing irrelevant here
            let calls = shared.calls.lock().unwrap();
            let url = calls[0].last().unwrap();
            assert_eq!(url, expected);
        }
    }

    // ── tag sanitization & timestamps ──

    #[test]
    fn tag_sanitization() {
        assert_eq!(sanitize_tag("app-1.0.0"), "app-1.0.0");
        assert_eq!(sanitize_tag("my app_1.0"), "my-app_1.0"); // space → '-'
        assert_eq!(sanitize_tag("1.0+build"), "1.0-build"); // '+' → '-'
        assert_eq!(sanitize_tag("-leading"), "leading"); // leading '-' dropped
        assert_eq!(sanitize_tag("..."), "untitled"); // fully erased
        assert_eq!(sanitize_tag(&"a".repeat(200)).len(), 128);
        // default tag derivation goes through sanitize_tag:
        assert_eq!(
            sanitize_tag(&format!("{}-{}", "my app", "1.0+build")),
            "my-app-1.0-build"
        );
    }

    #[test]
    fn rfc3339_formatting() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(86_400), "1970-01-02T00:00:00Z");
        assert_eq!(format_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    // ── digest helpers ──

    #[test]
    fn digest_validation() {
        let good = format!("sha256:{}", "a".repeat(64));
        assert!(validate_digest(&good).is_ok());
        assert!(validate_digest(&format!("sha256:{}", "A".repeat(64))).is_err());
        assert!(validate_digest(&format!("sha512:{}", "a".repeat(128))).is_err());
        assert!(validate_digest("sha256:short").is_err());
    }

    #[test]
    fn headers_parse_last_redirect_response() {
        let text = "HTTP/1.1 307 Temporary Redirect\r\nLocation: https://s3/x\r\n\r\n\
                    HTTP/1.1 200 OK\r\nDocker-Distribution-Api-Version: registry/2.0\r\nWww-Authenticate: Bearer realm=\"r\"\r\n\r\n";
        let (status, headers) = parse_headers(text);
        assert_eq!(status, 200);
        let get = |n: &str| headers.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
        assert_eq!(get("location"), None); // earlier response's headers reset
        assert_eq!(
            get("www-authenticate").as_deref(),
            Some("Bearer realm=\"r\"")
        );
    }

    // ── pull --install wiring (revision from lockfile pins) ──

    fn lock_with(name: &str, revision: u32, sha3_384: &str) -> LockFile {
        let mut lock = LockFile {
            version: 1,
            sources: Default::default(),
            snaps: Default::default(),
            inputs: Default::default(),
            packages: Default::default(),
        };
        lock.snaps.insert(
            name.to_string(),
            crate::lock::SnapLockEntry {
                revision,
                sha3_384: sha3_384.to_string(),
            },
        );
        lock
    }

    #[test]
    fn pending_from_blob_resolves_revision_from_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        let payload = write_artifact(dir.path(), "app_1.0.0_amd64.snap", b"payload");
        let sha3 = crate::store::sha3_384_file(&payload).unwrap();
        let lock = lock_with("app", 7, &sha3);

        let pending = pending_from_blob(&payload, &lock).unwrap();
        assert_eq!(pending.name, "app");
        assert_eq!(pending.revision, 7);
        assert_eq!(pending.sha3_384, sha3);
        assert_eq!(pending.payload_path, payload);
    }

    #[test]
    fn pending_from_blob_refuses_unpinned_divergent_and_ambiguous() {
        let dir = tempfile::tempdir().unwrap();
        let payload = write_artifact(dir.path(), "app_1.0.0_amd64.snap", b"payload");
        let sha3 = crate::store::sha3_384_file(&payload).unwrap();

        // name absent from the lockfile → unpinned refusal
        let lock = lock_with("other", 7, &sha3);
        let err = pending_from_blob(&payload, &lock).unwrap_err().to_string();
        assert!(err.contains("no shuttle.lock entry"), "{err}");
        assert!(err.contains("plain `pull`"), "{err}");

        // pinned but content diverged → fail-closed
        let lock = lock_with("app", 7, &"f".repeat(96));
        let err = pending_from_blob(&payload, &lock).unwrap_err().to_string();
        assert!(err.contains("does not match the lockfile pin"), "{err}");

        // ambiguous filename rejected by the SHARED push parser
        let amb = write_artifact(dir.path(), "a_b_c_d.snap", b"payload");
        let lock = lock_with("a", 1, "x");
        let err = pending_from_blob(&amb, &lock).unwrap_err().to_string();
        assert!(err.contains("ambiguous"), "{err}");
    }

    // ── cross-repo blob mount ──

    #[test]
    fn push_mount_201_skips_upload() {
        let dir = tempfile::tempdir().unwrap();
        write_artifact(dir.path(), "app_1.0.0_amd64.snap", b"payload");

        let fr = FakeRunner::new();
        fr.when(|a| url_of(a).ends_with("/v2/"), ok_200());
        fr.when(
            |a| has_flag(a, "--head") && url_of(a).contains("/blobs/"),
            responder(404, &[], Vec::new()), // missing locally → try mount
        );
        // The mount POST must carry BOTH mount= and from= — a monolithic
        // digest= POST would match nothing and panic the fake.
        fr.when(
            |a| {
                has_flag_value(a, "-X", "POST")
                    && url_of(a).contains("/blobs/uploads/")
                    && url_of(a).contains("mount=sha256:")
                    && url_of(a).contains("from=team/base")
            },
            responder(201, &[], Vec::new()), // mounted, no Location
        );
        fr.when(
            |a| has_flag_value(a, "-X", "PUT") && url_of(a).contains("/manifests/"),
            responder(201, &[], Vec::new()),
        );

        let reference = Reference::parse("localhost:5000/team/app").unwrap();
        let plan = plan_push(dir.path(), &[], None, &reference).unwrap();
        let client = test_client("localhost:5000/team/app", fr);
        let report = push_with(&client, &reference, &plan, Some("team/base")).unwrap();

        assert!(!report.blobs[0].existed);
        assert!(
            report.blobs[0].mounted,
            "mount 201 must report mounted: true"
        );
    }

    #[test]
    fn push_mount_202_falls_back_to_finalize() {
        let dir = tempfile::tempdir().unwrap();
        write_artifact(dir.path(), "app_1.0.0_amd64.snap", b"payload");

        let fr = FakeRunner::new();
        fr.when(|a| url_of(a).ends_with("/v2/"), ok_200());
        fr.when(
            |a| has_flag(a, "--head") && url_of(a).contains("/blobs/"),
            responder(404, &[], Vec::new()),
        );
        fr.when(
            |a| has_flag_value(a, "-X", "POST") && url_of(a).contains("mount=sha256:"),
            responder(
                202, // no mount — registry opened an upload session
                &[("Location", "/v2/team/app/blobs/uploads/uuid2")],
                Vec::new(),
            ),
        );
        fr.when(
            |a| {
                has_flag_value(a, "-X", "PUT")
                    && url_of(a).contains("uploads/uuid2")
                    && url_of(a).contains("digest=sha256:")
            },
            responder(201, &[], Vec::new()),
        );
        fr.when(
            |a| has_flag_value(a, "-X", "PUT") && url_of(a).contains("/manifests/"),
            responder(201, &[], Vec::new()),
        );

        let reference = Reference::parse("localhost:5000/team/app").unwrap();
        let plan = plan_push(dir.path(), &[], None, &reference).unwrap();
        let client = test_client("localhost:5000/team/app", fr);
        let report = push_with(&client, &reference, &plan, Some("team/base")).unwrap();

        assert!(!report.blobs[0].mounted);
        assert!(!report.blobs[0].existed);
    }

    #[test]
    fn push_without_mount_from_uses_monolithic_post() {
        let dir = tempfile::tempdir().unwrap();
        write_artifact(dir.path(), "app_1.0.0_amd64.snap", b"payload");

        let fr = FakeRunner::new();
        fr.when(|a| url_of(a).ends_with("/v2/"), ok_200());
        fr.when(
            |a| has_flag(a, "--head") && url_of(a).contains("/blobs/"),
            responder(404, &[], Vec::new()),
        );
        // Plain path: digest= POST, never a mount= POST.
        fr.when(
            |a| {
                has_flag_value(a, "-X", "POST")
                    && url_of(a).contains("digest=sha256:")
                    && !url_of(a).contains("mount=")
            },
            responder(201, &[], Vec::new()),
        );
        fr.when(
            |a| has_flag_value(a, "-X", "PUT") && url_of(a).contains("/manifests/"),
            responder(201, &[], Vec::new()),
        );

        let reference = Reference::parse("localhost:5000/team/app").unwrap();
        let plan = plan_push(dir.path(), &[], None, &reference).unwrap();
        let client = test_client("localhost:5000/team/app", fr);
        let report = push_with(&client, &reference, &plan, None).unwrap();
        assert!(!report.blobs[0].mounted);
    }

    // ── built-manifest record (Artifact extension) ──

    #[test]
    fn built_record_roundtrip_and_pull_expect_happy_path() {
        let dir = tempfile::tempdir().unwrap();
        write_artifact(dir.path(), "app_1.0.0_amd64.snap", b"payload");
        let reference = Reference::parse("localhost:5000/team/app").unwrap();
        let plan = plan_push(dir.path(), &[], None, &reference).unwrap();

        let rec_path = dir.path().join("built.json");
        write_built_record(&rec_path, &plan).unwrap();
        let record = read_built_record(&rec_path).unwrap();
        // roundtrip: file bytes equal the in-memory record
        let a = serde_json::to_value(built_record(&plan)).unwrap();
        let b = serde_json::to_value(&record).unwrap();
        assert_eq!(a, b);
        assert_eq!(b["state"], "built");
        assert_eq!(b["blobs"][0]["media_type"], MEDIA_TYPE_SNAP);

        // pull verified against the record — same payload, same digest
        let out = tempfile::tempdir().unwrap();
        let layer_digest = plan.artifacts[0].digest.clone();
        let fr = FakeRunner::new();
        fr.when(|a| url_of(a).ends_with("/v2/"), ok_200());
        fr.when(
            |a| url_of(a).contains("/manifests/v1"),
            responder(
                200,
                &[],
                manifest_bytes_with_size(
                    &layer_digest,
                    "app_1.0.0_amd64.snap",
                    b"payload".len() as u64,
                ),
            ),
        );
        fr.when(
            |a| url_of(a).contains("/blobs/sha256:"),
            responder(200, &[], b"payload".to_vec()),
        );
        let client = test_client("localhost:5000/team/app:v1", fr);
        let pull_ref = Reference::parse("localhost:5000/team/app:v1").unwrap();
        let report = pull_with(&client, &pull_ref, out.path(), Some(&record)).unwrap();
        assert_eq!(report.files.len(), 1);
    }

    #[test]
    fn pull_expect_tamper_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        write_artifact(dir.path(), "app_1.0.0_amd64.snap", b"payload");
        let reference = Reference::parse("localhost:5000/team/app").unwrap();
        let plan = plan_push(dir.path(), &[], None, &reference).unwrap();
        let layer_digest = plan.artifacts[0].digest.clone();

        let pull_with_record = |record: Artifact| -> miette::Result<PullReportJson> {
            let out = tempfile::tempdir().unwrap();
            let fr = FakeRunner::new();
            fr.when(|a| url_of(a).ends_with("/v2/"), ok_200());
            fr.when(
                |a| url_of(a).contains("/manifests/v1"),
                responder(
                    200,
                    &[],
                    manifest_bytes_with_size(
                        &layer_digest,
                        "app_1.0.0_amd64.snap",
                        b"payload".len() as u64,
                    ),
                ),
            );
            fr.when(
                |a| url_of(a).contains("/blobs/sha256:"),
                responder(200, &[], b"payload".to_vec()),
            );
            let client = test_client("localhost:5000/team/app:v1", fr);
            let pull_ref = Reference::parse("localhost:5000/team/app:v1").unwrap();
            pull_with(&client, &pull_ref, out.path(), Some(&record))
        };

        // size tampered (OCI descriptor says 5)
        let mut wrong_size = built_record(&plan);
        wrong_size.blobs[0].size = 999;
        let err = pull_with_record(wrong_size).unwrap_err().to_string();
        assert!(err.contains("size"), "{err}");

        // digest absent from the record (foreign blob)
        let mut foreign = built_record(&plan);
        foreign.blobs[0].digest = format!("sha256:{}", sha256_hex(b"other"));
        let err = pull_with_record(foreign).unwrap_err().to_string();
        assert!(
            err.contains("not in the expected built-manifest record"),
            "{err}"
        );

        // record with a blob the manifest never delivers → missing
        let mut extra = built_record(&plan);
        extra.blobs.push(BuiltBlob {
            digest: format!("sha256:{}", sha256_hex(b"missing")),
            size: 1,
            media_type: MEDIA_TYPE_SNAP.into(),
        });
        let err = pull_with_record(extra).unwrap_err().to_string();
        assert!(err.contains("missing from the pulled manifest"), "{err}");
    }

    #[test]
    fn read_built_record_rejects_unbuilt_and_empty() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("r.json");
        std::fs::write(&p, serde_json::to_vec(&Artifact::unbuilt()).unwrap()).unwrap();
        let err = read_built_record(&p).unwrap_err().to_string();
        assert!(err.contains("not a built-manifest record"), "{err}");
    }
}
