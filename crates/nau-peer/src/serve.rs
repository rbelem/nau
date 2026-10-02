//! `nau serve` — the peer lane's serving surface: the read-only pod
//! store grammar (ADR-0033 Decisions 4+5: plain TCP with a minimal
//! HTTP/1.1 subset over `GET /info`, `GET /manifests/<pkg>`,
//! `GET /blobs/<sha256>`) plus ONE token-gated write route,
//! `POST /build-requests` (ADR-0052 Decision 4), foreground until
//! interrupted.
//!
//! The wire grammar is NORMATIVE (ADR-0033 Decision 4 — safety is
//! conditional on it, not intrinsic to "read-only"): a blob segment is
//! exactly 64 lowercase hex resolved through
//! [`nau_core::blob_store::BlobStore::blob_path`], never a raw join — a
//! naive join turns `GET /blobs/../../.config/nau/secret-key` into
//! an unauthenticated arbitrary-file read over plaintext HTTP. Package
//! names are `[a-z0-9-]+` (the ADR-0032 collision-classifier charset).
//! Everything else is 404. Request line + headers are capped at 8 KiB,
//! every socket gets a read/write timeout, and the server holds a hard
//! connection-concurrency bound (the `oci.rs` bounded-timeout
//! precedent) — a bare `TcpListener` has no slowloris defenses.
//!
//! `/build-requests` (ADR-0052 Decision 4) is bearer-token gated
//! BEFORE anything else: the token lives in an operator-managed file
//! (`--token-file`, revocable by removal — the file is re-read per
//! request), the compare is exact, and every auth failure is a 4xx
//! that never reaches the queue. A valid request carries `{package,
//! version, requested_by}` (identity only — never build text), lands
//! as ONE queue file (atomic temp+rename), and earns a minimal 2xx
//! naming the request id. The GET surface and the trust chain are
//! untouched by this route.
//!
//! `/manifests/<pkg>` and `/info` publish the UNION of the current
//! generation's records (minted + signed on the fly — unsigned store
//! entries are never served) and the pull-staging inbox
//! ([`nau_core::pkg_manifest::manifest_path`]) per its documented
//! invariant — the exact union `export` freezes into the static tree,
//! through the same shared helpers.
//!
//! Announce (ADR-0033 Decision 3): when the announce switch is set —
//! `node { serve = { announce = true } }` or `serve --announce` — the
//! lane registers `_nau._tcp.local.` via [`crate::discovery`] for
//! the lifetime of the accept loop. Announce failure is a warning, not
//! an error: on multicast-filtered networks explicit peer addresses
//! degrade gracefully, and discovery sugar must not take serving down.
//!
//! Issue #326 PR 5 (crate extraction): the env-reading pod roots stay
//! root — the caller resolves `pod_root(None)` and hands it in; the
//! store view consumed here is the narrow core seam
//! ([`nau_core::blob_store::BlobStore`] + the generation view), never
//! the root `RuntimeStore`.

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use miette::{IntoDiagnostic, WrapErr};
use nau_core::blob_store::BlobStore;
use nau_core::generation_view;
use nau_core::paths::DEFAULT_SERVE_ADDRESS;
use nau_core::pkg_manifest::Generation;
use nau_infra::output;
use serde::Serialize;

/// Hard connection-concurrency bound (ADR-0033 Decision 4). The accept
/// loop refuses with 503 beyond this — one thread per connection with
/// no bound is a slowloris invitation.
const MAX_CONCURRENT_CONNECTIONS: usize = 16;

/// Total request line + headers cap. Anything longer is refused with
/// 400 before it can pin a connection.
const REQUEST_HEAD_LIMIT: usize = 8 * 1024;

/// POST body cap (`/build-requests`). The request identity is three
/// short strings; 64 KiB is orders of magnitude past any honest body
/// and refuses the oversized before it can pin memory.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Per-socket read/write timeout (the `oci.rs` bounded-timeout
/// precedent).
const IO_TIMEOUT: Duration = Duration::from_secs(5);

// ── Wire grammar ──

/// One accepted request, after strict grammar validation. Variants
/// carry pre-validated segments — they are safe to resolve through the
/// store's path APIs, never to raw-join.
#[derive(Debug, PartialEq, Eq)]
enum Route {
    Info,
    Manifest(String),
    Blob(String),
    /// `POST /build-requests` (ADR-0052 Decision 4) — the ONE write
    /// route, token-gated in its handler before anything else.
    BuildRequests,
}

/// Parse the HTTP request line. `Ok(route)` for a valid request;
/// `Err(status)` for the refusal code (405 wrong method for the path,
/// 404 anything not matching the route shapes exactly, 400 malformed
/// line).
fn parse_request(line: &str) -> Result<Route, u16> {
    let mut tokens = line.split_whitespace();
    let (Some(method), Some(path), Some(version)) = (tokens.next(), tokens.next(), tokens.next())
    else {
        return Err(400);
    };
    if tokens.next().is_some() {
        return Err(400);
    }
    if !version.starts_with("HTTP/") {
        return Err(400);
    }
    // The write route first: it is POST-only, and everything else on
    // its path is a 405 (the method names what would be allowed).
    if path == "/build-requests" {
        return if method == "POST" {
            Ok(Route::BuildRequests)
        } else {
            Err(405)
        };
    }
    if method != "GET" {
        return Err(405);
    }
    // Query strings and fragments are not part of any route shape —
    // strict segment grammar rejects them below (nothing outside the
    // exact forms parses).
    if path == "/info" {
        return Ok(Route::Info);
    }
    if let Some(pkg) = path.strip_prefix("/manifests/") {
        if is_pkg_name(pkg) {
            return Ok(Route::Manifest(pkg.to_string()));
        }
        return Err(404);
    }
    if let Some(sha) = path.strip_prefix("/blobs/") {
        if is_sha256(sha) {
            return Ok(Route::Blob(sha.to_string()));
        }
        return Err(404);
    }
    Err(404)
}

/// Package-name grammar: `[a-z0-9-]+` (ADR-0032 charset). A segment
/// failing this can never traverse: `/`, `.`, `..`, `%xx`, `?query` all
/// fail the charset.
fn is_pkg_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Blob-segment grammar: exactly 64 lowercase hex chars. Anything else
/// (uppercase, 63 or 65 chars, dots, slashes) is 404 — this is the rule
/// that makes the ADR's traversal-to-secret-key exploit impossible.
fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

// ── Request head reading ──

/// One parsed request head: the request line plus the header pairs in
/// arrival order. The GET routes consume only the line (their responses
/// are all `Connection: close`; nothing in the read-only subset needs
/// headers); `/build-requests` reads `Authorization` and
/// `Content-Length` off the pairs.
#[derive(Debug)]
struct RequestHead {
    line: String,
    headers: Vec<(String, String)>,
}

impl RequestHead {
    /// Case-insensitive header lookup, first match wins.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Outcome of reading one request head.
#[derive(Debug)]
enum Head {
    /// A complete head plus the bytes READ PAST its terminator — a
    /// client may pipeline the body in the same TCP segment as the
    /// head, and the chunked reads can absorb it. Discarding those
    /// bytes would corrupt a POST body; they are handed to the body
    /// reader. (The GET routes ignore them — no body, connection
    /// closes after one response.)
    Complete(RequestHead, Vec<u8>),
    /// Line + headers exceeded [`REQUEST_HEAD_LIMIT`] — refuse with 400.
    TooLarge,
    /// EOF or timeout before a complete head — close silently.
    Closed,
}

/// Read the request line + headers, capped, parse the header pairs,
/// and keep whatever arrived past the terminator.
fn read_head<R: Read>(reader: &mut R) -> Head {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    loop {
        if buf.len() > REQUEST_HEAD_LIMIT {
            return Head::TooLarge;
        }
        match reader.read(&mut chunk) {
            Ok(0) => return Head::Closed,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(ref e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Head::Closed;
            }
            Err(_) => return Head::Closed,
        }
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).into_owned();
            return Head::Complete(parse_head(&head), buf[pos + 4..].to_vec());
        }
    }
}

/// Split one head's text into the request line and `name: value`
/// pairs. Malformed header lines are kept verbatim — they can only
/// fail a later `header()` lookup, never panic (the size cap already
/// bounds them).
fn parse_head(head: &str) -> RequestHead {
    let mut lines = head.split("\r\n");
    let line = lines.next().unwrap_or_default().to_string();
    let headers = lines
        .filter_map(|l| {
            let (name, value) = l.split_once(':')?;
            Some((name.trim().to_string(), value.trim().to_string()))
        })
        .collect();
    RequestHead { line, headers }
}

// ── Server ──

/// The `/build-requests` gate (ADR-0052 Decision 4): the operator's
/// token file plus the queue the route appends to. `None` (no
/// `--token-file`) takes the route OFF the wire — POST answers 404
/// like any unknown path.
#[derive(Clone)]
struct BuildRequestGate {
    /// Operator-managed bearer tokens, one per line; revocation is
    /// removing the line (the file is re-read per request, so removal
    /// takes effect without a restart).
    token_file: PathBuf,
    queue: Arc<crate::queue::BuildQueue>,
}

/// Everything a connection handler needs. Shared across connection
/// threads behind an [`Arc`].
#[derive(Clone)]
struct ServerCtx {
    /// The served pod's state root: the generation manifests, the
    /// `active` link, and the staged-manifest inbox hang off it. The
    /// root glue resolves it (the env-reading `pod_root` stays root).
    state_root: PathBuf,
    /// The content-blob store over `<state_root>/store` — the narrow
    /// read-only seam `/blobs/<sha>` streams through (issue #326 PR 5:
    /// the crate never touches the root `RuntimeStore`).
    blobs: Arc<BlobStore>,
    /// Home used for the signing key (`~/.config/nau/secret-key`)
    /// when minting manifests. A seam: tests point it at a tempdir.
    home: PathBuf,
    /// The configured `node.name` (ADR-0033 Decision 6) — the identity
    /// `/info` publishes; the kernel hostname is only the fallback.
    node_name: Option<String>,
    /// The `/build-requests` gate; `None` = route off (404).
    build_requests: Option<BuildRequestGate>,
}

/// A computed response: either an inline body or a file to stream
/// (`/blobs` — never slurped, always streamed with Content-Length).
enum Handled {
    Body(u16, &'static str, Vec<u8>),
    File(u16, &'static str, PathBuf, u64),
}

impl Handled {
    /// The status code the response will carry (the request log's
    /// input — known before the bytes are written).
    fn status(&self) -> u16 {
        match self {
            Handled::Body(status, ..) | Handled::File(status, ..) => *status,
        }
    }
}

/// The `/build-requests` gate overrides (ADR-0052 Decision 4): the
/// token file turns the route on; the queue dir defaults to the XDG
/// data root. Both come from `--token-file`/`--queue-dir`.
#[derive(Debug, Clone, Copy, Default)]
pub struct BuildRequestsOptions<'a> {
    pub token_file: Option<&'a Path>,
    pub queue_dir: Option<&'a Path>,
}

/// Run `nau serve` with the CLI's bind overrides. `address`/`port`
/// are `None` when the operator gave no flag — the defaults come from
/// `node {}` conventions ([`DEFAULT_SERVE_ADDRESS`], loopback).
/// `announce` + `node_name` come from `node {}` (source of truth) with
/// the `--announce` flag as an override; `node_name: None` falls back
/// to the kernel hostname. `pod` is the `--pod` flag: the named pod's
/// store is the served surface (default `default`, matching the
/// `--pod` flags on `pull` and `export`). `pod_root` is the pod state
/// root the flag resolves under — resolved by the root glue (the
/// env-reading `pod_root` stays root). `build_requests` opens the
/// token-gated POST route when its token file is set. Foreground until
/// interrupted; no daemonization (ADR-0033 Decision 5).
pub fn run(
    pod_root: &Path,
    address: Option<&str>,
    port: Option<u16>,
    announce: bool,
    node_name: Option<&str>,
    pod: Option<&str>,
    build_requests: BuildRequestsOptions<'_>,
) -> miette::Result<()> {
    let (pod_name, ctx) = serve_ctx(
        pod_root,
        pod,
        node_name,
        build_requests.token_file,
        build_requests.queue_dir,
    )?;
    let (host, port) = resolve_bind(address, port)?;
    let listener = TcpListener::bind((host.as_str(), port))
        .into_diagnostic()
        .wrap_err_with(|| format!("binding serve address {host}:{port}"))?;
    output::info(format!(
        "serving pod '{pod_name}' store on http://{host}:{port} — Ctrl-C to stop"
    ));
    if ctx.build_requests.is_some() {
        output::info("accepting build requests on POST /build-requests (bearer-token gated)");
    }
    // The guard binds the registration to the serve loop's lifetime —
    // it is dropped only when the loop exits (i.e. never in practice:
    // Ctrl-C terminates the process, and the OS reaps the multicast
    // membership; the mDNS records expire by TTL).
    let _announce = if announce {
        let is_loopback = matches!(host.as_str(), "127.0.0.1" | "::1");
        let name = node_name
            .map(str::to_string)
            .unwrap_or_else(nau_core::pkg_manifest::hostname);
        match crate::discovery::announce(&name, port) {
            Ok(guard) => {
                output::info(format!(
                    "announcing as '{name}' on _nau._tcp (mDNS) — `nau peers` finds it"
                ));
                if is_loopback {
                    output::warn(
                        "announcing a loopback-only bind — LAN peers will discover this node but cannot connect; bind a real address (e.g. 0.0.0.0) to serve the LAN",
                    );
                }
                Some(guard)
            }
            Err(e) => {
                output::warn(format!(
                    "mDNS announce failed ({e:#}) — peers can still pull by explicit address"
                ));
                None
            }
        }
    } else {
        None
    };
    accept_loop(listener, ctx, Arc::new(AtomicUsize::new(0)))
}

/// Resolve the pod to serve under an explicit pod root: the `--pod`
/// name ([`nau_core::paths::resolve_pod_dir_under`]) plus the
/// store-existence gate, and carry the node name through to `/info`.
/// The `/build-requests` gate assembles here: a `--token-file` turns
/// the route on (queue root: `--queue-dir`, else the XDG default); an
/// unreadable token file refuses the STARTUP — a gate the operator
/// asked for and nau cannot honor must not silently serve half-open.
/// Split from [`run`] so tests can point the pod root at a tempdir and
/// observe which store a pod flag selects. A missing store is a named
/// error — the pod that was asked for and where it was looked for.
fn serve_ctx(
    pod_root: &Path,
    pod: Option<&str>,
    node_name: Option<&str>,
    token_file: Option<&Path>,
    queue_dir: Option<&Path>,
) -> miette::Result<(String, ServerCtx)> {
    let (pod_name, pod_dir) = nau_core::paths::resolve_pod_dir_under(pod_root, pod)?;
    if !pod_dir.is_dir() {
        miette::bail!(
            "no store for pod '{pod_name}' at {} — nothing to serve; \
             sync a pod first (`nau pod sync`)",
            pod_dir.display()
        );
    }
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
    let build_requests = match token_file {
        None => None,
        Some(token_file) => {
            if !token_file.is_file() {
                miette::bail!(
                    "build-requests token file {} does not exist — create it first \
                     (one bearer token per line; remove a line to revoke)",
                    token_file.display()
                );
            }
            let queue = crate::queue::BuildQueue::new(
                queue_dir
                    .map(Path::to_path_buf)
                    .unwrap_or_else(crate::queue::BuildQueue::default_dir),
            );
            queue.ensure_dirs()?;
            Some(BuildRequestGate {
                token_file: token_file.to_path_buf(),
                queue: Arc::new(queue),
            })
        }
    };
    let ctx = ServerCtx {
        // The store dir half of the runtime state layout
        // (`<state root>/store`, the same component
        // `nau_core::pkg_manifest::inbox_manifests` derives the inbox
        // from) — built straight over it via the core seam.
        state_root: pod_dir.clone(),
        blobs: Arc::new(BlobStore::new(pod_dir.join("store"))),
        home,
        node_name: node_name.map(str::to_string),
        build_requests,
    };
    Ok((pod_name, ctx))
}

/// Merge the CLI overrides onto the default address: `--address`
/// replaces the host (and default port), `--port` replaces the port.
fn resolve_bind(address: Option<&str>, port: Option<u16>) -> miette::Result<(String, u16)> {
    let base = address.unwrap_or(DEFAULT_SERVE_ADDRESS);
    let (host, base_port) = match base.rsplit_once(':') {
        Some((h, p)) => {
            let parsed: u16 = p
                .parse()
                .into_diagnostic()
                .wrap_err_with(|| format!("invalid serve address '{base}'"))?;
            (h.to_string(), parsed)
        }
        None => miette::bail!("invalid serve address '{base}': expected host:port"),
    };
    let literal = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(&host);
    if literal.is_empty() {
        miette::bail!("invalid serve address '{base}': empty host");
    }
    Ok((literal.to_string(), port.unwrap_or(base_port)))
}

/// Accept loop: one thread per connection under a hard cap; beyond the
/// cap the connection is refused with 503 on the spot. `active` counts
/// live connection threads; the accept thread is the only one that
/// increments it, so the check-and-add has no race. (The counter is a
/// parameter so tests can observe the cap deterministically.)
fn accept_loop(listener: TcpListener, ctx: ServerCtx, active: Arc<AtomicUsize>) -> ! {
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };
        if active.load(Ordering::Relaxed) >= MAX_CONCURRENT_CONNECTIONS {
            output::warn(format!(
                "connection limit reached ({MAX_CONCURRENT_CONNECTIONS}) — \
                 refusing a peer with 503"
            ));
            let mut stream = stream;
            drain_available(&mut stream);
            let _ = write_response(
                &mut stream,
                503,
                "application/json",
                b"{\"error\":\"connection limit reached\"}",
            );
            continue;
        }
        active.fetch_add(1, Ordering::Relaxed);
        let ctx = ctx.clone();
        let active = Arc::clone(&active);
        thread::spawn(move || {
            let _ = serve_connection(stream, &ctx);
            active.fetch_sub(1, Ordering::Relaxed);
        });
    }
    unreachable!("listener.incoming() never returns None");
}

/// Best-effort drain of an already-sent request head before a 503
/// close. Closing a socket with unread data in its receive buffer turns
/// the FIN into an RST — which discards the response from the client's
/// buffer, so the refused peer may never see its 503. The drain is
/// bounded and effectively non-blocking (1ms timeout, ≤ head limit):
/// a client still dribbling bytes gets its refusal either way — the
/// anti-slowloris property is the cap itself, not this path.
fn drain_available(stream: &mut TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(1)));
    let mut buf = [0u8; 1024];
    let mut total = 0usize;
    while total <= REQUEST_HEAD_LIMIT {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
    }
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
}

/// Close politely on a refused POST: consume what the client already
/// sent (bounded by its declared length or the request caps — a client
/// that declares megabytes gets the documented 503-path tradeoff: its
/// refusal may ride an RST once it keeps dribbling past the bound) so
/// the close is a FIN the client's status read survives. The window is
/// 250ms per read: a loopback client's body is effectively always
/// already buffered; a stalled one gets its refusal either way.
fn drain_for_refuse(stream: &mut TcpStream, head: &RequestHead) {
    let declared = head
        .header("content-length")
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let budget = declared.clamp(REQUEST_HEAD_LIMIT, MAX_BODY_BYTES + REQUEST_HEAD_LIMIT);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
    let mut buf = [0u8; 4096];
    let mut total = 0usize;
    while total < budget {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
    }
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
}

/// Serve ONE connection: read the capped head, parse the wire grammar,
/// dispatch, respond, close (`Connection: close` — one request per
/// connection; the minimal subset needs no keep-alive).
fn serve_connection(mut stream: TcpStream, ctx: &ServerCtx) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let _ = stream.set_nodelay(true);
    let head = match read_head(&mut stream) {
        Head::Complete(head, extra) => (head, extra),
        Head::TooLarge => {
            return write_json_error(&mut stream, 400, "request head exceeds 8 KiB");
        }
        Head::Closed => return Ok(()),
    };
    let line = head.0.line.clone();
    let (method, path) = request_target(&line);
    match parse_request(&line) {
        Ok(Route::BuildRequests) => {
            // The write route reads its body itself (bounded by
            // Content-Length + the body cap) — the gate checks the
            // Authorization header before anything else touches it.
            handle_build_requests_connection(&mut stream, ctx, &head.0, &head.1, method, path)
        }
        Ok(route) => match dispatch(ctx, &route) {
            Ok(handled) => {
                log_request(method, path, handled.status());
                write_handled(&mut stream, handled)
            }
            Err(e) => {
                // The full error chain goes to the LOCAL log only; the
                // wire gets a generic body — dispatch errors can name
                // signing keys, store paths, internal layout, and none
                // of that belongs on the peer-facing wire.
                output::warn(format!("serve: {method} {path} → 500: {e:#}"));
                log_request(method, path, 500);
                write_json_error(&mut stream, 500, "internal error")
            }
        },
        Err(405) => {
            log_request(method, path, 405);
            write_json_error(&mut stream, 405, "method not allowed")
        }
        Err(404) => {
            log_request(method, path, 404);
            write_json_error(&mut stream, 404, "not found")
        }
        Err(_) => {
            log_request(method, path, 400);
            write_json_error(&mut stream, 400, "malformed request")
        }
    }
}

/// The `/build-requests` connection path (ADR-0052 Decision 4): read
/// the bounded body off the socket (a refusal still drains the declared
/// bytes, so the client reliably receives its status), gate on the
/// bearer token BEFORE anything else, validate the identity, write ONE
/// queue file, answer with the request id. Auth failures are 4xx and
/// NEVER a queue write.
fn handle_build_requests_connection(
    stream: &mut TcpStream,
    ctx: &ServerCtx,
    head: &RequestHead,
    extra: &[u8],
    method: &str,
    path: &str,
) -> std::io::Result<()> {
    let gate = match &ctx.build_requests {
        // Route off: 404 like any unknown path — a serve the operator
        // started without --token-file has no write surface at all.
        None => {
            log_request(method, path, 404);
            return write_json_error(stream, 404, "not found");
        }
        Some(gate) => gate,
    };
    let body = match read_body(stream, head, extra) {
        Ok(body) => body,
        Err(status) => {
            log_request(method, path, status);
            // Close politely: drain what the client already sent
            // (bounded by the declared length or the request caps) so
            // the close is a FIN, not an RST that eats the refusal.
            drain_for_refuse(stream, head);
            let message = match status {
                413 => "request body exceeds 64 KiB",
                _ => "malformed request body",
            };
            return write_json_error(stream, status, message);
        }
    };
    // The gate: exact compare against every token line in the
    // operator's file. First, before parsing the body, before the
    // queue — an unauthenticated byte never becomes state.
    match authorize(gate, head.header("authorization")) {
        Ok(()) => {}
        Err(status) => {
            log_request(method, path, status);
            return write_json_error(stream, status, "unauthorized");
        }
    }
    let request: crate::queue::BuildRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            log_request(method, path, 400);
            return write_json_error(
                stream,
                400,
                &format!("body must be {{package, version, requested_by}} JSON: {e}"),
            );
        }
    };
    // enqueue validates the identity grammar itself (fail-closed for
    // every writer); a refusal is a 400 naming the field.
    match gate.queue.enqueue(&request) {
        Ok(id) => {
            log_request(method, path, 202);
            write_response(
                stream,
                202,
                "application/json",
                serde_json::to_vec(&serde_json::json!({ "id": id }))
                    .unwrap_or_else(|_| b"{}".to_vec())
                    .as_slice(),
            )
        }
        Err(e) => {
            log_request(method, path, 400);
            // The validation message names the offending field; it
            // carries no server-side secrets.
            write_json_error(stream, 400, &format!("{e:#}"))
        }
    }
}

/// Read the declared body: `Content-Length` required, capped at
/// [`MAX_BODY_BYTES`], bounded by the socket timeout already set.
/// `extra` is the head reader's over-read — pipelined body bytes that
/// must count toward the body, never be lost. `Err(413)` oversize,
/// `Err(400)` missing/invalid length or a short body (EOF/timeout
/// before the declared bytes arrived).
fn read_body(stream: &mut TcpStream, head: &RequestHead, extra: &[u8]) -> Result<Vec<u8>, u16> {
    let Some(len_raw) = head.header("content-length") else {
        return Err(400);
    };
    let Ok(len) = len_raw.trim().parse::<usize>() else {
        return Err(400);
    };
    if len > MAX_BODY_BYTES {
        return Err(413);
    }
    let mut buf: Vec<u8> = extra.iter().take(len).copied().collect();
    if buf.len() > len {
        return Err(400);
    }
    let mut chunk = [0u8; 512];
    while buf.len() < len {
        let want = (len - buf.len()).min(chunk.len());
        match stream.read(&mut chunk[..want]) {
            Ok(0) => return Err(400),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(ref e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Err(400)
            }
            Err(_) => return Err(400),
        }
    }
    Ok(buf)
}

/// The bearer gate: `Authorization: Bearer <token>` compared EXACTLY
/// against every non-empty line of the operator's token file (re-read
/// per request — revocation is removing the line, no restart). Both
/// the header shape and the lookup failure are 401; the compare walks
/// all candidates in constant time relative to the input (no
/// early-exit on the first matching byte).
fn authorize(gate: &BuildRequestGate, authorization: Option<&str>) -> Result<(), u16> {
    let Some(presented) = authorization.and_then(|a| a.strip_prefix("Bearer ")) else {
        return Err(401);
    };
    let presented = presented.trim();
    if presented.is_empty() {
        return Err(401);
    }
    let Ok(file) = std::fs::read_to_string(&gate.token_file) else {
        // An unreadable token file authenticates nobody.
        return Err(401);
    };
    let mut matched = false;
    for candidate in file.lines() {
        let candidate = candidate.trim();
        if candidate.is_empty() {
            continue;
        }
        if constant_time_eq(presented.as_bytes(), candidate.as_bytes()) {
            matched = true;
        }
    }
    if matched {
        Ok(())
    } else {
        Err(401)
    }
}

/// Byte-equal compare with no data-dependent early exit: the loop
/// always walks the longer input, XOR-accumulating differences
/// (length mismatch included in the accumulator). An exact match and
/// nothing else returns true.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u32;
    let n = a.len().max(b.len());
    for i in 0..n {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        diff |= (av ^ bv) as u32;
    }
    diff == 0
}

/// The (method, path) pair of a request line, verbatim from the wire —
/// display text for the request log, never a path.
fn request_target(line: &str) -> (&str, &str) {
    let mut tokens = line.split_whitespace();
    match (tokens.next(), tokens.next()) {
        (Some(method), Some(path)) => (method, path),
        _ => ("-", "-"),
    }
}

/// One line per handled request: method, path, status — the serving
/// surface's whole observability story. The request path is attacker-
/// controlled bytes: control characters (terminal escapes, CR/LF) are
/// stripped before the line reaches the log.
fn log_request(method: &str, path: &str, status: u16) {
    let path = output::strip_control_chars(path);
    output::info(format!("{method} {path} → {status}"));
}

/// Route a validated request to its handler.
fn dispatch(ctx: &ServerCtx, route: &Route) -> miette::Result<Handled> {
    match route {
        Route::Info => handle_info(ctx),
        Route::Manifest(pkg) => handle_manifest(ctx, pkg),
        Route::Blob(sha) => Ok(handle_blob(ctx, sha)),
        // Unreachable by construction: serve_connection routes the
        // write path through handle_build_requests_connection (it owns
        // the socket for the bounded body read) before dispatch.
        Route::BuildRequests => unreachable!("handled by handle_build_requests_connection"),
    }
}

// ── Endpoints ──

/// One package of the `/info` inventory.
#[derive(Serialize)]
struct InfoPackage {
    name: String,
    version: String,
    revision: u32,
}

/// The `/info` payload (the same shape `export` freezes into
/// `index.json`): node name + the current generation's package set.
#[derive(Serialize)]
struct Info {
    name: String,
    packages: Vec<InfoPackage>,
}

/// `GET /info`: the pod inventory — the UNION of the current
/// generation's records and the inbox-only staged manifests (the same
/// rule `export` freezes into `index.json`, through the same
/// [`nau_core::pkg_manifest`] helpers). Identity is the configured
/// `node.name`; the kernel hostname is only the fallback. No
/// generation and no inbox → an empty inventory (still 200 — the node
/// exists, it just has nothing to show).
fn handle_info(ctx: &ServerCtx) -> miette::Result<Handled> {
    let generation = generation_view::active_generation(&ctx.state_root)?;
    let inbox = nau_core::pkg_manifest::inbox_manifests(&ctx.state_root)?;
    let inbox_only = nau_core::pkg_manifest::union_inbox(&generation, &inbox);
    let mut packages: Vec<InfoPackage> = match &generation {
        Some(gen) => gen
            .packages
            .values()
            .map(|p| InfoPackage {
                name: p.name.clone(),
                version: p.version.clone(),
                revision: p.revision,
            })
            .collect(),
        None => Vec::new(),
    };
    for (name, path) in inbox_only {
        let raw = fs::read(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("reading staged manifest {}", path.display()))?;
        let manifest: nau_core::pkg_manifest::PackageManifest = serde_json::from_slice(&raw)
            .map_err(|e| miette::miette!("staged manifest for '{name}' does not parse: {e}"))?;
        packages.push(InfoPackage {
            name: manifest.name,
            version: manifest.version,
            revision: manifest.revision,
        });
    }
    // Canonical order regardless of generation-vs-inbox split (the
    // rule export's index follows).
    packages.sort_by(|a, b| a.name.cmp(&b.name));
    let info = Info {
        name: ctx
            .node_name
            .clone()
            .unwrap_or_else(nau_core::pkg_manifest::hostname),
        packages,
    };
    let body =
        serde_json::to_vec(&info).map_err(|e| miette::miette!("serialize /info payload: {e}"))?;
    Ok(Handled::Body(200, "application/json", body))
}

/// `GET /manifests/<pkg>` — the union rule (`pkg_manifest::manifest_path`
/// invariant): a package in the current generation is minted from its
/// records and signed on the spot (unsigned store entries are never
/// served); otherwise a pull-staged inbox manifest is served verbatim;
/// otherwise 404. The minted body is byte-identical to the file export
/// freezes into `manifests/<pkg>.json` — one mint, one truth.
fn handle_manifest(ctx: &ServerCtx, pkg: &str) -> miette::Result<Handled> {
    let generation: Option<Generation> = generation_view::active_generation(&ctx.state_root)?;
    if let Some(rec) = generation.as_ref().and_then(|g| g.packages.get(pkg)) {
        let kp = nau_core::pkg_manifest::load_signing_key(&ctx.home)?;
        let mut manifest = nau_core::pkg_manifest::mint_manifest(rec);
        nau_core::pkg_manifest::sign(&mut manifest, &kp)?;
        let body = serde_json::to_vec_pretty(&manifest)
            .map_err(|e| miette::miette!("serialize package manifest: {e}"))?;
        return Ok(Handled::Body(200, "application/json", body));
    }
    let inbox = nau_core::pkg_manifest::manifest_path(&ctx.state_root, pkg);
    match fs::metadata(&inbox) {
        Ok(meta) if meta.is_file() => {
            let body = fs::read(&inbox)
                .into_diagnostic()
                .wrap_err_with(|| format!("reading inbox manifest {}", inbox.display()))?;
            Ok(Handled::Body(200, "application/json", body))
        }
        _ => Ok(not_found()),
    }
}

/// `GET /blobs/<sha256>`: stream the content blob with Content-Length,
/// resolved ONLY through [`BlobStore::blob_path`] after the strict
/// hex-grammar validation — never a raw join. Absent → 404.
fn handle_blob(ctx: &ServerCtx, sha: &str) -> Handled {
    let path = ctx.blobs.blob_path(sha);
    match fs::metadata(&path) {
        Ok(meta) if meta.is_file() => {
            Handled::File(200, "application/octet-stream", path, meta.len())
        }
        _ => not_found(),
    }
}

fn not_found() -> Handled {
    Handled::Body(
        404,
        "application/json",
        b"{\"error\":\"not found\"}".to_vec(),
    )
}

// ── Response writing ──

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

/// Minimal headers: Content-Type, Content-Length, Connection: close.
fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        reason(status),
        content_type,
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Stream a [`Handled::File`] with its declared Content-Length — blobs
/// are copied, never slurped whole into memory.
fn write_handled(stream: &mut TcpStream, handled: Handled) -> std::io::Result<()> {
    match handled {
        Handled::Body(status, ctype, body) => write_response(stream, status, ctype, &body),
        Handled::File(status, ctype, path, len) => {
            let Ok(mut file) = fs::File::open(&path) else {
                return write_json_error(stream, 404, "not found");
            };
            let head = format!(
                "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                status,
                reason(status),
                ctype,
                len
            );
            stream.write_all(head.as_bytes())?;
            std::io::copy(&mut file, stream)?;
            stream.flush()
        }
    }
}

/// A JSON `{"error": ...}` refusal (e.g. a missing signing key — the
/// mint error already names `nau key keygen`).
fn write_json_error(stream: &mut TcpStream, status: u16, message: &str) -> std::io::Result<()> {
    let body = serde_json::json!({ "error": message }).to_string();
    write_response(stream, status, "application/json", body.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nau_core::cache_key::sha256_hex;
    use nau_core::generation_view;
    use nau_core::pkg_manifest;
    use nau_core::pkg_manifest::InstalledPackage;
    use nau_core::sign;
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::net::SocketAddr;

    // ── Pure wire-grammar tests ──

    #[test]
    fn parses_the_three_route_shapes() {
        assert_eq!(parse_request("GET /info HTTP/1.1"), Ok(Route::Info));
        assert_eq!(
            parse_request("GET /manifests/hello-world HTTP/1.1"),
            Ok(Route::Manifest("hello-world".to_string()))
        );
        assert_eq!(
            parse_request("GET /manifests/a1-2 HTTP/1.0"),
            Ok(Route::Manifest("a1-2".to_string()))
        );
        assert_eq!(
            parse_request(&format!("GET /blobs/{} HTTP/1.1", "ab".repeat(32))),
            Ok(Route::Blob("ab".repeat(32)))
        );
    }

    #[test]
    fn non_get_methods_are_405() {
        assert_eq!(parse_request("POST /info HTTP/1.1"), Err(405));
        assert_eq!(parse_request("DELETE /blobs/x HTTP/1.1"), Err(405));
        assert_eq!(parse_request("get /info HTTP/1.1"), Err(405));
    }

    #[test]
    fn malformed_request_lines_are_400() {
        assert_eq!(parse_request("GET /info"), Err(400));
        assert_eq!(parse_request("GET"), Err(400));
        assert_eq!(parse_request(""), Err(400));
        assert_eq!(parse_request("GET /info HTTP/1.1 extra"), Err(400));
        assert_eq!(parse_request("GET /info FTP/1.1"), Err(400));
    }

    #[test]
    fn traversal_attempts_are_404() {
        // The ADR's council exploit path — must never reach a path join.
        assert_eq!(
            parse_request("GET /blobs/../../etc/passwd HTTP/1.1"),
            Err(404)
        );
        assert_eq!(
            parse_request("GET /blobs/../../../.config/nau/secret-key HTTP/1.1"),
            Err(404)
        );
        assert_eq!(
            parse_request("GET /manifests/../pod.lua HTTP/1.1"),
            Err(404)
        );
        assert_eq!(parse_request("GET /manifests/.. HTTP/1.1"), Err(404));
    }

    #[test]
    fn blob_grammar_demands_exactly_64_lowercase_hex() {
        let upper = "AB".repeat(32);
        assert_eq!(
            parse_request(&format!("GET /blobs/{upper} HTTP/1.1")),
            Err(404)
        );
        assert_eq!(
            parse_request(&format!("GET /blobs/{} HTTP/1.1", "ab".repeat(31))),
            Err(404)
        );
        assert_eq!(
            parse_request(&format!("GET /blobs/{} HTTP/1.1", "ab".repeat(33))),
            Err(404)
        );
        assert_eq!(parse_request("GET /blobs/ HTTP/1.1"), Err(404));
        // Non-hex alphabet.
        assert_eq!(
            parse_request(&format!("GET /blobs/{} HTTP/1.1", "zz".repeat(32))),
            Err(404)
        );
    }

    #[test]
    fn manifest_grammar_is_the_collision_classifier_charset() {
        assert_eq!(parse_request("GET /manifests/UPPER HTTP/1.1"), Err(404));
        assert_eq!(parse_request("GET /manifests/ HTTP/1.1"), Err(404));
        assert_eq!(parse_request("GET /manifests/a/b HTTP/1.1"), Err(404));
        assert_eq!(
            parse_request("GET /manifests/with_underscore HTTP/1.1"),
            Err(404)
        );
    }

    #[test]
    fn query_strings_and_unknown_paths_are_404() {
        assert_eq!(parse_request("GET /info?x=1 HTTP/1.1"), Err(404));
        assert_eq!(parse_request("GET /info/ HTTP/1.1"), Err(404));
        assert_eq!(parse_request("GET /blobs/abc?x HTTP/1.1"), Err(404));
        assert_eq!(parse_request("GET /etc/passwd HTTP/1.1"), Err(404));
        assert_eq!(parse_request("GET / HTTP/1.1"), Err(404));
    }

    #[test]
    fn the_build_requests_route_is_post_only() {
        assert_eq!(
            parse_request("POST /build-requests HTTP/1.1"),
            Ok(Route::BuildRequests)
        );
        assert_eq!(parse_request("GET /build-requests HTTP/1.1"), Err(405));
        assert_eq!(parse_request("DELETE /build-requests HTTP/1.1"), Err(405));
        assert_eq!(parse_request("PUT /build-requests HTTP/1.1"), Err(405));
        assert_eq!(parse_request("post /build-requests HTTP/1.1"), Err(405));
        // The GET routes keep refusing POST (the write route did not
        // loosen the read-only grammar), and the method check precedes
        // the path grammar everywhere — the pre-existing wire posture.
        assert_eq!(parse_request("POST /info HTTP/1.1"), Err(405));
        assert_eq!(parse_request("POST /build-requests/ HTTP/1.1"), Err(405));
        assert_eq!(parse_request("POST /build-requests?x=1 HTTP/1.1"), Err(405));
    }

    #[test]
    fn oversized_head_is_too_large() {
        // 9 KiB with no head terminator → the 8 KiB cap fires.
        let bloated = vec![b'a'; REQUEST_HEAD_LIMIT + 1024];
        assert!(matches!(
            read_head(&mut Cursor::new(bloated)),
            Head::TooLarge
        ));
    }

    #[test]
    fn head_reader_extracts_the_request_line_and_parses_headers() {
        let raw = b"GET /info HTTP/1.1\r\nHost: peer\r\nUser-Agent: curl/8\r\n\r\n";
        match read_head(&mut Cursor::new(&raw[..])) {
            Head::Complete(head, extra) => {
                assert_eq!(head.line, "GET /info HTTP/1.1");
                assert_eq!(head.header("host"), Some("peer"));
                assert_eq!(
                    head.header("HOST"),
                    Some("peer"),
                    "lookup is case-insensitive"
                );
                assert_eq!(head.header("user-agent"), Some("curl/8"));
                assert_eq!(head.header("missing"), None);
                assert!(extra.is_empty(), "a GET with no body over-reads nothing");
            }
            other => panic!("expected a request head, got {other:?}"),
        }
        // EOF with no terminator → closed, never a hang.
        assert!(matches!(
            read_head(&mut Cursor::new(b"GET /info")),
            Head::Closed
        ));
        assert!(matches!(read_head(&mut Cursor::new(b"")), Head::Closed));
    }

    #[test]
    fn grammar_helpers_reject_dots_and_slashes() {
        assert!(!is_pkg_name(""));
        assert!(!is_pkg_name("a/b"));
        assert!(!is_pkg_name(".."));
        assert!(!is_pkg_name("a.b"));
        assert!(is_pkg_name("hello-world-2"));
        assert!(!is_sha256(&"c".repeat(63)));
        assert!(!is_sha256(&"c".repeat(65)));
        assert!(is_sha256(&"0123456789abcdef".repeat(4)));
    }

    #[test]
    fn resolve_bind_merges_cli_overrides_onto_the_loopback_default() {
        assert_eq!(
            resolve_bind(None, None).unwrap(),
            ("127.0.0.1".to_string(), 7780)
        );
        assert_eq!(
            resolve_bind(Some("0.0.0.0:9000"), None).unwrap(),
            ("0.0.0.0".to_string(), 9000)
        );
        assert_eq!(
            resolve_bind(Some("0.0.0.0:9000"), Some(8888)).unwrap(),
            ("0.0.0.0".to_string(), 8888)
        );
        assert_eq!(
            resolve_bind(None, Some(8080)).unwrap(),
            ("127.0.0.1".to_string(), 8080)
        );
        // IPv6 bracket form keeps its literal host.
        assert_eq!(
            resolve_bind(Some("[::1]:7780"), None).unwrap(),
            ("::1".to_string(), 7780)
        );
        assert!(resolve_bind(Some("nonsense"), None).is_err());
    }

    // ── Loopback integration tests ──

    /// A fabricated pod-store tree: generation 1 with one package
    /// ("hello-world"), its content blob, a pull-staged inbox manifest
    /// for a package NOT in the generation, and a signing key under a
    /// tempdir home — the minimal shape `serve` publishes.
    struct ServeFixture {
        addr: SocketAddr,
        /// Live connection count — lets the cap test wait for a full
        /// server deterministically instead of sleeping.
        active: Arc<AtomicUsize>,
        public_hex: String,
        blob_sha: String,
        blob_body: Vec<u8>,
        inbox_body: Vec<u8>,
    }

    /// Fabricate the store and start the accept loop on 127.0.0.1:0.
    /// The tempdir moves into the server thread, so the tree outlives
    /// the test body. `with_key = false` leaves the signing home
    /// keyless — the /manifests mint then fails (the generic-500 case).
    fn start() -> ServeFixture {
        start_with_signing_key(true)
    }

    /// Start with a `/build-requests` gate: the token lives at
    /// `<root>/tokens` (exactly `farm-token`), the queue at
    /// `<root>/queue`. Both tempdirs stay in the fixture so the tree
    /// outlives the loop.
    fn start_with_gate() -> (ServeFixture, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        // The served pod only needs to exist for serve_ctx's store gate;
        // the write-route tests never touch the read-only surface.
        fs::create_dir_all(dir.path().join("default")).unwrap();
        let token_file = dir.path().join("tokens");
        std::fs::write(&token_file, "farm-token\n").unwrap();
        let queue_dir = dir.path().join("queue");
        let (pod_name, ctx) =
            serve_ctx(dir.path(), None, None, Some(&token_file), Some(&queue_dir)).unwrap();
        assert_eq!(pod_name, "default");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let active = Arc::new(AtomicUsize::new(0));
        let server_active = Arc::clone(&active);
        thread::spawn(move || accept_loop(listener, ctx, server_active));
        let fx = ServeFixture {
            addr,
            active,
            public_hex: String::new(),
            blob_sha: String::new(),
            blob_body: Vec::new(),
            inbox_body: Vec::new(),
        };
        (fx, dir)
    }

    fn start_with_signing_key(with_key: bool) -> ServeFixture {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let blobs = BlobStore::new(root.join("store"));

        // Blob + generation record for "hello-world".
        let blob_body = b"payload-bytes".to_vec();
        let blob_sha = sha256_hex(&blob_body);
        let blob_path = blobs.blob_path(&blob_sha);
        fs::create_dir_all(blob_path.parent().unwrap()).unwrap();
        fs::write(&blob_path, &blob_body).unwrap();

        let mut packages = BTreeMap::new();
        packages.insert(
            "hello-world".to_string(),
            InstalledPackage {
                name: "hello-world".into(),
                version: "2.10".into(),
                revision: 7,
                sha3_384: "abc".into(),
                files: vec![blob_sha.clone()],
                units: Vec::new(),
                layer: nau_core::pkg_manifest::ClaimLayer::Own,
                apps: BTreeMap::new(),
                requires: Vec::new(),
                launchers: BTreeMap::new(),
                assembly: BTreeMap::new(),
                confined: None,
                app_confined: BTreeMap::new(),
                desktops: BTreeMap::new(),
                fonts: BTreeMap::new(),
                services: BTreeMap::new(),
                service_bins: BTreeMap::new(),
                meta_digest: None,
            },
        );
        let gen = Generation {
            n: 1,
            base_version: "24.04".into(),
            packages,
            created_epoch: 0,
            boot_entry: None,
        };
        let gen_dir = generation_view::generation_dir(root, 1);
        fs::create_dir_all(gen_dir.join("extensions")).unwrap();
        fs::write(
            gen_dir.join("manifest.json"),
            serde_json::to_vec(&gen).unwrap(),
        )
        .unwrap();
        std::os::unix::fs::symlink("generations/1", root.join("active")).unwrap();

        // Pull-staged inbox manifest for a staged-but-uninstalled pkg
        // (a real PackageManifest — /info walks the union and parses it).
        let inbox_manifest = pkg_manifest::PackageManifest {
            name: "inbox-only".into(),
            version: "0.4".into(),
            revision: 3,
            target: pkg_manifest::host_target(),
            files: vec![],
            install: Default::default(),
            signer: String::new(),
            signature: String::new(),
        };
        let inbox_body = serde_json::to_vec(&inbox_manifest).unwrap();
        let inbox = pkg_manifest::manifest_path(root, "inbox-only");
        fs::create_dir_all(inbox.parent().unwrap()).unwrap();
        fs::write(&inbox, &inbox_body).unwrap();

        // A secret the traversal attempt must NOT be able to reach.
        let home = root.join("home");
        let public_hex = if with_key {
            let kp = sign::create_secret_key(&home).unwrap();
            kp.public_hex()
        } else {
            String::new()
        };

        let ctx = ServerCtx {
            state_root: root.to_path_buf(),
            blobs: Arc::new(blobs),
            home,
            node_name: None,
            build_requests: None,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let active = Arc::new(AtomicUsize::new(0));
        let server_active = Arc::clone(&active);
        thread::spawn(move || {
            // `dir` moved here: the tree lives as long as the loop.
            let _keep = dir;
            accept_loop(listener, ctx, server_active);
        });
        ServeFixture {
            addr,
            active,
            public_hex,
            blob_sha,
            blob_body,
            inbox_body,
        }
    }

    /// Raw std-only HTTP client: send `raw`, read to EOF, split into
    /// (status, lowercased head, body).
    fn http_exchange(addr: SocketAddr, raw: &[u8]) -> (u16, String, Vec<u8>) {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        stream.write_all(raw).unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).unwrap();
        let split = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("response head terminator");
        let head = String::from_utf8_lossy(&buf[..split]).to_ascii_lowercase();
        let status: u16 = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .expect("status line");
        (status, head, buf[split + 4..].to_vec())
    }

    fn get(addr: SocketAddr, path: &str) -> (u16, String, Vec<u8>) {
        http_exchange(
            addr,
            format!("GET {path} HTTP/1.1\r\nHost: test\r\n\r\n").as_bytes(),
        )
    }

    /// Wait (bounded) until the server reports `want` live connections.
    fn wait_for_active(fx: &ServeFixture, want: usize) {
        for _ in 0..500 {
            if fx.active.load(Ordering::Relaxed) == want {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!(
            "server never reached {want} live connections (at {})",
            fx.active.load(Ordering::Relaxed)
        );
    }

    #[test]
    fn serve_end_to_end_loopback() {
        let fx = start();
        let addr = fx.addr;

        // /info: 200, valid JSON, the union inventory — the generation
        // package AND the inbox-only staged package.
        let (status, head, body) = get(addr, "/info");
        assert_eq!(status, 200);
        assert!(head.contains("content-type: application/json"));
        assert!(head.contains("content-length:"));
        assert!(head.contains("connection: close"));
        let info: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(!info["name"].as_str().unwrap().is_empty());
        let pkgs = info["packages"].as_array().unwrap();
        assert_eq!(pkgs.len(), 2, "generation ∪ inbox-only");
        assert_eq!(pkgs[0]["name"], "hello-world");
        assert_eq!(pkgs[0]["version"], "2.10");
        assert_eq!(pkgs[0]["revision"], 7);
        assert_eq!(pkgs[1]["name"], "inbox-only");
        assert_eq!(pkgs[1]["version"], "0.4");
        assert_eq!(pkgs[1]["revision"], 3);

        // /manifests/hello-world: minted + signed, self-consistent.
        let (status, _, body) = get(addr, "/manifests/hello-world");
        assert_eq!(status, 200);
        let manifest: pkg_manifest::PackageManifest = serde_json::from_slice(&body).unwrap();
        assert_eq!(manifest.name, "hello-world");
        assert_eq!(manifest.revision, 7);
        assert_eq!(manifest.files.len(), 1);
        assert_eq!(manifest.files[0].sha256, fx.blob_sha);
        pkg_manifest::verify(&manifest, &fx.public_hex)
            .expect("the served manifest must signature-verify");

        // /blobs/<sha>: streamed body matches, Content-Length present.
        let (status, head, body) = get(addr, &format!("/blobs/{}", fx.blob_sha));
        assert_eq!(status, 200);
        assert!(head.contains("content-type: application/octet-stream"));
        assert!(
            head.contains(&format!("content-length: {}", fx.blob_body.len())),
            "Content-Length header must match the blob: {head}"
        );
        assert_eq!(body, fx.blob_body);

        // Inbox union: staged-but-uninstalled manifest served verbatim.
        let (status, _, body) = get(addr, "/manifests/inbox-only");
        assert_eq!(status, 200);
        assert_eq!(body, fx.inbox_body);
    }

    #[test]
    fn serve_refuses_traversal_unknown_and_wrong_method() {
        let fx = start();
        let addr = fx.addr;

        // The ADR's exploit request: must be 404, never a file read —
        // and the key under the store tree must not leak.
        let (status, _, body) = get(addr, "/blobs/../../home/.config/nau/secret-key");
        assert_eq!(status, 404);
        assert!(!body.is_empty());

        // Uppercase hex / 63-hex blobs: grammar refuses.
        assert_eq!(get(addr, &format!("/blobs/{}", "AB".repeat(32))).0, 404);
        assert_eq!(get(addr, &format!("/blobs/{}", "ab".repeat(31))).0, 404);

        // Unknown package / unknown blob / unknown path.
        assert_eq!(get(addr, "/manifests/missing").0, 404);
        assert_eq!(get(addr, &format!("/blobs/{}", "cd".repeat(32))).0, 404);
        assert_eq!(get(addr, "/nope").0, 404);

        // POST: 405.
        let (status, _, _) = http_exchange(
            addr,
            b"POST /info HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\r\n",
        );
        assert_eq!(status, 405);
    }

    #[test]
    fn serve_holds_the_concurrency_cap_and_refuses_with_503() {
        let fx = start();
        let addr = fx.addr;

        // 16 silent connections occupy every slot (their handlers sit
        // in the 5s read timeout). The 17th gets 503 on the spot.
        let holders: Vec<TcpStream> = (0..MAX_CONCURRENT_CONNECTIONS)
            .map(|_| TcpStream::connect(addr).unwrap())
            .collect();
        wait_for_active(&fx, MAX_CONCURRENT_CONNECTIONS);
        let (status, _, _) = get(addr, "/info");
        assert_eq!(status, 503, "a full server must refuse with 503");

        // Slots free up again once the holders disconnect: their
        // handlers wake on EOF (no 5s wait), the count drains to 0,
        // and the next request is served.
        drop(holders);
        wait_for_active(&fx, 0);
        assert_eq!(get(addr, "/info").0, 200);
    }

    /// A pod directory whose generation-1 store holds exactly one
    /// package (`pkg`) with a single blob — enough for `/info` to
    /// identify whose store is being served.
    fn fabricate_pod(root: &Path, pod: &str, pkg: &str) {
        let state_root = root.join(pod);
        let blobs = BlobStore::new(state_root.join("store"));
        let body = format!("payload-of-{pkg}").into_bytes();
        let sha = sha256_hex(&body);
        let blob_path = blobs.blob_path(&sha);
        fs::create_dir_all(blob_path.parent().unwrap()).unwrap();
        fs::write(&blob_path, &body).unwrap();

        let mut packages = BTreeMap::new();
        packages.insert(
            pkg.to_string(),
            InstalledPackage {
                name: pkg.to_string(),
                version: "1.0".into(),
                revision: 1,
                sha3_384: "abc".into(),
                files: vec![sha],
                units: Vec::new(),
                layer: nau_core::pkg_manifest::ClaimLayer::Own,
                apps: BTreeMap::new(),
                requires: Vec::new(),
                launchers: BTreeMap::new(),
                assembly: BTreeMap::new(),
                confined: None,
                app_confined: BTreeMap::new(),
                desktops: BTreeMap::new(),
                fonts: BTreeMap::new(),
                services: BTreeMap::new(),
                service_bins: BTreeMap::new(),
                meta_digest: None,
            },
        );
        let gen = Generation {
            n: 1,
            base_version: "24.04".into(),
            packages,
            created_epoch: 0,
            boot_entry: None,
        };
        let gen_dir = generation_view::generation_dir(&state_root, 1);
        fs::create_dir_all(gen_dir.join("extensions")).unwrap();
        fs::write(
            gen_dir.join("manifest.json"),
            serde_json::to_vec(&gen).unwrap(),
        )
        .unwrap();
        std::os::unix::fs::symlink("generations/1", state_root.join("active")).unwrap();
    }

    /// `--pod` selects the named pod's store as the served surface
    /// (ADR-0033 Decision 5): two pods in a tempdir root, the
    /// non-default one served, `/info` reflects ITS inventory.
    #[test]
    fn serve_pod_flag_serves_the_named_pod() {
        let root = tempfile::tempdir().unwrap();
        fabricate_pod(root.path(), "default", "default-pod-pkg");
        fabricate_pod(root.path(), "lab", "lab-pod-pkg");

        // No flag: the default pod, as before.
        let (name, _) = serve_ctx(root.path(), None, None, None, None).unwrap();
        assert_eq!(name, "default");

        let (name, ctx) = serve_ctx(root.path(), Some("lab"), None, None, None).unwrap();
        assert_eq!(name, "lab");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || accept_loop(listener, ctx, Arc::new(AtomicUsize::new(0))));

        let (status, _, body) = get(addr, "/info");
        assert_eq!(status, 200);
        let info: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let pkgs = info["packages"].as_array().unwrap();
        assert_eq!(pkgs.len(), 1, "the served store is lab's, not default's");
        assert_eq!(pkgs[0]["name"], "lab-pod-pkg");

        // A missing store is a named refusal.
        let err = serve_ctx(root.path(), Some("ghost"), None, None, None)
            .err()
            .expect("no such pod");
        assert!(err.to_string().contains("ghost"), "{err}");
    }

    /// `/info` identity (Decision 6): the configured node name is
    /// published when known; the kernel hostname is only the fallback.
    #[test]
    fn info_publishes_the_node_name_over_the_hostname_fallback() {
        let root = tempfile::tempdir().unwrap();
        fabricate_pod(root.path(), "default", "pkg");
        let (pod_name, ctx) = serve_ctx(root.path(), None, Some("devbox"), None, None).unwrap();
        assert_eq!(pod_name, "default");
        let info = handle_info(&ctx).expect("info builds");
        let Handled::Body(200, _, body) = info else {
            panic!("expected a body response");
        };
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["name"], "devbox");

        // No node name → kernel hostname fallback (never empty).
        let (_, ctx) = serve_ctx(root.path(), None, None, None, None).unwrap();
        let info = handle_info(&ctx).expect("info builds");
        let Handled::Body(_, _, body) = info else {
            panic!("expected a body response");
        };
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            !parsed["name"].as_str().unwrap().is_empty(),
            "the hostname fallback must not be empty"
        );
    }

    /// A request line carrying ANSI escapes is logged sanitized: the
    /// control characters (ESC) are stripped before the line reaches
    /// output::info, defusing terminal escapes from attacker bytes.
    #[test]
    fn logged_paths_are_sanitized_of_control_characters() {
        let line = "GET /manifests/\u{1b}[31mhello-world\u{1b}[0m HTTP/1.1";
        let (method, path) = request_target(line);
        let sanitized = output::strip_control_chars(path);
        assert!(
            !sanitized.contains('\u{1b}'),
            "no ESC may survive: {sanitized:?}"
        );
        assert_eq!(sanitized, "/manifests/[31mhello-world[0m");
        // The method is echoed verbatim from the same wire line — the
        // log line is built from the sanitized path.
        assert_eq!(method, "GET");
    }

    /// A dispatch error (here: no signing key for the /manifests mint)
    /// logs the chain locally but returns a GENERIC body — the error
    /// text (key paths, `nau key keygen` hints, store layout) must
    /// never reach the wire.
    #[test]
    fn internal_errors_return_a_generic_body_not_the_error_chain() {
        let fx = start_with_signing_key(false);
        let (status, _, body) = get(fx.addr, "/manifests/hello-world");
        assert_eq!(status, 500);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed, serde_json::json!({ "error": "internal error" }));
        let text = String::from_utf8_lossy(&body);
        assert!(
            !text.contains("keygen"),
            "no ceremony hints on the wire: {text}"
        );
        assert!(
            !text.contains("secret-key"),
            "no key paths on the wire: {text}"
        );
    }

    // ── POST /build-requests (ADR-0052 Decision 4) ──

    /// A raw POST with Authorization + JSON body; returns
    /// (status, lowercased head, body).
    fn post(
        addr: SocketAddr,
        token: Option<&str>,
        body: &str,
        extra: &[(&str, &str)],
    ) -> (u16, String, Vec<u8>) {
        let mut req = String::from("POST /build-requests HTTP/1.1\r\nHost: test\r\n");
        if let Some(token) = token {
            req.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        for (name, value) in extra {
            req.push_str(&format!("{name}: {value}\r\n"));
        }
        // A caller-supplied content-length header overrides the default
        // (the missing-length test passes none by blanking it here).
        if !extra
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        {
            req.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        req.push_str("\r\n");
        req.push_str(body);
        http_exchange(addr, req.as_bytes())
    }

    fn request_body(pkg: &str, version: &str, by: &str) -> String {
        serde_json::json!({ "package": pkg, "version": version, "requested_by": by }).to_string()
    }

    /// The gate is BEFORE everything: no token, a wrong token, and a
    /// revoked token all answer 401 — and the queue directory never
    /// gains a file.
    #[test]
    fn post_is_bearer_gated_before_any_queue_write() {
        let (fx, dir) = start_with_gate();
        let queue_root = dir.path().join("queue");
        let queue = crate::queue::BuildQueue::new(&queue_root);
        let body = request_body("hello-world", "1.2.3", "device-7");

        // No Authorization header at all.
        let (status, ..) = post(fx.addr, None, &body, &[]);
        assert_eq!(status, 401);
        // Malformed scheme.
        let raw = format!(
            "POST /build-requests HTTP/1.1\r\nHost: t\r\nAuthorization: Basic zzz\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        assert_eq!(http_exchange(fx.addr, raw.as_bytes()).0, 401);
        // Wrong token.
        let (status, _, resp) = post(fx.addr, Some("not-the-token"), &body, &[]);
        assert_eq!(status, 401);
        let text = String::from_utf8_lossy(&resp);
        assert!(text.contains("unauthorized"), "{text}");

        // Revocation: removing the line from the token file takes
        // effect on the NEXT request (per-request re-read).
        std::fs::write(dir.path().join("tokens"), "another-token\n").unwrap();
        assert_eq!(post(fx.addr, Some("farm-token"), &body, &[]).0, 401);

        // The refused requests never touched the queue.
        assert_eq!(queue.pending_count().unwrap(), 0);
        assert!(queue.claim().unwrap().is_none());
    }

    #[test]
    fn post_happy_path_writes_one_queue_file_and_answers_the_id() {
        let (fx, dir) = start_with_gate();
        let queue = crate::queue::BuildQueue::new(dir.path().join("queue"));

        let (status, head, resp) = post(
            fx.addr,
            Some("farm-token"),
            &request_body("hello-world", "1.2.3", "device-7"),
            &[],
        );
        assert_eq!(status, 202);
        assert!(head.contains("content-type: application/json"));
        let parsed: serde_json::Value = serde_json::from_slice(&resp).unwrap();
        let id = parsed["id"].as_str().expect("202 names the request id");

        // The queue holds exactly the request that was POSTed.
        assert_eq!(queue.pending_count().unwrap(), 1);
        let claimed = queue.claim().unwrap().expect("the request is claimable");
        assert_eq!(claimed.id, id);
        assert_eq!(claimed.request.package, "hello-world");
        assert_eq!(claimed.request.version, "1.2.3");
        assert_eq!(claimed.request.requested_by, "device-7");
    }

    #[test]
    fn post_malformed_identities_are_400_after_auth() {
        let (fx, dir) = start_with_gate();
        let queue = crate::queue::BuildQueue::new(dir.path().join("queue"));

        // Not JSON.
        let (status, _, _) = post(fx.addr, Some("farm-token"), "not json", &[]);
        assert_eq!(status, 400);
        // Package outside the collision-classifier charset.
        assert_eq!(
            post(
                fx.addr,
                Some("farm-token"),
                &request_body("Hello_World", "1.2.3", "d"),
                &[]
            )
            .0,
            400
        );
        // Version that is not a plain triple.
        assert_eq!(
            post(
                fx.addr,
                Some("farm-token"),
                &request_body("hello", "v1.2.3", "d"),
                &[]
            )
            .0,
            400
        );
        assert_eq!(
            post(
                fx.addr,
                Some("farm-token"),
                &request_body("hello", "1.2", "d"),
                &[]
            )
            .0,
            400
        );
        // Empty requested_by.
        assert_eq!(
            post(
                fx.addr,
                Some("farm-token"),
                &request_body("hello", "1.2.3", ""),
                &[]
            )
            .0,
            400
        );

        // Every refusal stayed a refusal: nothing entered the queue.
        assert_eq!(queue.pending_count().unwrap(), 0);
    }

    #[test]
    fn post_enforces_the_body_framing_rules() {
        let (fx, _) = start_with_gate();
        let body = request_body("hello-world", "1.2.3", "device-7");

        // No Content-Length: refused before the body matters.
        let raw = format!(
            "POST /build-requests HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer farm-token\r\n\r\n{body}"
        );
        assert_eq!(http_exchange(fx.addr, raw.as_bytes()).0, 400);
        // Non-integer Content-Length.
        let (status, _, _) = post(
            fx.addr,
            Some("farm-token"),
            &body,
            &[("Content-Length", "abc")],
        );
        assert_eq!(status, 400);
        // Oversize: over the 64 KiB cap is 413 (the head still parses —
        // the body is never read).
        let blob = "x".repeat(MAX_BODY_BYTES + 1);
        let raw = format!(
            "POST /build-requests HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer farm-token\r\nContent-Length: {}\r\n\r\n{blob}",
            blob.len()
        );
        assert_eq!(http_exchange(fx.addr, raw.as_bytes()).0, 413);
    }

    #[test]
    fn the_route_is_off_without_a_token_file() {
        // The plain fixture configures no gate: POST answers 404 like
        // any unknown path, whatever the credentials say.
        let fx = start();
        let (status, _, _) = post(
            fx.addr,
            Some("anything"),
            &request_body("hello", "1.2.3", "d"),
            &[],
        );
        assert_eq!(status, 404);
        assert_eq!(post(fx.addr, None, "{}", &[]).0, 404);
    }

    #[test]
    fn constant_time_eq_is_exact_equality() {
        assert!(constant_time_eq(b"token", b"token"));
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"token", b"tokeN"));
        assert!(!constant_time_eq(b"token", b"toke"));
        assert!(!constant_time_eq(b"toke", b"token"));
        assert!(!constant_time_eq(b"", b"\0\0\0\0\0"));
        assert!(!constant_time_eq(b"\0\0\0\0\0", b""));
        assert!(!constant_time_eq(b"a", b"b"));
    }
}
