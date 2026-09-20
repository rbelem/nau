//! `shuttle serve` — the peer lane's read-only serving surface
//! (ADR-0033 Decisions 4+5): plain TCP with a minimal HTTP/1.1 subset
//! over the pod store (`GET /info`, `GET /manifests/<pkg>`,
//! `GET /blobs/<sha256>`), foreground until interrupted.
//!
//! The wire grammar is NORMATIVE (ADR-0033 Decision 4 — safety is
//! conditional on it, not intrinsic to "read-only"): a blob segment is
//! exactly 64 lowercase hex resolved through
//! [`crate::runtime::RuntimeStore::blob_path`], never a raw join — a
//! naive join turns `GET /blobs/../../.config/shuttle/secret-key` into
//! an unauthenticated arbitrary-file read over plaintext HTTP. Package
//! names are `[a-z0-9-]+` (the ADR-0032 collision-classifier charset).
//! Everything else is 404. Request line + headers are capped at 8 KiB,
//! every socket gets a read/write timeout, and the server holds a hard
//! connection-concurrency bound (the `oci.rs` bounded-timeout
//! precedent) — a bare `TcpListener` has no slowloris defenses.
//!
//! `/manifests/<pkg>` publishes the UNION of the current generation's
//! records (minted + signed on the fly — unsigned store entries are
//! never served) and the pull-staging inbox
//! ([`crate::pkg_manifest::manifest_path`]) per its documented
//! invariant.

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use miette::{IntoDiagnostic, WrapErr};
use serde::Serialize;

use crate::lua::DEFAULT_SERVE_ADDRESS;
use crate::runtime::{Generation, InstalledPackage, RuntimeStore};

/// Hard connection-concurrency bound (ADR-0033 Decision 4). The accept
/// loop refuses with 503 beyond this — one thread per connection with
/// no bound is a slowloris invitation.
const MAX_CONCURRENT_CONNECTIONS: usize = 16;

/// Total request line + headers cap. Anything longer is refused with
/// 400 before it can pin a connection.
const REQUEST_HEAD_LIMIT: usize = 8 * 1024;

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
}

/// Parse the HTTP request line. `Ok(route)` for a valid GET;
/// `Err(status)` for the refusal code (405 wrong method, 404 anything
/// not matching the three route shapes exactly, 400 malformed line).
fn parse_request(line: &str) -> Result<Route, u16> {
    let mut tokens = line.split_whitespace();
    let (Some(method), Some(path), Some(version)) = (tokens.next(), tokens.next(), tokens.next())
    else {
        return Err(400);
    };
    if tokens.next().is_some() {
        return Err(400);
    }
    if method != "GET" {
        return Err(405);
    }
    if !version.starts_with("HTTP/") {
        return Err(400);
    }
    // Query strings and fragments are not part of any route shape —
    // strict segment grammar rejects them below (nothing outside the
    // three exact forms parses).
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

/// Outcome of reading one request head.
#[derive(Debug)]
enum Head {
    /// The request line (everything before the first CRLF).
    Line(String),
    /// Line + headers exceeded [`REQUEST_HEAD_LIMIT`] — refuse with 400.
    TooLarge,
    /// EOF or timeout before a complete head — close silently.
    Closed,
}

/// Read the request line + headers, capped. The headers themselves are
/// discarded (the responses are all `Connection: close`; nothing in the
/// minimal subset needs them) — only their SIZE is policed.
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
            let line = head.lines().next().unwrap_or_default().to_string();
            return Head::Line(line);
        }
    }
}

// ── Server ──

/// Everything a connection handler needs. Shared across connection
/// threads behind an [`Arc`].
#[derive(Clone)]
struct ServerCtx {
    store: Arc<RuntimeStore>,
    /// Home used for the signing key (`~/.config/shuttle/secret-key`)
    /// when minting manifests. A seam: tests point it at a tempdir.
    home: PathBuf,
}

/// A computed response: either an inline body or a file to stream
/// (`/blobs` — never slurped, always streamed with Content-Length).
enum Handled {
    Body(u16, &'static str, Vec<u8>),
    File(u16, &'static str, PathBuf, u64),
}

/// Run `shuttle serve` with the CLI's bind overrides. `address`/`port`
/// are `None` when the operator gave no flag — the defaults come from
/// `node {}` conventions ([`DEFAULT_SERVE_ADDRESS`], loopback). Serves
/// the invoking user's default pod store (ADR-0033 Decision 5: v1
/// scope is the pod store, foreground, no daemonization).
pub fn run(address: Option<&str>, port: Option<u16>) -> miette::Result<()> {
    let pod_root = crate::pod::pod_root(None);
    let pod_dir = crate::pod::pod_dir(&pod_root, crate::pod::DEFAULT_POD);
    if !pod_dir.is_dir() {
        miette::bail!(
            "no pod store at {} — nothing to serve; sync a pod first \
             (`shuttle pod sync`)",
            pod_dir.display()
        );
    }
    let ctx = ServerCtx {
        store: Arc::new(crate::pod::pod_store(&pod_dir)),
        home: PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())),
    };
    let (host, port) = resolve_bind(address, port)?;
    let listener = TcpListener::bind((host.as_str(), port))
        .into_diagnostic()
        .wrap_err_with(|| format!("binding serve address {host}:{port}"))?;
    crate::output::info(format!(
        "serving pod '{}' store on http://{host}:{port} — Ctrl-C to stop",
        crate::pod::DEFAULT_POD
    ));
    accept_loop(listener, ctx, Arc::new(AtomicUsize::new(0)))
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

/// Serve ONE connection: read the capped head, parse the wire grammar,
/// dispatch, respond, close (`Connection: close` — one request per
/// connection; the minimal subset needs no keep-alive).
fn serve_connection(mut stream: TcpStream, ctx: &ServerCtx) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let _ = stream.set_nodelay(true);
    let line = match read_head(&mut stream) {
        Head::Line(line) => line,
        Head::TooLarge => {
            return write_json_error(&mut stream, 400, "request head exceeds 8 KiB");
        }
        Head::Closed => return Ok(()),
    };
    match parse_request(&line) {
        Ok(route) => match dispatch(ctx, &route) {
            Ok(handled) => write_handled(&mut stream, handled),
            Err(e) => write_json_error(&mut stream, 500, &format!("{e}")),
        },
        Err(405) => write_json_error(&mut stream, 405, "GET only"),
        Err(404) => write_json_error(&mut stream, 404, "not found"),
        Err(_) => write_json_error(&mut stream, 400, "malformed request"),
    }
}

/// Route a validated request to its handler.
fn dispatch(ctx: &ServerCtx, route: &Route) -> miette::Result<Handled> {
    match route {
        Route::Info => handle_info(ctx),
        Route::Manifest(pkg) => handle_manifest(ctx, pkg),
        Route::Blob(sha) => Ok(handle_blob(ctx, sha)),
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

/// `GET /info`: the pod inventory from the current generation's
/// manifest records. No generation yet → an empty inventory (still
/// 200 — the node exists, it just has nothing installed).
fn handle_info(ctx: &ServerCtx) -> miette::Result<Handled> {
    let generation = ctx.store.active_generation()?;
    let info = Info {
        name: hostname(),
        packages: match &generation {
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
        },
    };
    let body =
        serde_json::to_vec(&info).map_err(|e| miette::miette!("serialize /info payload: {e}"))?;
    Ok(Handled::Body(200, "application/json", body))
}

/// `GET /manifests/<pkg>` — the union rule (`pkg_manifest::manifest_path`
/// invariant): a package in the current generation is minted from its
/// records and signed on the spot (unsigned store entries are never
/// served); otherwise a pull-staged inbox manifest is served verbatim;
/// otherwise 404.
fn handle_manifest(ctx: &ServerCtx, pkg: &str) -> miette::Result<Handled> {
    let generation: Option<Generation> = ctx.store.active_generation()?;
    if let Some(rec) = generation.as_ref().and_then(|g| g.packages.get(pkg)) {
        let kp = crate::pkg_manifest::load_signing_key(&ctx.home)?;
        let mut manifest = mint_manifest(rec);
        crate::pkg_manifest::sign(&mut manifest, &kp)?;
        let body = serde_json::to_vec(&manifest)
            .map_err(|e| miette::miette!("serialize package manifest: {e}"))?;
        return Ok(Handled::Body(200, "application/json", body));
    }
    let inbox = crate::pkg_manifest::manifest_path(ctx.store.root(), pkg);
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
/// resolved ONLY through [`RuntimeStore::blob_path`] after the strict
/// hex-grammar validation — never a raw join. Absent → 404.
fn handle_blob(ctx: &ServerCtx, sha: &str) -> Handled {
    let path = ctx.store.blob_path(sha);
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

// ── Minting (ADR-0033 Decision 2) ──

/// Host GNU triplet for the minted `target` field.
fn host_target() -> String {
    format!("{}-unknown-linux-gnu", std::env::consts::ARCH)
}

/// Mint a [`crate::pkg_manifest::PackageManifest`] from a generation's
/// [`InstalledPackage`] records. Identity, the store blob set, and the
/// snap.yaml-derived install metadata all travel (ADR-0033 Decision 2:
/// a receiving peer must reconstruct an installable entry from the
/// manifest alone).
///
/// One honest limitation: generation manifests record per-file HASHES,
/// not payload paths — the path-bearing mint belongs to the build/ingest
/// hooks. Until those land, minted `files[].path` carries the
/// ADR-0012 store address (`store/<aa>/<sha256>`) as a stable
/// placeholder, and `executable` conservatively reads false.
fn mint_manifest(rec: &InstalledPackage) -> crate::pkg_manifest::PackageManifest {
    let InstalledPackage {
        name,
        version,
        revision,
        files,
        units,
        apps,
        launchers,
        assembly,
        confined,
        app_confined,
        desktops,
        fonts,
        services,
        service_bins,
        requires,
        ..
    } = rec.clone();
    crate::pkg_manifest::PackageManifest {
        name,
        version,
        revision,
        target: host_target(),
        files: files
            .iter()
            .map(|h| crate::pkg_manifest::ManifestFile {
                path: format!("store/{}/{}", h.get(..2).unwrap_or(h), h),
                sha256: h.clone(),
                executable: false,
            })
            .collect(),
        install: crate::pkg_manifest::InstallMeta {
            units,
            apps,
            launchers,
            assembly,
            confined,
            app_confined,
            desktops,
            fonts,
            services,
            service_bins,
            requires,
        },
        signer: String::new(),
        signature: String::new(),
    }
}

/// The node name `/info` publishes: the kernel hostname (std fs, no new
/// deps).
fn hostname() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

// ── Response writing ──

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
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
/// mint error already names `shuttle key keygen`).
fn write_json_error(stream: &mut TcpStream, status: u16, message: &str) -> std::io::Result<()> {
    let body = serde_json::json!({ "error": message }).to_string();
    write_response(stream, status, "application/json", body.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkg_manifest;
    use crate::sign;
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
            parse_request("GET /blobs/../../../.config/shuttle/secret-key HTTP/1.1"),
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
    fn oversized_head_is_too_large() {
        // 9 KiB with no head terminator → the 8 KiB cap fires.
        let bloated = vec![b'a'; REQUEST_HEAD_LIMIT + 1024];
        assert!(matches!(
            read_head(&mut Cursor::new(bloated)),
            Head::TooLarge
        ));
    }

    #[test]
    fn head_reader_extracts_the_request_line_and_drops_headers() {
        let raw = b"GET /info HTTP/1.1\r\nHost: peer\r\nUser-Agent: curl/8\r\n\r\n";
        match read_head(&mut Cursor::new(&raw[..])) {
            Head::Line(line) => assert_eq!(line, "GET /info HTTP/1.1"),
            other => panic!("expected a request line, got {other:?}"),
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
    /// the test body.
    fn start() -> ServeFixture {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let store = RuntimeStore::new(root.to_path_buf());

        // Blob + generation record for "hello-world".
        let blob_body = b"payload-bytes".to_vec();
        let blob_sha = crate::oci::sha256_hex(&blob_body);
        let blob_path = store.blob_path(&blob_sha);
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
                layer: crate::farm::ClaimLayer::Own,
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
            },
        );
        let gen = Generation {
            n: 1,
            base_version: "24.04".into(),
            packages,
            created_epoch: 0,
            boot_entry: None,
        };
        let gen_dir = store.generation_dir(1);
        fs::create_dir_all(gen_dir.join("extensions")).unwrap();
        fs::write(
            gen_dir.join("manifest.json"),
            serde_json::to_vec(&gen).unwrap(),
        )
        .unwrap();
        std::os::unix::fs::symlink("generations/1", root.join("active")).unwrap();

        // Pull-staged inbox manifest for a staged-but-uninstalled pkg.
        let inbox_body = br#"{"name":"inbox-only","staged":true}"#.to_vec();
        let inbox = pkg_manifest::manifest_path(root, "inbox-only");
        fs::create_dir_all(inbox.parent().unwrap()).unwrap();
        fs::write(&inbox, &inbox_body).unwrap();

        // A secret the traversal attempt must NOT be able to reach.
        let home = root.join("home");
        let kp = sign::create_secret_key(&home).unwrap();

        let ctx = ServerCtx {
            store: Arc::new(store),
            home,
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
            public_hex: kp.public_hex(),
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

        // /info: 200, valid JSON, the generation package listed.
        let (status, head, body) = get(addr, "/info");
        assert_eq!(status, 200);
        assert!(head.contains("content-type: application/json"));
        assert!(head.contains("content-length:"));
        assert!(head.contains("connection: close"));
        let info: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(!info["name"].as_str().unwrap().is_empty());
        let pkgs = info["packages"].as_array().unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0]["name"], "hello-world");
        assert_eq!(pkgs[0]["version"], "2.10");
        assert_eq!(pkgs[0]["revision"], 7);

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
        let (status, _, body) = get(addr, "/blobs/../../home/.config/shuttle/secret-key");
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
}
