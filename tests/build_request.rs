//! The build-request lane end to end (ADR-0052 Decisions 4+6):
//! the submit client against a hand-rolled loopback listener (the
//! secrets.rs vault-harness precedent — real curl, captured request),
//! and the drain happy path through the REAL farm-side eval
//! (bounded-subprocess worker) with injected build/release seams.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, Mutex};

use nau::build_request::{
    resolve_server_fronts, run_drain, submit, BuildRequest, BuildStep, Drain, ReleaseConfig,
    Releaser,
};
use nau_core::servers::ServerFront;
use nau_peer::queue::BuildQueue;

// ── The hand-rolled listener (secrets.rs:1443 precedent) ──

/// One canned response served over 127.0.0.1 HTTP on an OS-assigned
/// port, for the listener's life (one request per connection). Captures
/// every request's line + Authorization header so a test asserts the
/// exact wire shape the client produced.
struct CannedServer {
    base: String,
    captured: Arc<Mutex<Vec<(String, String)>>>,
}

impl CannedServer {
    /// Bind and serve `status`/`body` to every request.
    fn start(status: &'static str, body: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let captured = Arc::new(Mutex::new(Vec::new()));
        let slot = Arc::clone(&captured);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                serve_one(stream, status, body, &slot);
            }
        });
        Self { base, captured }
    }

    fn requests(&self) -> Vec<(String, String)> {
        self.captured.lock().unwrap().clone()
    }
}

/// Read one request head (to the terminator), capture the request line
/// and the Authorization header, answer canned. Wire errors are
/// swallowed — the capture is the assertion surface.
fn serve_one(
    mut stream: std::net::TcpStream,
    status: &str,
    body: &str,
    captured: &Mutex<Vec<(String, String)>>,
) {
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                data.extend_from_slice(&buf[..n]);
                if data.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
        }
    }
    let req = String::from_utf8_lossy(&data);
    let mut lines = req.split("\r\n");
    let request_line = lines.next().unwrap_or("").to_string();
    let auth = lines
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("Authorization")
                .then(|| value.trim().to_string())
        })
        .unwrap_or_default();
    captured.lock().unwrap().push((request_line, auth));
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}

// ── Submit client over the wire ──

const TOKEN: &str = "farm-secret-token";

fn submit_args() -> (&'static str, &'static str, &'static str) {
    ("hello-world", "1.2.3", "device-7")
}

#[test]
fn submit_posts_the_identity_and_prints_the_server_id() {
    let server = CannedServer::start("202 Accepted", r#"{ "id": "req-123" }"#);
    let (package, version, by) = submit_args();
    let submitted = submit(
        std::slice::from_ref(&server.base),
        package,
        version,
        by,
        TOKEN,
    )
    .expect("submit succeeds");
    assert_eq!(submitted.id, "req-123");
    assert_eq!(submitted.server, server.base);

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    let (line, auth) = &requests[0];
    assert_eq!(line, "POST /build-requests HTTP/1.1", "the route shape");
    assert_eq!(auth, &format!("Bearer {TOKEN}"), "exact bearer header");
}

#[test]
fn submit_surfaces_a_refusal_with_the_server_words() {
    let server = CannedServer::start(
        "400 Bad Request",
        r#"{ "error": "package 'hello-world' is not provisioned on this farm" }"#,
    );
    let err = submit(
        std::slice::from_ref(&server.base),
        "hello-world",
        "1.2.3",
        "device-7",
        TOKEN,
    )
    .expect_err("4xx is terminal");
    let msg = format!("{err:#}");
    assert!(msg.contains("HTTP 400"), "{msg}");
    assert!(
        msg.contains("not provisioned"),
        "the server's words ride: {msg}"
    );
}

#[test]
fn submit_fails_over_on_5xx_and_transport_in_order() {
    // A 5xx front, then a healthy one: the SECOND front answers.
    let bad = CannedServer::start("500 Internal Server Error", r#"{ "error": "boom" }"#);
    let good = CannedServer::start("202 Accepted", r#"{ "id": "req-2nd" }"#);
    let (package, version, by) = submit_args();
    let submitted = submit(
        &[bad.base.clone(), good.base.clone()],
        package,
        version,
        by,
        TOKEN,
    )
    .expect("failover reaches the healthy front");
    assert_eq!(submitted.id, "req-2nd");
    assert_eq!(submitted.server, good.base);

    // A dead transport (nothing listening) falls through too.
    let dead = "http://127.0.0.1:1";
    let submitted = submit(
        &[dead.to_string(), good.base.clone()],
        package,
        version,
        by,
        TOKEN,
    )
    .expect("transport failure falls through to the healthy front");
    assert_eq!(submitted.id, "req-2nd");
}

#[test]
fn submit_validates_before_any_wire() {
    // Nothing listens at this address — a local refusal must happen
    // before any connection attempt.
    let err = submit(
        &["http://127.0.0.1:1".to_string()],
        "BAD_PACKAGE",
        "1.2.3",
        "d",
        TOKEN,
    )
    .expect_err("client-side grammar gate");
    assert!(
        err.to_string().contains("[a-z0-9-]"),
        "refused locally: {err}"
    );
    let err = submit(
        &["http://127.0.0.1:1".to_string()],
        "hello",
        "v1.2.3",
        "d",
        TOKEN,
    )
    .expect_err("client-side version gate");
    assert!(err.to_string().contains("triple"), "{err}");
}

// ── Drain happy path: REAL farm-side eval, injected seams ──

/// The build seam: drops a fake `.snap` (the real `PoolBuild` runs the
/// toolchain-heavy build path — out of the offline suite's scope).
struct FakeBuild;

impl BuildStep for FakeBuild {
    fn build(
        &self,
        request: &BuildRequest,
        meta: &nau_core::snap_types::SnapMeta,
        _recipe: &Path,
        output_dir: &Path,
    ) -> miette::Result<std::path::PathBuf> {
        // The eval-driven contract is visible here: the meta the drain
        // resolved IS the requested identity.
        assert_eq!(meta.name, request.package);
        assert_eq!(meta.version, request.version);
        let path = output_dir.join(format!(
            "{}_{}_amd64.snap",
            request.package, request.version
        ));
        std::fs::write(
            &path,
            format!("fake-snap-of-{}-{}", meta.name, meta.version),
        )
        .unwrap();
        Ok(path)
    }
}

struct FakeRelease;

impl Releaser for FakeRelease {
    fn release(
        &self,
        input: &nau_ship::release::ReleaseInput,
    ) -> miette::Result<nau_ship::release::ReleaseOutput> {
        let body = std::fs::read(&input.snap_path).unwrap();
        assert!(
            body.starts_with(b"fake-snap-of-"),
            "the built artifact flows: {:?}",
            String::from_utf8_lossy(&body)
        );
        Ok(nau_ship::release::ReleaseOutput {
            manifest_url: "https://tree.example/nau/manifests/testpkg.json".into(),
            blob_urls: vec![format!(
                "https://tree.example/nau/blobs/{}",
                "cd".repeat(32)
            )],
        })
    }
}

#[test]
fn drain_claims_evaluates_builds_and_writes_the_release_receipt() {
    let dir = tempfile::tempdir().unwrap();

    // The farm's collection: pkgs/t/testpkg.lua — a recipe that does
    // NOT honor the constraint global, so the identity check carries
    // the version selection (the requested version matches the
    // declaration).
    let recipes = dir.path().join("pkgs");
    let recipe = recipes.join("t").join("testpkg.lua");
    std::fs::create_dir_all(recipe.parent().unwrap()).unwrap();
    std::fs::write(
        &recipe,
        r#"
return {
    testpkg = snap {
        name = "testpkg",
        version = "1.2.3",
        summary = "drain integration fixture",
    },
}
"#,
    )
    .unwrap();

    let queue = BuildQueue::new(dir.path().join("queue"));
    let id = queue
        .enqueue(&BuildRequest {
            package: "testpkg".into(),
            version: "1.2.3".into(),
            requested_by: "device-7".into(),
        })
        .unwrap();

    let drain = Drain {
        queue: queue.clone(),
        recipes_root: recipes,
        release_cfg: ReleaseConfig {
            signing_key: Some(dir.path().join("update.pub")),
            s3_endpoint: Some("https://s3.internal.example".into()),
            s3_bucket: Some("nau-tree".into()),
            s3_region: Some("us-east-1".into()),
            s3_access_key: Some("ak".into()),
            s3_secret_key: Some("sk".into()),
            tree_base: Some("https://tree.example/nau".into()),
        },
        build: Box::new(FakeBuild),
        release: Box::new(FakeRelease),
        once: true,
        poll_secs: 0,
    };
    let settled = run_drain(&drain).expect("the drain runs");
    assert_eq!(settled.len(), 1);
    assert!(settled[0].released, "{:?}", settled[0]);
    assert_eq!(settled[0].id, id);
    assert_eq!(
        settled[0].manifest_url.as_deref(),
        Some("https://tree.example/nau/manifests/testpkg.json")
    );

    // The receipt landed in done/ with the release urls; nothing is
    // claimable anymore.
    let receipt: nau_peer::queue::Receipt = serde_json::from_slice(
        &std::fs::read(
            dir.path()
                .join("queue")
                .join("done")
                .join(format!("{id}.receipt.json")),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(receipt.status, "released");
    assert_eq!(
        receipt.manifest_url.as_deref(),
        Some("https://tree.example/nau/manifests/testpkg.json")
    );
    assert_eq!(receipt.blob_urls.len(), 1);
    assert_eq!(receipt.request.requested_by, "device-7");
    assert!(queue.claim().unwrap().is_none(), "queue fully drained");
}

#[test]
fn drain_honors_the_eval_constraint_for_versioned_recipes() {
    // A constraint-reading recipe (the opencode-bin class): the
    // `constraint` global is the selector, and an unknown version is a
    // loud refusal — the requested version must be adopted verbatim.
    let dir = tempfile::tempdir().unwrap();
    let recipes = dir.path().join("pkgs");
    let recipe = recipes.join("c").join("constrained.lua");
    std::fs::create_dir_all(recipe.parent().unwrap()).unwrap();
    std::fs::write(
        &recipe,
        r#"
local version = "2.0.21"
if constraint ~= nil then
    local pinned = tostring(constraint)
    if pinned ~= "2.0.21" and pinned ~= "2.0.20" then
        error("constrained: unknown version '" .. pinned .. "'")
    end
    version = pinned
end
return {
    constrained = snap {
        name = "constrained",
        version = version,
        summary = "constraint-honoring fixture",
    },
}
"#,
    )
    .unwrap();

    let queue = BuildQueue::new(dir.path().join("queue"));
    queue
        .enqueue(&BuildRequest {
            package: "constrained".into(),
            version: "2.0.20".into(),
            requested_by: "device-9".into(),
        })
        .unwrap();

    let drain = Drain {
        queue: queue.clone(),
        recipes_root: recipes,
        release_cfg: ReleaseConfig {
            signing_key: Some(dir.path().join("update.pub")),
            s3_endpoint: Some("https://s3.internal.example".into()),
            s3_bucket: Some("nau-tree".into()),
            s3_region: Some("us-east-1".into()),
            s3_access_key: Some("ak".into()),
            s3_secret_key: Some("sk".into()),
            tree_base: Some("https://tree.example/nau".into()),
        },
        build: Box::new(FakeBuild),
        release: Box::new(FakeRelease),
        once: true,
        poll_secs: 0,
    };
    let settled = run_drain(&drain).expect("the drain runs");
    assert_eq!(settled.len(), 1);
    assert!(
        settled[0].released,
        "the constraint selected 2.0.20 verbatim: {:?}",
        settled[0]
    );
}

#[test]
fn an_unknown_constraint_is_a_recorded_failure_not_a_release() {
    let dir = tempfile::tempdir().unwrap();
    let recipes = dir.path().join("pkgs");
    let recipe = recipes.join("c").join("constrained.lua");
    std::fs::create_dir_all(recipe.parent().unwrap()).unwrap();
    std::fs::write(
        &recipe,
        r#"
if constraint ~= nil and tostring(constraint) ~= "2.0.21" then
    error("constrained: unknown version '" .. tostring(constraint) .. "'")
end
return {
    constrained = snap {
        name = "constrained",
        version = "2.0.21",
        summary = "constraint-honoring fixture",
    },
}
"#,
    )
    .unwrap();

    let queue = BuildQueue::new(dir.path().join("queue"));
    let id = queue
        .enqueue(&BuildRequest {
            package: "constrained".into(),
            version: "1.0.0".into(),
            requested_by: "device-9".into(),
        })
        .unwrap();

    let drain = Drain {
        queue: queue.clone(),
        recipes_root: recipes,
        release_cfg: ReleaseConfig::default(),
        build: Box::new(FakeBuild),
        release: Box::new(FakeRelease),
        once: true,
        poll_secs: 0,
    };
    let settled = run_drain(&drain).expect("the drain runs");
    assert_eq!(settled.len(), 1);
    assert!(!settled[0].released, "{:?}", settled[0]);
    let error = settled[0].error.clone().unwrap_or_default();
    assert!(
        error.contains("unknown version"),
        "the recipe's own refusal is recorded: {error}"
    );

    // The receipt carries the error; the claim moved to done/.
    let receipt: nau_peer::queue::Receipt = serde_json::from_slice(
        &std::fs::read(
            dir.path()
                .join("queue")
                .join("done")
                .join(format!("{id}.receipt.json")),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(receipt.status, "error");
    assert!(queue.claim().unwrap().is_none());
}

// ── Resolution order through the real config loaders ──

#[test]
fn system_servers_load_through_the_real_eval() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("nau.lua");
    std::fs::write(
        &config,
        r#"
servers = {
    "https://primary.example/nau",
    { url = "http://backup.example:7780" },
}
return {}
"#,
    )
    .unwrap();
    // The absolute path keeps the test cwd-independent.
    let loaded = nau::build_request::load_system_servers(&config.display().to_string()).unwrap();
    assert_eq!(
        loaded,
        vec![
            ServerFront {
                url: "https://primary.example/nau".into()
            },
            ServerFront {
                url: "http://backup.example:7780".into()
            },
        ]
    );

    // And the resolution folds the loaded list in order.
    let resolved = resolve_server_fronts(None, &loaded, "opencode-bin").expect("the list resolves");
    assert_eq!(
        resolved.as_ref(),
        &[
            "https://primary.example/nau".to_string(),
            "http://backup.example:7780".to_string()
        ]
    );
}

#[test]
fn drain_failures_are_recorded_and_the_loop_survives() {
    let dir = tempfile::tempdir().unwrap();
    // A recipe that resolves 1.2.3 (the collection layout fixture).
    let recipes = dir.path().join("pkgs");
    let recipe = recipes.join("t").join("testpkg.lua");
    std::fs::create_dir_all(recipe.parent().unwrap()).unwrap();
    std::fs::write(
        &recipe,
        r#"
return {
    testpkg = snap {
        name = "testpkg",
        version = "1.2.3",
        summary = "drain integration fixture",
    },
}
"#,
    )
    .unwrap();
    let queue = BuildQueue::new(dir.path().join("queue"));
    // Requested version ≠ what the recipe resolves: the identity gate
    // must fail the request — a constraint-ignoring recipe must never
    // release its floating default.
    queue
        .enqueue(&BuildRequest {
            package: "testpkg".into(),
            version: "9.9.9".into(),
            requested_by: "device-7".into(),
        })
        .unwrap();
    // A package with no recipe at all: an independent second failure.
    queue
        .enqueue(&BuildRequest {
            package: "ghost".into(),
            version: "1.0.0".into(),
            requested_by: "device-7".into(),
        })
        .unwrap();

    let drain = || Drain {
        queue: queue.clone(),
        recipes_root: recipes.clone(),
        release_cfg: ReleaseConfig::default(),
        build: Box::new(FakeBuild),
        release: Box::new(FakeRelease),
        once: true,
        poll_secs: 0,
    };
    for _ in 0..2 {
        let settled = run_drain(&drain()).unwrap();
        assert_eq!(settled.len(), 1);
        assert!(!settled[0].released, "{:?}", settled[0]);
    }

    // Both receipts are error receipts naming their causes.
    let done = dir.path().join("queue").join("done");
    let mut errors = Vec::new();
    for entry in std::fs::read_dir(&done).unwrap().filter_map(|e| e.ok()) {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".receipt.json") {
            let receipt: nau_peer::queue::Receipt =
                serde_json::from_slice(&std::fs::read(entry.path()).unwrap()).unwrap();
            assert_eq!(receipt.status, "error");
            errors.push(receipt.error.unwrap_or_default());
        }
    }
    assert_eq!(errors.len(), 2, "both failures recorded: {errors:?}");
    assert!(
        errors
            .iter()
            .any(|e| e.contains("resolved version '1.2.3'")),
        "the identity mismatch is named: {errors:?}"
    );
    assert!(
        errors.iter().any(|e| e.contains("not found under")),
        "the missing recipe is named: {errors:?}"
    );
    assert!(queue.claim().unwrap().is_none());
}
