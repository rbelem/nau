//! `shuttle pod` overlay integration tests (issue #6: inline code-only
//! overlays).
//!
//! Drives the real binary end to end through the FULL chain: an overlay
//! entry in a pod's own `pod.lua` patches the resolved package (version
//! pin, build tweak), the patched payload is built with the normal snap
//! build path, installed into the pod's runtime store, and exposed
//! through the generation bin farm — for THAT pod only. All state
//! (project dir, pod root) lives in tempdirs — never the real home.
//!
//! Precedence under test (CONTEXT.md: Overlay, later wins):
//! 1. shared collection — the unmodified resolved package,
//! 2. own packages — the pod's declaration + lockfile pin hold against
//!    collection drift,
//! 3. overlay — beats both.
//!
//! Tests gate on the external toolchain (mksquashfs/unsquashfs/curl/tar),
//! same skip pattern as `pod_install.rs`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;

// ── Gating ──

fn has_tool(tool: &str) -> bool {
    Command::new("which")
        .arg(tool)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some()
}

fn chain_available() -> bool {
    ["mksquashfs", "unsquashfs", "curl", "tar"]
        .iter()
        .all(|t| has_tool(t))
}

fn require_chain() {
    if !chain_available() {
        eprintln!("skipping: mksquashfs/unsquashfs/curl/tar unavailable");
    }
}

macro_rules! gated_test {
    ($fn_name:ident, $($body:tt)*) => {
        #[test]
        fn $fn_name() {
            require_chain();
            if !chain_available() {
                return;
            }
            $($body)*
        }
    };
}

// ── Loopback source server ──

/// Serve the files of `dir` over 127.0.0.1 HTTP (one request per
/// connection). The thread lives as long as the test process.
fn serve_dir(dir: &Path) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let root = dir.to_path_buf();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            if serve_one(&mut stream, &root).is_err() {
                continue;
            }
        }
    });
    port
}

fn serve_one(stream: &mut TcpStream, root: &Path) -> std::io::Result<()> {
    let mut buf = [0u8; 4096];
    let mut data = Vec::new();
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
        if data.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let req = String::from_utf8_lossy(&data);
    let path = req.split_whitespace().nth(1).unwrap_or("/");
    let file = root.join(path.trim_start_matches('/'));
    let (status, body) = match std::fs::read(&file) {
        Ok(b) => ("200 OK", b),
        Err(_) => ("404 Not Found", b"not found".to_vec()),
    };
    let head = format!(
        "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()
}

// ── Fixtures ──

fn make_tarball(server_dir: &Path, name: &str) {
    let pkg = server_dir.join(name);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(pkg.join("README"), "fixture source\n").unwrap();
    let status = Command::new("tar")
        .args([
            "czf",
            server_dir.join(format!("{name}.tar.gz")).to_str().unwrap(),
            name,
        ])
        .current_dir(server_dir)
        .status()
        .unwrap();
    assert!(status.success(), "tar failed");
}

/// A package that builds an echo-marker binary; the version feeds
/// meta/snap.yaml so a version move changes content identity.
fn write_pkg_version(project: &Path, name: &str, version: &str, marker: &str, port: u16) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let lua = format!(
        r#"return {{ default = snap {{
    name = "{name}",
    version = "{version}",
    source = "http://127.0.0.1:{port}/{name}.tar.gz",
    build = "mkdir -p $STAGE/bin && echo '#!/bin/sh' > $STAGE/bin/{name} && echo 'echo {marker}' >> $STAGE/bin/{name} && chmod +x $STAGE/bin/{name}",
    apps = {{ {name} = {{ command = "bin/{name}" }} }},
}} }}
"#
    );
    std::fs::write(dir.join(format!("{name}.lua")), lua).unwrap();
}

// ── Runners ──

fn run(project: &Path, root: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.arg("pod").args(args).arg("--root").arg(root);
    cmd.current_dir(project);
    // The desktop launcher surface (issue #7) writes to the user data
    // home — redirect it inside the test's tempdir, never the real home.
    cmd.env("SHUTTLE_DATA_HOME", root.join("data-home"));
    let out = cmd.output().expect("failed to spawn shuttle pod");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn pod_dir(root: &Path, pod: &str) -> PathBuf {
    root.join(pod)
}

fn current_generation(root: &Path, pod: &str) -> u64 {
    let target = std::fs::read_link(pod_dir(root, pod).join("current")).unwrap();
    target
        .components()
        .rev()
        .nth(1)
        .unwrap()
        .as_os_str()
        .to_str()
        .unwrap()
        .parse()
        .unwrap()
}

fn generation_count(root: &Path, pod: &str) -> usize {
    let gens = pod_dir(root, pod).join("generations");
    std::fs::read_dir(&gens)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().parse::<u64>().is_ok())
                .count()
        })
        .unwrap_or(0)
}

fn current_farm(root: &Path, pod: &str) -> PathBuf {
    let link = pod_dir(root, pod).join("current");
    let target = std::fs::read_link(&link).unwrap();
    if target.is_absolute() {
        target
    } else {
        pod_dir(root, pod).join(target)
    }
}

/// Run the farm entry `name` and return its stdout (the fixture binaries
/// echo their marker).
fn farm_output(farm: &Path, name: &str) -> String {
    let out = Command::new(farm.join(name))
        .output()
        .expect("run farm binary");
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn lock_pin(root: &Path, pod: &str, name: &str) -> Option<String> {
    let lock: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(pod_dir(root, pod).join("shuttle.lock")).unwrap(),
    )
    .unwrap();
    lock["packages"][name]["version"]
        .as_str()
        .map(str::to_string)
}

/// The recorded version of one package in a generation manifest.
fn manifest_version(root: &Path, pod: &str, gen: u64, pkg: &str) -> String {
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            pod_dir(root, pod)
                .join("generations")
                .join(gen.to_string())
                .join("manifest.json"),
        )
        .unwrap(),
    )
    .unwrap();
    manifest["packages"][pkg]["version"]
        .as_str()
        .expect("manifest must record the package version")
        .to_string()
}

fn snapshot(path: &Path) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

// ── Acceptance: per-pod overlay, three precedence steps ──

gated_test!(
    overlay_applies_per_pod_across_all_three_precedence_layers,
    {
        let project = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let server = tempfile::tempdir().unwrap();
        let port = serve_dir(server.path());
        make_tarball(server.path(), "tool");
        write_pkg_version(project.path(), "tool", "14.1", "tool-14.1-ran", port);

        // Layer 2 setup: the pod declares `tool@14` and pins 14.1.
        let (code, _, stderr) = run(project.path(), root.path(), &["add", "tool@14"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        assert_eq!(current_generation(root.path(), "default"), 1);
        assert_eq!(
            lock_pin(root.path(), "default", "tool").as_deref(),
            Some("14.1")
        );
        assert_eq!(
            farm_output(&current_farm(root.path(), "default"), "tool"),
            "tool-14.1-ran"
        );

        // The shared collection moves: 14.4 with a different marker.
        write_pkg_version(project.path(), "tool", "14.4", "tool-14.4-ran", port);

        // Precedence step 2 — own packages beat the shared collection: the
        // reconcile HOLDS the pod at its pin instead of rebuilding at 14.4.
        let (code, _, stderr) = run(project.path(), root.path(), &["sync"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        assert!(
            stderr.contains("no new generation"),
            "a held package must not rebuild: {stderr}"
        );
        assert_eq!(
            generation_count(root.path(), "default"),
            1,
            "a held package must not bump the generation"
        );
        assert_eq!(
            lock_pin(root.path(), "default", "tool").as_deref(),
            Some("14.1"),
            "the pod stays pinned at its own version despite collection drift"
        );
        assert_eq!(
            farm_output(&current_farm(root.path(), "default"), "tool"),
            "tool-14.1-ran",
            "the pod stays at its own pinned content"
        );

        // Precedence step 3 — overlay beats both: the pod's own overlay pins
        // version 9.9 AND tweaks the build (new marker). Hand-edit pod.lua.
        let decl_path = pod_dir(root.path(), "default").join("pod.lua");
        let decl = std::fs::read_to_string(&decl_path).unwrap();
        let overlay_build = "mkdir -p $STAGE/bin && echo '#!/bin/sh' > $STAGE/bin/tool && echo 'echo tool-overlay-ran' >> $STAGE/bin/tool && chmod +x $STAGE/bin/tool";
        let edited = decl.replace(
            r#"packages = { "tool@14" },"#,
            &format!(
                r#"packages = {{ "tool@14" }},
    overlay = {{
        tool = {{ version = "9.9", build = "{overlay_build}" }},
    }},"#
            ),
        );
        assert_ne!(edited, decl, "fixture must match the rendered declaration");
        std::fs::write(&decl_path, &edited).unwrap();

        let (code, _, stderr) = run(project.path(), root.path(), &["sync"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        assert_eq!(
            generation_count(root.path(), "default"),
            2,
            "the overlaid rebuild must bump the generation"
        );
        assert_eq!(current_generation(root.path(), "default"), 2);
        // The overlay version pin flows into the lockfile...
        assert_eq!(
            lock_pin(root.path(), "default", "tool").as_deref(),
            Some("9.9"),
            "the overlay version pin must flow into the lockfile"
        );
        // ...into the generation manifest...
        assert_eq!(
            manifest_version(root.path(), "default", 2, "tool"),
            "9.9",
            "the generation manifest must record the overlaid version"
        );
        // ...and the tweaked build into the farm binary.
        assert_eq!(
            farm_output(&current_farm(root.path(), "default"), "tool"),
            "tool-overlay-ran",
            "the farm binary must reflect the overlaid build"
        );

        // Re-sync is a no-op: the overlaid content is already installed at
        // the same identity.
        let (code, _, stderr) = run(project.path(), root.path(), &["sync"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        assert!(
            stderr.contains("no new generation"),
            "re-sync with a settled overlay must be a no-op: {stderr}"
        );
        assert_eq!(generation_count(root.path(), "default"), 2);

        // Precedence step 1 — the shared collection resolves unmodified in
        // every other pod: a sibling pod with no overlay builds the
        // collection's current 14.4.
        let (code, _, stderr) = run(
            project.path(),
            root.path(),
            &["--name", "sibling", "add", "tool"],
        );
        assert_eq!(code, Some(0), "stderr: {stderr}");
        assert_eq!(
            lock_pin(root.path(), "sibling", "tool").as_deref(),
            Some("14.4"),
            "the sibling pod must pin the unmodified collection version"
        );
        assert_eq!(
            manifest_version(root.path(), "sibling", 1, "tool"),
            "14.4",
            "the sibling generation must carry the unmodified package"
        );
        assert_eq!(
            farm_output(&current_farm(root.path(), "sibling"), "tool"),
            "tool-14.4-ran",
            "the sibling farm must expose the unmodified binary"
        );
        // ...and the overlay left the sibling's generations untouched.
        assert_eq!(generation_count(root.path(), "sibling"), 1);
        assert_eq!(
            generation_count(root.path(), "default"),
            2,
            "default unchanged by sibling add"
        );
    }
);

gated_test!(overlay_applies_at_add_time_and_pins_effective_version, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "tool");
    write_pkg_version(project.path(), "tool", "14.1", "tool-14.1-ran", port);

    // Hand-write a pod.lua with ONLY an overlay (no packages yet): the
    // overlay pre-declares the customization, then `add` joins the
    // package and pins the effective (overlaid) version.
    std::fs::create_dir_all(pod_dir(root.path(), "overlaid")).unwrap();
    std::fs::write(
        pod_dir(root.path(), "overlaid").join("pod.lua"),
        r#"pod {
    overlay = {
        tool = { version = "9.9" },
    },
}
"#,
    )
    .unwrap();

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["--name", "overlaid", "add", "tool"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(
        lock_pin(root.path(), "overlaid", "tool").as_deref(),
        Some("9.9"),
        "add must pin the overlay-effective version"
    );
    assert_eq!(
        manifest_version(root.path(), "overlaid", 1, "tool"),
        "9.9",
        "the built package must carry the overlaid version"
    );
    // The declaration round-trips with the overlay intact.
    let decl = std::fs::read_to_string(pod_dir(root.path(), "overlaid").join("pod.lua")).unwrap();
    assert!(
        decl.contains(r#"version = "9.9""#),
        "the overlay must survive the add's re-render, got:\n{decl}"
    );
});

gated_test!(overlay_nonexistent_package_fails_before_any_mutation, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "tool");
    write_pkg_version(project.path(), "tool", "14.1", "tool-14.1-ran", port);

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "tool"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(generation_count(root.path(), "default"), 1);

    let lock_before = snapshot(&pod_dir(root.path(), "default").join("shuttle.lock"));
    let link_before = std::fs::read_link(pod_dir(root.path(), "default").join("current")).unwrap();

    // Hand-edit pod.lua: overlay a package the pod does not declare
    // (and that does not exist anywhere).
    let decl_path = pod_dir(root.path(), "default").join("pod.lua");
    let decl = std::fs::read_to_string(&decl_path).unwrap();
    let edited = decl.replace(
        r#"packages = { "tool" },"#,
        r#"packages = { "tool" },
    overlay = {
        ghost = { version = "1.0" },
    },"#,
    );
    assert_ne!(edited, decl, "fixture must match the rendered declaration");
    std::fs::write(&decl_path, &edited).unwrap();

    let (code, _, stderr) = run(project.path(), root.path(), &["sync"]);
    assert_eq!(code, Some(1), "must fail: {stderr}");
    assert!(
        stderr.contains("ghost") && stderr.contains("does not declare"),
        "error must name the nonexistent overlay target: {stderr}"
    );
    // Zero writes: the declaration is NOT re-rendered (still exactly the
    // hand-edited bytes), the lockfile and current link are untouched.
    assert_eq!(
        snapshot(&pod_dir(root.path(), "default").join("pod.lua")),
        Some(edited.into_bytes()),
        "declaration must not be re-rendered"
    );
    assert_eq!(
        snapshot(&pod_dir(root.path(), "default").join("shuttle.lock")),
        lock_before,
        "lockfile must be untouched"
    );
    assert_eq!(
        std::fs::read_link(pod_dir(root.path(), "default").join("current")).unwrap(),
        link_before,
        "current link must be untouched"
    );
    assert_eq!(
        generation_count(root.path(), "default"),
        1,
        "a failed overlay validation must not create generations"
    );
});

gated_test!(overlay_unsupported_field_fails_before_any_mutation, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "tool");
    write_pkg_version(project.path(), "tool", "14.1", "tool-14.1-ran", port);

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "tool"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");

    let lock_before = snapshot(&pod_dir(root.path(), "default").join("shuttle.lock"));

    let decl_path = pod_dir(root.path(), "default").join("pod.lua");
    let decl = std::fs::read_to_string(&decl_path).unwrap();
    let edited = decl.replace(
        r#"packages = { "tool" },"#,
        r#"packages = { "tool" },
    overlay = {
        tool = { version = 9 },
    },"#,
    );
    std::fs::write(&decl_path, &edited).unwrap();

    let (code, _, stderr) = run(project.path(), root.path(), &["sync"]);
    assert_eq!(code, Some(1), "must fail: {stderr}");
    assert!(
        stderr.contains("'overlay.tool.version'") && stderr.contains("string"),
        "error must name the offending overlay field: {stderr}"
    );
    assert_eq!(
        snapshot(&pod_dir(root.path(), "default").join("pod.lua")),
        Some(edited.into_bytes()),
        "declaration must not be re-rendered"
    );
    assert_eq!(
        snapshot(&pod_dir(root.path(), "default").join("shuttle.lock")),
        lock_before,
        "lockfile must be untouched"
    );
});
