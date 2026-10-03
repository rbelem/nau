//! Version-line coexistence by constraint (ADR-0047, ticket #278).
//!
//! ONE package, TWO version lines: a pod pins its line with the
//! constraint (`nodelike@22`), the recipe selects the line from the
//! eval-context `constraint` global, and the two lines coexist ACROSS
//! pods — never within one. Drives the real binary end to end (pod add
//! → eval → build → store → generation) with all state in tempdirs, the
//! same gating + loopback-source-server patterns as `tests/pod_wrapper.rs`.
//!
//! Covered here:
//! - the default line installs when no constraint is declared, with the
//!   ADR-0047 wrapper invariant's staged layout (npm/npx as REAL files
//!   + `.real` siblings, wrapped around the bare `node` name);
//! - `@22` installs the 22 line: same tree shape (unsuffixed — the
//!   suffixed `node22` design is dead), 22 content, and the lockfile
//!   records `{version, constraint}`;
//! - the two lines' staged manifests share one path set (no renamed
//!   staging, each staged path appears once per payload);
//! - a recipe that DROPS a declared line makes sync REFUSE (named
//!   error, pin kept, installed content kept) — never a silent re-pin;
//! - a `requires` edge constraint (`nodelike@22`) closure-pulls the
//!   declared line for consumers (the codegraph migration shape);
//! - two edges pulling one name onto different lines refuse named.

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

/// Pack the nodelike source tarball for one line: `bin/node` (the
/// runtime stand-in), `lib/node_modules/npm/bin/npm-cli.js` +
/// `lib/node_modules/npx-cli.js` (the cli scripts), and `bin/npm` /
/// `bin/npx` as RELATIVE SYMLINKS into those scripts — the exact shape
/// the official node tarball ships and the real-copy recipe fix (rm +
/// cp -L) exists for. Both cli scripts REQUIRE a sibling module first
/// (npm-cli.js its package's lib/cli.js — the real npm-cli.js shape),
/// so a copy out of `lib/node_modules` loses the require anchor and
/// dies with MODULE_NOT_FOUND at runtime. `<marker>` differs per line
/// so the staged payload proves WHICH line's source landed.
fn make_nodelike_tarball(server_dir: &Path, marker: &str) {
    let pkg = server_dir.join("nodelike");
    let _ = std::fs::remove_dir_all(&pkg);
    std::fs::create_dir_all(pkg.join("bin")).unwrap();
    std::fs::create_dir_all(pkg.join("lib/node_modules/npm/bin")).unwrap();
    std::fs::create_dir_all(pkg.join("lib/node_modules/npm/lib")).unwrap();
    std::fs::write(
        pkg.join("bin/node"),
        format!("#!/bin/sh\necho node-{marker}\n"),
    )
    .unwrap();
    std::fs::write(
        pkg.join("lib/node_modules/npm/lib/cli.js"),
        format!("#!/usr/bin/env node\nconsole.log('npm-resolve-{marker}')\n"),
    )
    .unwrap();
    std::fs::write(
        pkg.join("lib/node_modules/npm/bin/npm-cli.js"),
        format!("#!/usr/bin/env node\nrequire('../lib/cli.js')\nconsole.log('npm-cli-{marker}')\n"),
    )
    .unwrap();
    std::fs::write(
        pkg.join("lib/node_modules/npx-cli.js"),
        format!(
            "#!/usr/bin/env node\nrequire('./npm/lib/cli.js')\nconsole.log('npx-cli-{marker}')\n"
        ),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        "../lib/node_modules/npm/bin/npm-cli.js",
        pkg.join("bin/npm"),
    )
    .unwrap();
    std::os::unix::fs::symlink("../lib/node_modules/npx-cli.js", pkg.join("bin/npx")).unwrap();
    for path in [
        pkg.join("bin/node"),
        pkg.join("lib/node_modules/npm/lib/cli.js"),
        pkg.join("lib/node_modules/npm/bin/npm-cli.js"),
        pkg.join("lib/node_modules/npx-cli.js"),
    ] {
        let mut perm = std::fs::metadata(&path).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perm.set_mode(0o755);
        std::fs::set_permissions(&path, perm).unwrap();
    }
    let status = Command::new("tar")
        .args([
            "czf",
            server_dir
                .join(format!("nodelike-{marker}.tar.gz"))
                .to_str()
                .unwrap(),
            "nodelike",
        ])
        .current_dir(server_dir)
        .status()
        .unwrap();
    assert!(status.success(), "tar failed");
}

/// The constraint-selected nodelike recipe, in the shape of
/// pkgs/n/node.lua: a `lines` table, selection by the `constraint`
/// global (default "26"), refusal of an undeclared line, and the
/// package-anchored bootstrap build (rm precedes the bootstraps) with
/// interpreter apps. The bootstrap paths mirror the fixture layout
/// (npx-cli.js sits at lib/node_modules/, not inside npm/).
/// `declared` controls WHICH lines exist — the drop test removes "22".
fn write_nodelike_recipe(project: &Path, port: u16, declared: &[&str]) {
    let mut lines = String::new();
    for line in declared {
        lines.push_str(&format!(
            "    [\"{line}\"] = {{ version = \"{line}.0.0\", url = \"http://127.0.0.1:{port}/nodelike-{line}.tar.gz\", sha256 = \"fixture-unverified\" }},\n"
        ));
    }
    let lua = format!(
        r#"local lines = {{
{lines}}}
local line = constraint or "26"
local picked = lines[line]
if picked == nil then
    error("nodelike: constraint '@" .. tostring(line) .. "' selects no declared line")
end
return {{ default = snap {{
    name = "nodelike",
    version = picked.version,
    lines = lines,
    source = picked.url,
    build = "mkdir -p $STAGE/usr && cp -r bin lib $STAGE/usr/ && rm $STAGE/usr/bin/npm $STAGE/usr/bin/npx && printf '%s\\n' '#!/usr/bin/env node' \"require('../lib/node_modules/npm/bin/npm-cli.js')\" > $STAGE/usr/bin/npm && printf '%s\\n' '#!/usr/bin/env node' \"require('../lib/node_modules/npx-cli.js')\" > $STAGE/usr/bin/npx",
    type = "source",
    apps = {{
        node = app {{ command = "usr/bin/node" }},
        npm = app {{ command = "usr/bin/npm", interpreter = "node" }},
        npx = app {{ command = "usr/bin/npx", interpreter = "node" }},
    }},
}} }}
"#
    );
    let dir = project.join("pkgs/n");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("nodelike.lua"), lua).unwrap();
}

/// A consumer package whose `requires` edge pins the nodelike line —
/// the migrated codegraph shape (ADR-0047: the constraint, not a
/// renamed sibling). `consumer.tar.gz` (dir `consumer` with a `cons`
/// script) must already exist in the server dir.
fn write_consumer(project: &Path, port: u16, name: &str, edge: &str) {
    let dir = project.join("pkgs/c");
    std::fs::create_dir_all(&dir).unwrap();
    let lua = format!(
        r#"return {{ default = snap {{
    name = "{name}",
    version = "1.0",
    source = "http://127.0.0.1:{port}/consumer.tar.gz",
    build = "mkdir -p $STAGE/bin && cp $SRC/consumer/cons $STAGE/bin/{name} && chmod +x $STAGE/bin/{name}",
    requires = {{ "{edge}" }},
}} }}
"#
    );
    std::fs::write(dir.join(format!("{name}.lua")), lua).unwrap();
}

/// Pack the shared consumer source tarball into the server dir.
fn make_consumer_tarball(server_dir: &Path) {
    let src = server_dir.join("consumer");
    let _ = std::fs::remove_dir_all(&src);
    std::fs::create_dir_all(src.join("consumer")).unwrap();
    std::fs::write(src.join("consumer/cons"), "#!/bin/sh\necho ran\n").unwrap();
    let status = Command::new("tar")
        .args([
            "czf",
            server_dir.join("consumer.tar.gz").to_str().unwrap(),
            "consumer",
        ])
        .current_dir(server_dir)
        .status()
        .unwrap();
    assert!(status.success(), "tar failed");
}

// ── Runners / helpers ──

fn run(project: &Path, root: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nau"));
    cmd.arg("pod").args(args).arg("--root").arg(root);
    cmd.current_dir(project);
    cmd.env("NAU_DATA_HOME", root.join("data-home"));
    // Keep pod activation off the host systemd bus (issue #66).
    cmd.env("NAU_SYSTEMD", "off");
    let out = cmd.output().expect("failed to spawn nau pod");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn pod_dir(root: &Path, pod: &str) -> PathBuf {
    root.join(pod)
}

fn load_lock(root: &Path, pod: &str) -> nau::lock::LockFile {
    nau::lock::LockFile::load(&pod_dir(root, pod).join("nau.lock"))
        .expect("pod lockfile must parse")
        .expect("pod lockfile must exist")
}

/// The extracted payload tree of `pkg` in the pod's CURRENT generation.
/// `current` points at the generation's FARM dir; the extension tree
/// lives beside it at `extensions/<pkg>/usr/<payload-rel-path>`
/// (build_prefix.rs) — so the returned path is the payload root and
/// staged `usr/bin/node` resolves at `<payload>/usr/bin/node`.
fn extension_dir(root: &Path, pod: &str, pkg: &str) -> PathBuf {
    let gen_link =
        std::fs::read_link(pod_dir(root, pod).join("current")).expect("current generation link");
    let farm = if gen_link.is_absolute() {
        gen_link
    } else {
        pod_dir(root, pod).join(gen_link)
    };
    farm.parent()
        .expect("farm sits in the generation dir")
        .join("extensions")
        .join(pkg)
        .join("usr")
}

/// Sorted, pod-relative file list of the package's staged tree.
fn staged_paths(ext: &Path) -> Vec<String> {
    let mut out = Vec::new();
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            let rel = path
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .to_string();
            if path.is_dir() {
                walk(&path, base, out);
            } else {
                out.push(rel);
            }
        }
    }
    walk(ext, ext, &mut out);
    out.sort();
    out
}

/// The wrapper invariant's staged layout (ADR-0047 Decision 7): node is
/// the plain runtime file; npm/npx are REAL bootstrap files (the
/// symlinks were replaced), each preserved at a `.real` sibling that
/// requires the package's own staged entry — the require must name the
/// in-tree path, because that anchor is what keeps npm's module
/// resolution inside its staged package. The line marker lives in the
/// staged entry the bootstrap requires, so WHICH line's payload landed
/// is still proven from the tree. The wrapper execs the bare `node`
/// name.
fn assert_line_layout(ext: &Path, marker: &str) {
    let bin = ext.join("usr/bin");
    assert!(
        bin.join("node").is_file(),
        "node runtime must be staged (ext {:?})",
        ext
    );
    for (tool, require_rel, entry_rel) in [
        (
            "npm",
            "lib/node_modules/npm/bin/npm-cli.js",
            "usr/lib/node_modules/npm/bin/npm-cli.js",
        ),
        (
            "npx",
            "lib/node_modules/npx-cli.js",
            "usr/lib/node_modules/npx-cli.js",
        ),
    ] {
        let wrapper = bin.join(tool);
        let real = bin.join(format!("{tool}.real"));
        let meta = std::fs::symlink_metadata(&wrapper).expect("wrapper must exist");
        assert!(
            meta.is_file(),
            "{tool} must be a REAL file, not a symlink (ADR-0047 D7 real-copy fix)"
        );
        assert!(
            real.is_file(),
            "{tool}.real sibling (the bootstrap) must be staged"
        );
        let real_content = std::fs::read_to_string(&real).unwrap();
        assert!(
            real_content.contains(&format!("require('../{require_rel}')")),
            "{tool}.real must bootstrap the staged entry {require_rel}, got: {real_content}"
        );
        let entry = std::fs::read_to_string(ext.join(entry_rel)).unwrap();
        let tag = if tool == "npm" {
            format!("npm-cli-{marker}")
        } else {
            format!("npx-cli-{marker}")
        };
        assert!(
            entry.contains(&tag),
            "the staged entry {entry_rel} must carry the {marker} line's script, got: {entry}"
        );
        let wrapper_content = std::fs::read_to_string(&wrapper).unwrap();
        assert!(
            wrapper_content.contains("node"),
            "{tool} wrapper must exec the bare interpreter name: {wrapper_content}"
        );
    }
}

// ── Tests ──

gated_test!(default_line_installs_with_real_copy_wrappers, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_nodelike_tarball(server.path(), "26");
    make_nodelike_tarball(server.path(), "22");
    write_nodelike_recipe(project.path(), port, &["26", "22"]);

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "nodelike"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");

    let lock = load_lock(root.path(), "default");
    let entry = lock.packages.get("nodelike").expect("pin recorded");
    assert_eq!(
        entry.version, "26.0.0",
        "no constraint → the default 26 line"
    );
    assert_eq!(entry.constraint, None, "no constraint recorded");

    let ext = extension_dir(root.path(), "default", "nodelike");
    assert_line_layout(&ext, "26");
});

gated_test!(wrapped_npm_npx_entries_resolve_from_the_generation_tree, {
    // The #9 wrapper execs the bare interpreter on the `.real` entry in
    // the generation tree, so the entry's own relative requires must
    // resolve THERE — npm-cli.js requires its package's lib/cli.js, and
    // npm/npx only work when the staged entry keeps that anchor.
    if !has_tool("node") {
        eprintln!("skipping: host node unavailable");
        return;
    }
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_nodelike_tarball(server.path(), "26");
    write_nodelike_recipe(project.path(), port, &["26"]);

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "nodelike"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");

    // The wrapper resolves its interpreter from PATH (the bare `node`
    // name), so the run needs a real node on PATH — the fixture's own
    // node stub would only echo. The command is invoked the way pod
    // PATH resolves it: the generation's farm shim, whose store blob
    // derives PODROOT and lands on the extension tree's npm.real.
    let path = std::env::var("PATH").unwrap_or_default();
    let shim_dir = pod_dir(root.path(), "default").join("current");
    for (tool, markers) in [
        ("npm", vec!["npm-cli-26", "npm-resolve-26"]),
        ("npx", vec!["npx-cli-26", "npm-resolve-26"]),
    ] {
        let out = Command::new(shim_dir.join(tool))
            .env("PATH", &path)
            .output()
            .unwrap_or_else(|e| panic!("run wrapped {tool}: {e}"));
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(
            out.status.code(),
            Some(0),
            "wrapped {tool} must run from the generation tree; stderr: {err}"
        );
        for m in markers {
            assert!(stdout.contains(m), "{tool} output must carry {m}: {stdout}");
        }
    }
});

gated_test!(constraint_selects_the_22_line_across_pods, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_nodelike_tarball(server.path(), "26");
    make_nodelike_tarball(server.path(), "22");
    write_nodelike_recipe(project.path(), port, &["26", "22"]);

    // Pod `line26` keeps the default; pod `line22` pins the constraint.
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["--name", "line26", "add", "nodelike"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["--name", "line22", "add", "nodelike@22"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");

    let lock = load_lock(root.path(), "line22");
    let entry = lock.packages.get("nodelike").expect("pin recorded");
    assert_eq!(
        entry.version, "22.0.0",
        "the constraint selected the 22 line"
    );
    assert_eq!(entry.constraint.as_deref(), Some("22"));

    // The 26 pod is untouched at 26; the two lines coexist ACROSS pods.
    let lock26 = load_lock(root.path(), "line26");
    assert_eq!(lock26.packages["nodelike"].version, "26.0.0");

    assert_line_layout(&extension_dir(root.path(), "line22", "nodelike"), "22");
    assert_line_layout(&extension_dir(root.path(), "line26", "nodelike"), "26");
});

gated_test!(two_lines_stage_one_tree_shape_no_suffixed_escape, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_nodelike_tarball(server.path(), "26");
    make_nodelike_tarball(server.path(), "22");
    write_nodelike_recipe(project.path(), port, &["26", "22"]);

    for (pod, spec) in [("line26", "nodelike"), ("line22", "nodelike@22")] {
        let (code, _, stderr) = run(project.path(), root.path(), &["--name", pod, "add", spec]);
        assert_eq!(code, Some(0), "{pod}: stderr: {stderr}");
    }

    let paths26 = staged_paths(&extension_dir(root.path(), "line26", "nodelike"));
    let paths22 = staged_paths(&extension_dir(root.path(), "line22", "nodelike"));
    // ONE tree shape: the 22 line stages the SAME unsuffixed paths as
    // the 26 line — no node22-style renames, nothing relocated.
    assert_eq!(paths26, paths22, "both lines must stage one tree shape");
    assert!(
        paths26
            .iter()
            .all(|p| !p.contains("22") && !p.contains("26")),
        "no line-marked or suffixed staging: {paths26:?}"
    );
    // Each staged path appears exactly once per payload (a pod's
    // manifest never carries the same path twice — one line per pod).
    let mut sorted = paths26.clone();
    sorted.dedup();
    assert_eq!(sorted, paths26, "no duplicate staged paths in a payload");
    // And the two lines never share a pod: each pod's lock carries its
    // own single-version pin for the one name.
    assert_eq!(
        load_lock(root.path(), "line26").packages["nodelike"].version,
        "26.0.0"
    );
    assert_eq!(
        load_lock(root.path(), "line22").packages["nodelike"].version,
        "22.0.0"
    );
});

gated_test!(sync_refuses_when_a_declared_line_disappears, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_nodelike_tarball(server.path(), "26");
    make_nodelike_tarball(server.path(), "22");
    write_nodelike_recipe(project.path(), port, &["26", "22"]);

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["--name", "pinned", "add", "nodelike@22"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");

    // The recipe DROPS the 22 line upstream (only 26 remains).
    write_nodelike_recipe(project.path(), port, &["26"]);

    // Sync must REFUSE, naming the vanished line — not silently re-pin
    // the default line over the declared constraint.
    let (code, _, stderr) = run(project.path(), root.path(), &["--name", "pinned", "sync"]);
    assert_ne!(
        code,
        Some(0),
        "sync must refuse when the declared line is gone"
    );
    assert!(
        stderr.contains("selects no declared line") || stderr.contains("no declared line"),
        "refusal must name the missing line: {stderr}"
    );

    // The pin and the installed content are KEPT: a refusal, not a
    // re-pin — the operator decides (widen, or restore the line).
    let lock = load_lock(root.path(), "pinned");
    let entry = lock.packages.get("nodelike").expect("pin kept");
    assert_eq!(
        entry.version, "22.0.0",
        "the 22 pin must survive the refusal"
    );
    assert_eq!(entry.constraint.as_deref(), Some("22"));
    let ext = extension_dir(root.path(), "pinned", "nodelike");
    let entry =
        std::fs::read_to_string(ext.join("usr/lib/node_modules/npm/bin/npm-cli.js")).unwrap();
    assert!(
        entry.contains("npm-cli-22"),
        "the installed 22-line content must survive the refusal: {entry}"
    );
});

gated_test!(recipe_dropping_the_line_refuses_at_add_too, {
    // The same refusal fires on the ADD path: a fresh `pod add
    // nodelike@22` against a recipe that no longer declares 22 must
    // fail before ANY state is written (zero-write guarantee).
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_nodelike_tarball(server.path(), "26");
    make_nodelike_tarball(server.path(), "22");
    write_nodelike_recipe(project.path(), port, &["26"]);

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["--name", "fresh", "add", "nodelike@22"],
    );
    assert_ne!(code, Some(0), "adding a vanished line must refuse");
    assert!(
        stderr.contains("selects no declared line") || stderr.contains("no declared line"),
        "refusal must name the missing line: {stderr}"
    );
    assert!(
        !pod_dir(root.path(), "fresh").join("nau.lock").exists(),
        "the refusal must be zero-write: no lockfile recorded"
    );
});

gated_test!(requires_edge_constraint_closure_pulls_the_line, {
    // The migrated codegraph shape: a consumer's `requires` edge pins
    // `nodelike@22`; declaring the consumer closure-pulls the 22 line
    // (same unsuffixed payload a `nodelike@22` pod spec would pin).
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_nodelike_tarball(server.path(), "26");
    make_nodelike_tarball(server.path(), "22");
    write_nodelike_recipe(project.path(), port, &["26", "22"]);
    // The consumer source rides the SAME loopback server dir.
    let src = server.path().join("consumer");
    std::fs::create_dir_all(src.join("consumer")).unwrap();
    std::fs::write(src.join("consumer/cons"), "#!/bin/sh\necho ran\n").unwrap();
    let status = Command::new("tar")
        .args([
            "czf",
            server.path().join("consumer.tar.gz").to_str().unwrap(),
            "consumer",
        ])
        .current_dir(server.path())
        .status()
        .unwrap();
    assert!(status.success(), "tar failed");
    let dir = project.path().join("pkgs/c");
    std::fs::create_dir_all(&dir).unwrap();
    let lua = format!(
        r#"return {{ default = snap {{
    name = "consumer",
    version = "1.0",
    source = "http://127.0.0.1:{port}/consumer.tar.gz",
    build = "mkdir -p $STAGE/bin && cp $SRC/consumer/cons $STAGE/bin/cons && chmod +x $STAGE/bin/cons",
    requires = {{ "nodelike@22" }},
    apps = {{ cons = app {{ command = "bin/cons", interpreter = "node" }} }},
}} }}
"#
    );
    std::fs::write(dir.join("consumer.lua"), lua).unwrap();

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["--name", "edge", "add", "consumer"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");

    // The closure member is the 22 LINE: same tree, 22 content.
    let ext = extension_dir(root.path(), "edge", "nodelike");
    let entry =
        std::fs::read_to_string(ext.join("usr/lib/node_modules/npm/bin/npm-cli.js")).unwrap();
    assert!(
        entry.contains("npm-cli-22"),
        "the requires edge must pull the 22 line: {entry}"
    );
    assert_line_layout(&ext, "22");
});

gated_test!(conflicting_requires_lines_refuse_named, {
    // Two consumers pulling one name onto two different constrained
    // lines: one pod holds one version of a name (ADR-0047 D2) — the
    // sync refuses named instead of letting edge order pick a winner.
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_nodelike_tarball(server.path(), "26");
    make_nodelike_tarball(server.path(), "22");
    write_nodelike_recipe(project.path(), port, &["26", "22"]);
    make_consumer_tarball(server.path());
    write_consumer(project.path(), port, "cons22", "nodelike@22");
    write_consumer(project.path(), port, "cons26", "nodelike@26");

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["--name", "mix", "add", "cons22"],
    );
    assert_eq!(code, Some(0), "first consumer lands: {stderr}");
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["--name", "mix", "add", "cons26"],
    );
    assert_ne!(code, Some(0), "conflicting lines must refuse");
    assert!(
        stderr.contains("conflicting version lines for 'nodelike'"),
        "refusal must name the package and the conflict: {stderr}"
    );
    // The refused consumer never INSTALLS: the sync fails before any
    // build, so the generation still carries only the first consumer at
    // its 22 line (the declaration/pin record is the documented repair
    // path — "fix the package and re-run sync").
    let lock = load_lock(root.path(), "mix");
    assert!(
        lock.packages.contains_key("cons22"),
        "the first consumer's pin survives: {lock:?}"
    );
    assert!(
        !extension_dir(root.path(), "mix", "cons26").exists(),
        "the conflicting consumer must not install"
    );
    let ext = extension_dir(root.path(), "mix", "nodelike");
    let entry =
        std::fs::read_to_string(ext.join("usr/lib/node_modules/npm/bin/npm-cli.js")).unwrap();
    assert!(
        entry.contains("npm-cli-22"),
        "the closure line stays at 22 — no silent winner: {entry}"
    );
});
