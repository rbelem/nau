//! `shuttle pod` desktop launchers (issue #7): GUI packages surface
//! user-level `.desktop` entries + icons, versioned with the pod
//! generation.
//!
//! Drives the real binary end to end through the FULL install chain (the
//! same gated toolchain pattern as `pod_install.rs`): a declared GUI
//! package in `pkgs/` is built (source over loopback HTTP, bwrap build,
//! mksquashfs), installed into the pod's runtime store, and surfaced —
//! generated entry inside the generation, pod-namespaced user-level
//! links in a REDIRECTED data home (`SHUTTLE_DATA_HOME`). Never the real
//! home or the real `~/.local/share/applications`.
//!
//! Every generated entry is validated with the strict spec-conformance
//! checker (`shuttle::desktop::validate`: required keys, valid quoted
//! Exec, registered categories, icon resolvable).

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

// ── Loopback source server (same pattern as pod_install.rs) ──

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

// ── Fixtures ──

/// A minimal valid 1x1 PNG — the fixture package's icon.
const ICON_PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
    0x89, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x8C, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44,
    0xAE, 0x42, 0x60, 0x82,
];

/// Write a GUI package: builds a real executable into `$STAGE/bin/<bin>`,
/// a `.desktop` file into `$STAGE/share/applications/<app>.desktop`, and
/// (when `with_icon`) ships a snap icon. Exposes the app with the
/// `desktop` app field.
#[allow(clippy::too_many_arguments)]
fn write_gui_pkg(
    project: &Path,
    name: &str,
    app: &str,
    bin: &str,
    display_name: &str,
    marker: &str,
    port: u16,
    tarball: &str,
    with_icon: bool,
) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let icon_line = if with_icon {
        "    icon = \"icon.png\",\n"
    } else {
        ""
    };
    let lua = format!(
        r#"return {{ default = snap {{
    name = "{name}",
    version = "1.0",
{icon_line}    source = "http://127.0.0.1:{port}/{tarball}",
    build = "mkdir -p $STAGE/bin $STAGE/share/applications && printf '#!/bin/sh\\necho {marker}\\n' > $STAGE/bin/{bin} && chmod +x $STAGE/bin/{bin} && printf '[Desktop Entry]\\nType=Application\\nName={display_name}\\nCategories=Utility;\\n' > $STAGE/share/applications/{app}.desktop",
    apps = {{ {app} = {{ command = "bin/{bin}", desktop = "share/applications/{app}.desktop" }} }},
}} }}
"#
    );
    std::fs::write(dir.join(format!("{name}.lua")), lua).unwrap();
    if with_icon {
        std::fs::write(dir.join("icon.png"), ICON_PNG).unwrap();
    }
}

// ── Runners ──

fn run(
    project: &Path,
    root: &Path,
    data_home: &Path,
    args: &[&str],
) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.arg("pod").args(args).arg("--root").arg(root);
    cmd.current_dir(project);
    // The launcher surface is redirected — never the real home or the
    // real ~/.local/share/applications.
    cmd.env("SHUTTLE_DATA_HOME", data_home);
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
    std::fs::read_dir(pod_dir(root, pod).join("generations"))
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().parse::<u64>().is_ok())
                .count()
        })
        .unwrap_or(0)
}

/// The user-level entry link for one app.
fn user_entry(data_home: &Path, pod: &str, app: &str) -> PathBuf {
    data_home
        .join("applications")
        .join(format!("shuttle-pod-{pod}-{app}.desktop"))
}

/// The user-level icon link for one app.
fn user_icon(data_home: &Path, pod: &str, app: &str, ext: &str) -> PathBuf {
    data_home
        .join("icons/hicolor/256x256/apps")
        .join(format!("shuttle-pod-{pod}-{app}.{ext}"))
}

/// The generation's launcher file for one app.
fn gen_entry(root: &Path, pod: &str, gen: u64, app: &str) -> PathBuf {
    pod_dir(root, pod).join(format!("generations/{gen}/launchers/{app}.desktop"))
}

/// The app's icon hash from the generation manifest.
fn icon_hash(root: &Path, pod: &str, gen: u64, pkg: &str, app: &str) -> String {
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            pod_dir(root, pod).join(format!("generations/{gen}/manifest.json")),
        )
        .unwrap(),
    )
    .unwrap();
    manifest["packages"][pkg]["desktops"][app]["icon"]["sha256"]
        .as_str()
        .expect("manifest records the icon hash")
        .to_string()
}

// ── Acceptance: install → valid entry, farm Exec, icon alongside ──

gated_test!(install_produces_valid_entry_with_icon_and_links, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let data_home = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "guifix");
    write_gui_pkg(
        project.path(),
        "guifix",
        "guifix",
        "guifix",
        "GUI Fix",
        "gui-ran",
        port,
        "guifix.tar.gz",
        true,
    );

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        data_home.path(),
        &["add", "guifix"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(current_generation(root.path(), "default"), 1);

    // The generated entry lives inside the generation, and the
    // pod-namespaced user-level link points INTO it.
    let gen_file = gen_entry(root.path(), "default", 1, "guifix");
    let entry_text = std::fs::read_to_string(&gen_file).unwrap();
    let user_link = user_entry(data_home.path(), "default", "guifix");
    assert_eq!(
        std::fs::read_link(&user_link).unwrap(),
        gen_file,
        "user entry must link into the generation"
    );

    // STRICT spec conformance: required keys, valid quoted Exec,
    // registered categories.
    shuttle::desktop::validate(&entry_text, Some("shuttle-pod-default-guifix"), None)
        .expect("generated entry must pass the strict validator");
    assert!(
        entry_text.contains("Name=GUI Fix\n"),
        "Name comes from the package's .desktop file: {entry_text}"
    );
    assert!(entry_text.contains("Categories=Utility;\n"));
    // Exec = the pod farm binary (the `current` activation seam).
    let exec_path = pod_dir(root.path(), "default").join("current/guifix");
    assert!(
        entry_text.contains(&format!("Exec=\"{}\"", exec_path.display())),
        "Exec must be the farm binary, got: {entry_text}"
    );

    // The icon is linked alongside: pod-namespaced theme icon into the
    // store blob — and the validator's blob check passes against it.
    let hash = icon_hash(root.path(), "default", 1, "guifix", "guifix");
    let (aa, _) = hash.split_at(2);
    let blob = pod_dir(root.path(), "default").join(format!("store/{aa}/{hash}"));
    let icon_link = user_icon(data_home.path(), "default", "guifix", "png");
    assert_eq!(std::fs::read_link(&icon_link).unwrap(), blob);
    assert_eq!(std::fs::read(&icon_link).unwrap(), ICON_PNG);
    shuttle::desktop::validate(&entry_text, Some("shuttle-pod-default-guifix"), Some(&blob))
        .expect("entry must validate with its icon blob resolvable");

    // The launcher's Exec target EXECUTES the farm binary.
    let out = Command::new(&exec_path)
        .output()
        .expect("spawn exec target");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("gui-ran"),
        "farm binary must execute: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
});

gated_test!(entry_without_icon_is_valid_and_links_nothing, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let data_home = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "baregui");
    write_gui_pkg(
        project.path(),
        "baregui",
        "baregui",
        "baregui",
        "Bare GUI",
        "bare-ran",
        port,
        "baregui.tar.gz",
        false,
    );

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        data_home.path(),
        &["add", "baregui"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");

    let text = std::fs::read_to_string(gen_entry(root.path(), "default", 1, "baregui")).unwrap();
    shuttle::desktop::validate(&text, None, None)
        .expect("icon-less entry must still pass the strict validator");
    assert!(
        !text.lines().any(|l| l.starts_with("Icon=")),
        "no Icon= key without a shipped icon: {text}"
    );
    assert!(
        !user_icon(data_home.path(), "default", "baregui", "png").exists(),
        "no icon link without a shipped icon"
    );
    assert!(user_entry(data_home.path(), "default", "baregui").exists());
});

gated_test!(remove_withdraws_entry_and_icon, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let data_home = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "guifix");
    write_gui_pkg(
        project.path(),
        "guifix",
        "guifix",
        "guifix",
        "GUI Fix",
        "gui-ran",
        port,
        "guifix.tar.gz",
        true,
    );

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        data_home.path(),
        &["add", "guifix"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(user_entry(data_home.path(), "default", "guifix").exists());
    assert!(user_icon(data_home.path(), "default", "guifix", "png").exists());

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        data_home.path(),
        &["remove", "guifix"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");

    // Entry and icon withdrawn at the user level.
    assert!(
        !user_entry(data_home.path(), "default", "guifix").exists(),
        "entry withdrawn"
    );
    assert!(
        !user_icon(data_home.path(), "default", "guifix", "png").exists(),
        "icon withdrawn"
    );
    // The withdrawn generation's own launcher file goes with the emit
    // (the new generation's launcher set is empty).
    let active_gen = current_generation(root.path(), "default");
    assert!(
        !gen_entry(root.path(), "default", active_gen, "guifix").exists(),
        "active generation carries no launcher for the removed package"
    );
});

gated_test!(rollback_restores_previous_launcher_set, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let data_home = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "guifix");
    make_tarball(server.path(), "guifix2");
    write_gui_pkg(
        project.path(),
        "guifix",
        "guifix",
        "guifix",
        "GUI Fix",
        "gui-ran",
        port,
        "guifix.tar.gz",
        true,
    );
    write_gui_pkg(
        project.path(),
        "guifix2",
        "guifix2",
        "guifix2",
        "GUI Fix Two",
        "gui2-ran",
        port,
        "guifix2.tar.gz",
        true,
    );

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        data_home.path(),
        &["add", "guifix"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        data_home.path(),
        &["add", "guifix2"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(current_generation(root.path(), "default"), 2);
    assert!(user_entry(data_home.path(), "default", "guifix").exists());
    assert!(user_entry(data_home.path(), "default", "guifix2").exists());

    // Roll back: ONLY the pod's current link flips (system state
    // untouched), and the launcher set re-emits to the previous
    // generation's — the second app's entry + icon disappear.
    let (code, _, stderr) = run(project.path(), root.path(), data_home.path(), &["rollback"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(current_generation(root.path(), "default"), 1);
    assert!(
        user_entry(data_home.path(), "default", "guifix").exists(),
        "previous set restored"
    );
    assert!(
        !user_entry(data_home.path(), "default", "guifix2").exists(),
        "newer generation's entry withdrawn"
    );
    assert!(
        !user_icon(data_home.path(), "default", "guifix2", "png").exists(),
        "newer generation's icon withdrawn"
    );
    assert!(
        user_icon(data_home.path(), "default", "guifix", "png").exists(),
        "previous set's icon restored"
    );
    // The restored entry still validates and still executes.
    let text = std::fs::read_to_string(gen_entry(root.path(), "default", 1, "guifix")).unwrap();
    let hash = icon_hash(root.path(), "default", 1, "guifix", "guifix");
    let (aa, _) = hash.split_at(2);
    let blob = pod_dir(root.path(), "default").join(format!("store/{aa}/{hash}"));
    shuttle::desktop::validate(&text, Some("shuttle-pod-default-guifix"), Some(&blob)).unwrap();
});

gated_test!(same_precedence_app_id_collision_errors, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let data_home = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "fixa");
    make_tarball(server.path(), "fixb");
    // Two plain packages claiming the SAME desktop app id — a
    // same-precedence collision: hard error.
    write_gui_pkg(
        project.path(),
        "fixa",
        "clash",
        "bina",
        "App A",
        "ran-a",
        port,
        "fixa.tar.gz",
        false,
    );
    write_gui_pkg(
        project.path(),
        "fixb",
        "clash",
        "binb",
        "App B",
        "ran-b",
        port,
        "fixb.tar.gz",
        false,
    );

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        data_home.path(),
        &["add", "fixa"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let gens_before = generation_count(root.path(), "default");

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        data_home.path(),
        &["add", "fixb"],
    );
    assert_ne!(code, Some(0), "same-precedence collision must error");
    assert!(
        stderr.contains("same-precedence"),
        "error must name the collision rule: {stderr}"
    );
    assert!(
        stderr.contains("'clash'"),
        "error must name the application id: {stderr}"
    );

    // Zero store writes: no new generation, and fixa's launcher surface
    // is untouched (no clash entry from fixb ever leaked).
    assert_eq!(generation_count(root.path(), "default"), gens_before);
    assert!(
        user_entry(data_home.path(), "default", "clash").exists(),
        "the incumbent's entry stays"
    );
    let text = std::fs::read_to_string(user_entry(data_home.path(), "default", "clash")).unwrap();
    assert!(
        text.contains("Name=App A\n"),
        "the incumbent's entry is unchanged, got: {text}"
    );
});

gated_test!(overlay_override_of_app_id_warns_and_wins, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let data_home = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "fixa");
    make_tarball(server.path(), "fixb");
    write_gui_pkg(
        project.path(),
        "fixa",
        "clash",
        "bina",
        "App A",
        "ran-a",
        port,
        "fixa.tar.gz",
        false,
    );
    write_gui_pkg(
        project.path(),
        "fixb",
        "clash",
        "binb",
        "App B",
        "ran-b",
        port,
        "fixb.tar.gz",
        false,
    );

    // A pod.lua declaring both packages with an overlay entry on fixb:
    // the overlay layer strictly dominates, so the same app id is a
    // cross-layer override — warn, the overlay package wins.
    let lua = r#"pod {
    packages = { "fixa", "fixb" },
    overlay = { fixb = { version = "2.0" } },
}
"#;
    std::fs::create_dir_all(pod_dir(root.path(), "default")).unwrap();
    std::fs::write(pod_dir(root.path(), "default").join("pod.lua"), lua).unwrap();

    let (code, _, stderr) = run(project.path(), root.path(), data_home.path(), &["sync"]);
    assert_eq!(code, Some(0), "cross-layer override must succeed: {stderr}");
    assert!(
        stderr.contains("overrides"),
        "the override must warn: {stderr}"
    );

    // The winning entry carries the overlay package's desktop metadata.
    let text = std::fs::read_to_string(user_entry(data_home.path(), "default", "clash")).unwrap();
    assert!(
        text.contains("Name=App B\n"),
        "the overlay layer wins, got: {text}"
    );
    // And the winning Exec runs the overlay package's binary.
    let exec_path = pod_dir(root.path(), "default").join("current/clash");
    let out = Command::new(&exec_path).output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("ran-b"));
});

gated_test!(cross_pod_app_ids_coexist, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let data_home = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "guifix");
    write_gui_pkg(
        project.path(),
        "guifix",
        "guifix",
        "guifix",
        "GUI Fix",
        "gui-ran",
        port,
        "guifix.tar.gz",
        true,
    );

    // Two pods, same app id — like binaries in separate farms, they
    // coexist: each pod's entry is pod-namespaced, no warn, no error.
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        data_home.path(),
        &["add", "guifix"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        data_home.path(),
        &["--name", "second", "add", "guifix"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");

    assert!(user_entry(data_home.path(), "default", "guifix").exists());
    assert!(user_entry(data_home.path(), "second", "guifix").exists());
    assert!(user_icon(data_home.path(), "default", "guifix", "png").exists());
    assert!(user_icon(data_home.path(), "second", "guifix", "png").exists());
    // The second pod's entry executes ITS farm binary (its own `current`).
    let text = std::fs::read_to_string(user_entry(data_home.path(), "second", "guifix")).unwrap();
    let exec_path = pod_dir(root.path(), "second").join("current/guifix");
    assert!(text.contains(&format!("Exec=\"{}\"", exec_path.display())));
    let out = Command::new(&exec_path).output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("gui-ran"));
});
