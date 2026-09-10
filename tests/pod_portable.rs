//! `shuttle pod` native-ELF interpreter portability integration tests
//! (issue #12).
//!
//! A pod build on a nix devbox host compiles with the nix gcc-wrapper, so a
//! built native binary's ELF **interpreter** references
//! `/nix/store/...-glibc.../ld-linux-x86-64.so.2` and its RUNPATH carries
//! the build machine's nix toolchain paths — a non-nix host cannot run it.
//! Shuttle repoints the interpreter at the system loader
//! (`/lib64/ld-linux-x86-64.so.2`) and clears RUNPATH at build time, so the
//! export path carries no `/nix/store` reference and runs on a plain host.
//!
//! Drives the real binary end to end through the FULL chain (pod add →
//! farm → execute), all state in tempdirs, using a loopback source server
//! (same gating + server patterns as `tests/pod_native_elf.rs`).

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
    [
        "mksquashfs",
        "unsquashfs",
        "curl",
        "tar",
        "gcc",
        "patchelf",
        "readelf",
    ]
    .iter()
    .all(|t| has_tool(t))
}

fn require_chain() {
    if !chain_available() {
        eprintln!("skipping: mksquashfs/unsquashfs/curl/tar/gcc/patchelf/readelf unavailable");
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
    let n = stream.read(&mut buf)?;
    if n == 0 {
        return Ok(());
    }
    data.extend_from_slice(&buf[..n]);
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

/// Pack a source tarball carrying a tiny standalone C app (links only the
/// system C library — no bundled runtime libs, so the #10 native-ELF lib
/// wrapper does NOT apply and the farm binary is the real ELF itself).
fn make_tarball(server_dir: &Path, name: &str) {
    let pkg = server_dir.join(name);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("app.c"),
        "#include <stdio.h>\nint main(void){ printf(\"portable-ok\\n\"); return 0; }\n",
    )
    .unwrap();
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

fn write_pkg(project: &Path, name: &str, port: u16, tarball: &str) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let lua = format!(
        r#"return {{ default = snap {{
    name = "{name}",
    version = "1.0",
    source = "http://127.0.0.1:{port}/{tarball}",
    build = "mkdir -p $STAGE/usr/bin && gcc -o $STAGE/usr/bin/{name} $SRC/app.c && chmod +x $STAGE/usr/bin/{name}",
    apps = {{ {name} = {{ command = "usr/bin/{name}" }} }},
}} }}
"#
    );
    std::fs::write(dir.join(format!("{name}.lua")), lua).unwrap();
}

// ── Runners / helpers ──

fn run(project: &Path, root: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.arg("pod").args(args).arg("--root").arg(root);
    cmd.current_dir(project);
    cmd.env("SHUTTLE_DATA_HOME", root.join("data-home"));
    // Keep pod activation off the host systemd bus (issue #66).
    cmd.env("SHUTTLE_SYSTEMD", "off");
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

fn current_farm(root: &Path, pod: &str) -> PathBuf {
    let target = std::fs::read_link(pod_dir(root, pod).join("current")).unwrap();
    if target.is_absolute() {
        target
    } else {
        pod_dir(root, pod).join(target)
    }
}

fn farm_entry_target(farm: &Path, name: &str) -> PathBuf {
    std::fs::canonicalize(farm.join(name)).expect("farm entry must resolve to existing content")
}

fn read_bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path).expect("read file")
}

fn run_farm_binary(farm: &Path, name: &str) -> String {
    let mut cmd = Command::new(farm.join(name));
    let path = format!(
        "{}:{}",
        farm.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    cmd.env("PATH", path);
    let out = cmd.output().expect("spawn farm entry");
    assert!(
        out.status.success(),
        "farm entry {name} must run successfully (exit {:?}): {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

// ── Acceptance: pod-built native ELF carries no `/nix/store` interpreter/RUNPATH ──

gated_test!(pod_built_native_elf_is_portable_on_export_path, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = project.path().join("server");
    make_tarball(&server, "port");
    let port = serve_dir(&server);
    write_pkg(project.path(), "port", port, "port.tar.gz");

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "port"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");

    // The farm export path: for a no-bundled-lib native ELF it IS the real
    // binary's store blob (no #10 wrapper), so reading the farm target
    // gives us the built ELF directly.
    let farm = current_farm(root.path(), "default");
    assert!(farm.join("port").exists(), "farm must expose the app");
    let target = farm_entry_target(&farm, "port");
    let store_dir = std::fs::canonicalize(pod_dir(root.path(), "default").join("store")).unwrap();
    assert!(
        target.starts_with(&store_dir),
        "farm entry must resolve into the store, not a shim: {target:?}"
    );

    // It must be a real native ELF (no wrapper — links only the C library).
    let bytes = read_bytes(&target);
    assert!(
        bytes.starts_with(b"\x7fELF"),
        "export path must be a native ELF, got magic: {:02x?}",
        &bytes[..4.min(bytes.len())]
    );

    // The ELF interpreter must be a system loader path, never the build
    // machine's nix store.
    let out = Command::new("readelf")
        .args(["-l", target.to_str().unwrap()])
        .output();
    let interp = String::from_utf8_lossy(&out.as_ref().unwrap().stdout);
    let interp_line = interp
        .lines()
        .find(|l| l.contains("interpreter"))
        .unwrap_or_else(|| panic!("no interpreter line in readelf -l: {interp}"));
    assert!(
        !interp_line.contains("/nix/store/"),
        "built binary interpreter must not reference the build machine's nix store: {interp_line}"
    );
    assert!(
        interp_line.contains("/lib64/ld-linux-x86-64.so.2"),
        "built binary interpreter must point at the system loader: {interp_line}"
    );

    // RUNPATH must carry no /nix/store (a non-nix host resolves runtime libs
    // from the system default search path + the pod library wrapper).
    let out = Command::new("readelf")
        .args(["-d", target.to_str().unwrap()])
        .output();
    let dyn_text = String::from_utf8_lossy(&out.as_ref().unwrap().stdout);
    assert!(
        !dyn_text.contains("/nix/store/"),
        "built binary RUNPATH must not reference the build machine's nix store: {dyn_text}"
    );

    // And it must actually execute through the farm.
    let out = run_farm_binary(&farm, "port");
    assert!(
        out.contains("portable-ok"),
        "portable native ELF must execute on the host: {out:?}"
    );
});
