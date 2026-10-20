//! Gated end-to-end check: a source package whose `build_deps` name the
//! `toolchain` alias compiles C and C++ through the pool toolchain inside
//! the hermetic sandbox (`test-fixtures/toolchain-gcc-probe.lua`), and the
//! meta payload's bare-name links resolve.
//!
//! The probe needs the meta's closure payloads (~450 MB) present as built
//! `.snap` files. Point `NAU_TOOLCHAIN_PROBE_CACHE` at a directory holding
//! `{name}_{version}_{amd64}.snap` for every closure member; a pod's
//! downloads dir seeded by `scripts/toolchain-local-assemble.sh <pod>
//! <dir>` is exactly that set. The test checks each member against the
//! recipe's CURRENT version and skips, by name, when the dir is unset or
//! incomplete — the payloads are not CI-cheap, and a stale payload must
//! not masquerade as a green probe.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The meta's closure in dependency order (pkgs/t/toolchain-gcc-gnu-x86_64.lua
/// requires plus the transitive libgcc/m4/make), with the meta itself last.
const MEMBERS: [&str; 12] = [
    "linux-headers",
    "glibc",
    "libgcc",
    "gcc",
    "zlib",
    "isl",
    "mpc",
    "m4",
    "make",
    "mpfr",
    "gmp",
    "toolchain",
];

fn has_tool(tool: &str) -> bool {
    Command::new("which")
        .arg(tool)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some()
}

/// Every closure member's `{name}_{version}_{arch}.snap` path under `dir`,
/// keyed by the member name. `Err` names the members whose payload is
/// absent at the recipe's current version.
fn closure_payloads(dir: &Path) -> Result<Vec<(String, PathBuf)>, Vec<String>> {
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for member in MEMBERS {
        let meta = nau::deps::load_meta(member)
            .unwrap_or_else(|e| panic!("evaluating recipe '{member}' failed: {e}"));
        let path = dir.join(format!("{}_{}_{}.snap", meta.name, meta.version, "amd64"));
        if path.exists() {
            found.push((meta.name, path));
        } else {
            missing.push(format!(
                "{} {} ({})",
                meta.name,
                meta.version,
                path.display()
            ));
        }
    }
    if missing.is_empty() {
        Ok(found)
    } else {
        Err(missing)
    }
}

/// Assert the meta payload's bare-name links resolve to a real file: extract
/// only the link chain and follow it.
fn assert_meta_bare_names_resolve(meta_snap: &Path) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("payload");
    let out = Command::new("unsquashfs")
        .args(["-q", "-n", "-d"])
        .arg(&root)
        .arg(meta_snap)
        .args([
            "usr/bin/gcc",
            "usr/bin/g++",
            "toolchain/usr/bin/gcc",
            "toolchain/usr/bin/g++",
            "toolchain/usr/bin/cc",
            "toolchain/usr/bin/c++",
        ])
        .output()
        .expect("spawn unsquashfs");
    assert!(
        out.status.success(),
        "unsquashfs could not extract the bare-name chain: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    for entry in ["usr/bin/gcc", "usr/bin/g++"] {
        let path = root.join(entry);
        let resolved = std::fs::metadata(&path)
            .unwrap_or_else(|e| panic!("{entry} does not resolve in the payload: {e}"));
        assert!(
            resolved.is_file(),
            "{entry} resolves to something that is not a file"
        );
    }
}

#[test]
fn toolchain_probe_builds_c_and_cpp() {
    let Some(cache) = std::env::var_os("NAU_TOOLCHAIN_PROBE_CACHE").map(PathBuf::from) else {
        eprintln!("skipping: NAU_TOOLCHAIN_PROBE_CACHE is unset (needs the closure payloads)");
        return;
    };
    if !["mksquashfs", "unsquashfs", "bwrap"]
        .iter()
        .all(|t| has_tool(t))
    {
        eprintln!("skipping: mksquashfs/unsquashfs/bwrap unavailable");
        return;
    }
    let payloads = match closure_payloads(&cache) {
        Ok(payloads) => payloads,
        Err(missing) => {
            eprintln!(
                "skipping: NAU_TOOLCHAIN_PROBE_CACHE is incomplete — missing {}. \
                 Seed it with `scripts/toolchain-local-assemble.sh <pod> <dir>`.",
                missing.join(", ")
            );
            return;
        }
    };
    let meta_snap = payloads
        .iter()
        .find(|(name, _)| name == "toolchain-gcc-gnu-x86_64")
        .map(|(_, path)| path.clone())
        .expect("closure_payloads resolved the meta by its canonical name");
    assert_meta_bare_names_resolve(&meta_snap);

    let stage = tempfile::tempdir().expect("tempdir");
    let out = Command::new(env!("CARGO_BIN_EXE_nau"))
        .args(["build", "--file", "test-fixtures/toolchain-gcc-probe.lua"])
        .arg("--output")
        .arg(&cache)
        .arg("--stage")
        .arg(stage.path())
        .env("NAU_SYSTEMD", "off")
        .output()
        .expect("failed to spawn nau build");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "probe build failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("toolchain-gcc-probe: C and C++ builds green")
            || stderr.contains("toolchain-gcc-probe: C and C++ builds green"),
        "the probe's own assertions did not run.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}
