//! Grep-gate for the floor-tool seam (issue #101 AC-1): no production or
//! fixture code outside the tools module may spawn a floor tool by bare
//! name. Every floor-tool spawn must resolve through `shuttle::tools`
//! (per-tool precedence: provisioned-first, curl PATH-first) so the
//! provisioned set, `SHUTTLE_TOOL_<NAME>` overrides, and doctor's resolved
//! origin report stay the single source of truth.

use std::fs;
use std::path::{Path, PathBuf};

const FLOOR_TOOLS: [&str; 5] = ["mksquashfs", "unsquashfs", "bwrap", "curl", "tar"];

/// Files allowed to carry the bare-name spawn, each with the reason it is
/// legitimate. The goal is an EMPTY list — a new entry needs a review-level
/// justification, not convenience.
const EXCEPTIONS: [(&str, &str); 1] = [(
    "src/confine.rs",
    "test-only bwrap arg-construction fixtures (never executed); they must \
     run on hosts without bwrap or a provisioned set",
)];

fn walk_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        panic!("cannot read {}", dir.display());
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_raw_floor_tool_spawns_outside_the_tools_module() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk_rs(&src, &mut files);
    files.sort();

    let mut offenders = Vec::new();
    for file in files {
        let rel = file
            .strip_prefix(env!("CARGO_MANIFEST_DIR"))
            .unwrap_or(&file)
            .to_string_lossy()
            .into_owned();
        // The tools module itself owns the floor-tool probes and the
        // provisioner's exec tests.
        if rel == "src/tools.rs" {
            continue;
        }
        let body = fs::read_to_string(&file).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        for (lineno, line) in body.lines().enumerate() {
            for tool in FLOOR_TOOLS {
                if line.contains(&format!(r#"Command::new("{tool}")"#)) {
                    offenders.push(format!(
                        "{rel}:{}: bare spawn of '{tool}' — resolve through \
                         shuttle::tools{}",
                        lineno + 1,
                        EXCEPTIONS
                            .iter()
                            .find(|(path, _)| *path == rel)
                            .map_or(String::new(), |(_, why)| format!(" (excepted: {why})"))
                    ));
                }
            }
        }
    }

    let unexpected: Vec<String> = offenders
        .iter()
        .filter(|o| !EXCEPTIONS.iter().any(|(path, _)| o.starts_with(*path)))
        .map(|o| o.clone())
        .collect();
    assert!(
        unexpected.is_empty(),
        "raw floor-tool spawns outside the tools module (issue #101 AC-1):\n{}",
        unexpected.join("\n")
    );
}
