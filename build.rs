//! Builds Luau 0.663's analyzer (Luau.Analysis + deps) from the vendored
//! upstream tarball, plus the extern "C" shim in `shim/`.
//!
//! Ported from analyzer-spike/build.rs (the proven recipe — see
//! analyzer-spike/REPORT.md). Source lists come from the tarball's own
//! Sources.cmake (the build system Luau itself uses), so nothing is
//! hand-maintained per library:
//!   Luau.Analysis (64 .cpp) -> needs Ast (9), EqSat (2), Config (2) publicly,
//!   Compiler (10) + VM (33) privately (TypeFunction.cpp uses BytecodeBuilder +
//!   compileOrThrow + lua_* symbols).
//! Total: 120 C++ translation units + 1 shim TU.
//!
//! The vendored tarball (`vendor/luau-0.663.tar.gz`) duplicates the copy in
//! `analyzer-spike/` on purpose: the spike directory is archival research and
//! stays untouched.

use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const LUAU_TAG: &str = "0.663";
// Luau.Analysis needs Ast, EqSat and Config compiled, plus Compiler and VM
// headers (TypeFunction.cpp uses BytecodeBuilder + compileOrThrow + lua_*
// symbols). The Compiler+VM OBJECTS are deliberately not compiled here: the
// `mlua` runtime dependency already links the identical luau0-src
// 0.12.3+luau663 VM+Compiler (same sources, same LUAI_MAXCSTACK /
// LUA_VECTOR_SIZE defines), and compiling them again duplicates every VM
// symbol at link time. The analyzer's undefined refs resolve against mlua's.
const LIBS: &[&str] = &["Ast", "Config", "EqSat", "Analysis"];
// Only these tree prefixes are unpacked from the tarball (skip CLI/tests/bench).
const WANTED_DIRS: &[&str] = &[
    "Analysis", "Ast", "Common", "Compiler", "Config", "EqSat", "VM",
];

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let tarball = manifest_dir.join(format!("vendor/luau-{LUAU_TAG}.tar.gz"));
    // Only these three inputs trigger a C++ rebuild — incremental Rust-only
    // rebuilds reuse the cached object files in target/.
    println!("cargo:rerun-if-changed={}", tarball.display());
    println!("cargo:rerun-if-changed=shim/shuttle_shim.cpp");
    println!("cargo:rerun-if-changed=build.rs");

    let src_root = out_dir.join("luau-src");
    if !src_root.join("Sources.cmake").exists() {
        extract_wanted(&tarball, &src_root);
    }

    let cpp_lists = read_sources_cmake(&src_root.join("Sources.cmake"));

    let mut build = cc::Build::new();
    build
        .cpp(true)
        .std("c++17")
        .warnings(false)
        // Must match the defines luau0-src builds mlua's VM with, so the
        // analyzer's undefined lua_* symbols resolve against mlua's objects:
        // LUA_API=extern "C" is what gives the lua_* API C linkage there
        // (luau0-src lib.rs does exactly this; without it this crate's TUs
        // emit C++-mangled references that can never link).
        .define("LUAI_MAXCSTACK", "1000000")
        .define("LUA_VECTOR_SIZE", "3")
        .define("LUA_API", "extern \"C\"")
        // Luau 0.663 relies on transitive <cstdint> includes (e.g.
        // TypedAllocator.cpp uses uintptr_t); newer gcc no longer leaks it in.
        .flag("-include")
        .flag("cstdint");

    for dir in [
        "Common", "Ast", "Config", "EqSat", "Analysis", "Compiler", "VM",
    ] {
        build.include(src_root.join(dir).join("include"));
    }

    for lib in LIBS {
        let key = format!("Luau.{lib}");
        let Some(files) = cpp_lists.get(&key) else {
            panic!("Sources.cmake: no source list for {key}");
        };
        for cpp in files {
            build.file(src_root.join(cpp));
        }
    }
    build.file(manifest_dir.join("shim/shuttle_shim.cpp"));

    build.compile("shuttle_luau_analysis");
}

/// Unpack `luau-0.663/{Analysis,Ast,...}/{include,src}` from the vendored
/// tarball into `dest`, stripping the top-level directory component.
fn extract_wanted(tarball: &Path, dest: &Path) {
    fs::create_dir_all(dest).unwrap();
    let gz = flate2::read::GzDecoder::new(File::open(tarball).unwrap());
    let mut archive = tar::Archive::new(gz);
    let wanted: Vec<String> = WANTED_DIRS
        .iter()
        .map(|d| format!("luau-{LUAU_TAG}/{d}/"))
        .collect();

    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_path_buf();
        let Some(rel) = path.to_str() else { continue };
        let root_file = rel == format!("luau-{LUAU_TAG}/Sources.cmake");
        if !root_file && !wanted.iter().any(|w| rel.starts_with(w.as_str())) {
            continue;
        }
        // strip "luau-0.663/" prefix
        let stripped = PathBuf::from(rel.split_once('/').unwrap().1);
        let target = dest.join(stripped);
        if entry.header().entry_type().is_dir() {
            fs::create_dir_all(&target).unwrap();
        } else {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            io::copy(&mut entry, &mut File::create(&target).unwrap()).unwrap();
        }
    }
}

/// Parse Sources.cmake into { "Luau.Ast" -> ["Ast/src/Allocator.cpp", ...] }.
fn read_sources_cmake(path: &Path) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut cmake = String::new();
    File::open(path)
        .unwrap()
        .read_to_string(&mut cmake)
        .unwrap();

    let mut result = std::collections::BTreeMap::new();
    let rest = cmake;
    let mut search_from = 0usize;
    while let Some(open) = rest[search_from..].find("target_sources(Luau.") {
        let abs = search_from + open;
        let after = &rest[abs + "target_sources(".len()..];
        let lib = after.split_whitespace().next().unwrap().to_string();
        let Some(body_start) = after.find("PRIVATE") else {
            break;
        };
        let body = &after[body_start + "PRIVATE".len()..];
        let Some(close) = body.find(')') else { break };
        let files: Vec<String> = body[..close]
            .lines()
            .map(str::trim)
            .filter(|l| l.ends_with(".cpp"))
            .map(String::from)
            .collect();
        result.insert(lib, files);
        search_from = abs + "target_sources(".len() + body_start + close;
    }
    result
}
