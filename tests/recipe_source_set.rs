//! Recipe source-set consistency: a recipe that unpacks its sources with
//! `dpkg-deb` must unpack exactly the sources it declares.
//!
//! Why this is a check and not a comment. The gcc payload declares 66
//! Debian debs (22 per architecture) and unpacks them by name. A version
//! bump that renames a Debian binary package breaks that pairing: the
//! build asks for `libsframe1` while the sources table carries
//! `libsframe3`, and the failure lands at build time as a missing file
//! in `$SRC`.
//!
//! That failure is expensive to reach. The build needs a pool window
//! (AGENTS.md: heavy compiles are pool-only), so the pairing check would
//! otherwise be verified only where a worker happens to exist. This test
//! needs no build at all.
//!
//! Two unpack shapes exist, and both are covered:
//!
//!   * the loop form (pkgs/g/gcc.lua) — `for p in ... do dpkg-deb -x
//!     "$SRC/$p"`, with per-architecture names spelled `$dt` (the Debian
//!     triplet) and `$a` (the Debian architecture). The recipe declares
//!     its own architecture map in a `case` block; the test reads that
//!     block rather than hardcoding a second copy of it.
//!
//!   * the literal form (pkgs/l/linux-headers.lua and the libX family) —
//!     `dpkg-deb -x "$SRC/<name>"`, one reference per source.
//!
//! The source-key naming rule is the recipe's own: a name that already
//! encodes the triplet stays bare (`gcc-16-x86-64-linux-gnu`), and an
//! architecture-generic name carries the architecture suffix
//! (`gcc-16_amd64`, the Debian filename convention).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// A recipe that unpacks its sources with dpkg-deb.
struct DebRecipe {
    path: PathBuf,
    body: String,
    /// The declared `sources` keys.
    declared: BTreeSet<String>,
    /// The names the build script unpacks, already expanded per
    /// architecture.
    unpacked: BTreeSet<String>,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Every recipe under pkgs/ that unpacks a deb.
fn deb_recipes() -> Vec<DebRecipe> {
    let pkgs = repo_root().join("pkgs");
    let mut found = Vec::new();
    let mut stack = vec![pkgs];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("lua") {
                continue;
            }
            let Ok(body) = std::fs::read_to_string(&path) else {
                continue;
            };
            if !body.contains("dpkg-deb") {
                continue;
            }
            let declared = declared_sources(&body);
            if declared.is_empty() {
                // A recipe that unpacks a deb but declares no `sources`
                // table gets its archive by URL at build time. Not this
                // check's business.
                continue;
            }
            let unpacked = unpacked_names(&body);
            found.push(DebRecipe {
                path,
                body,
                declared,
                unpacked,
            });
        }
    }
    found.sort_by(|a, b| a.path.cmp(&b.path));
    found
}

/// The keys of the recipe's `sources` table.
fn declared_sources(body: &str) -> BTreeSet<String> {
    let Some(start) = body.find("sources = {") else {
        return BTreeSet::new();
    };
    let rest = &body[start + "sources = {".len()..];
    let mut keys = BTreeSet::new();
    let mut depth = 1usize;
    for line in rest.lines() {
        // Track brace depth so a nested table does not end the scan.
        for ch in line.chars() {
            match ch {
                '{' => depth += 1,
                '}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        if depth == 0 {
            break;
        }
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("[\"") {
            if let Some(end) = rest.find("\"]") {
                keys.insert(rest[..end].to_string());
            }
        }
    }
    keys
}

/// The names the build script unpacks, expanded over every architecture
/// the recipe declares.
fn unpacked_names(body: &str) -> BTreeSet<String> {
    if let Some(templates) = loop_templates(body) {
        let arches = arch_map(body);
        let mut names = BTreeSet::new();
        for (arch, triplet) in arches {
            for template in &templates {
                let expanded = template.replace("$dt", &triplet).replace("$a", &arch);
                names.insert(source_key(&expanded, &arch, &triplet));
            }
        }
        return names;
    }
    literal_unpacked(body)
}

/// The `for p in ...` list of the deb-unpack loop.
fn loop_templates(body: &str) -> Option<Vec<String>> {
    let anchor = body.find("for p in")?;
    let rest = &body[anchor + "for p in".len()..];
    let end = rest.find("do dpkg-deb")?;
    let block = &rest[..end];
    let mut templates = Vec::new();
    for chunk in block.split('\\') {
        for word in chunk.split_whitespace() {
            let word = word.trim();
            if word.starts_with('"') && word.ends_with('"') && word.len() > 2 {
                templates.push(word[1..word.len() - 1].to_string());
            }
        }
    }
    if templates.is_empty() {
        None
    } else {
        Some(templates)
    }
}

/// The recipe's own architecture map: the `case` block that assigns
/// `a=<arch>` and `dt=<triplet>`.
///
/// A case arm reads `aarch64*) a=arm64; t=aarch64-linux-gnu; dt=$t ;;`.
/// The assignments are picked out as whitespace-delimited tokens, so the
/// case pattern in front of them is ignored.
fn arch_map(body: &str) -> Vec<(String, String)> {
    let mut arches = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if !line.ends_with(";;") {
            continue;
        }
        let mut arch = None;
        let mut triplet = None;
        let mut binary_triplet = None;
        for token in line.split_whitespace() {
            // The assignments are separated by semicolons, so the token
            // that is not last carries one: `t=aarch64-linux-gnu;`.
            let token = token.trim_end_matches(';');
            if let Some(value) = token.strip_prefix("a=") {
                arch = Some(value.to_string());
            } else if let Some(value) = token.strip_prefix("dt=") {
                triplet = Some(value.to_string());
            } else if let Some(value) = token.strip_prefix("t=") {
                binary_triplet = Some(value.to_string());
            }
        }
        let (Some(arch), Some(triplet)) = (arch, triplet) else {
            continue;
        };
        // `dt=$t` means the deb-name triplet is the one assigned to `t`.
        let triplet = if triplet == "$t" {
            match binary_triplet {
                Some(t) => t,
                None => continue,
            }
        } else {
            triplet
        };
        arches.push((arch, triplet));
    }
    arches
}

/// The recipe's source-key naming rule.
fn source_key(expanded: &str, arch: &str, triplet: &str) -> String {
    if expanded.ends_with(&format!("_{arch}")) {
        return expanded.to_string();
    }
    if expanded.contains(triplet) {
        return expanded.to_string();
    }
    format!("{expanded}_{arch}")
}

/// The literal `dpkg-deb -x "$SRC/<name>"` references.
fn literal_unpacked(body: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut rest = body;
    while let Some(at) = rest.find("dpkg-deb -x \"$SRC/") {
        rest = &rest[at + "dpkg-deb -x \"$SRC/".len()..];
        if let Some(end) = rest.find('"') {
            names.insert(rest[..end].to_string());
        }
    }
    names
}

#[test]
fn every_deb_recipe_unpacks_exactly_its_declared_sources() {
    let recipes = deb_recipes();
    assert!(
        !recipes.is_empty(),
        "no deb-unpacking recipe found under pkgs/; the scan is broken"
    );
    for recipe in &recipes {
        let name = recipe.path.display();
        let missing: Vec<_> = recipe
            .declared
            .difference(&recipe.unpacked)
            .cloned()
            .collect();
        let extra: Vec<_> = recipe
            .unpacked
            .difference(&recipe.declared)
            .cloned()
            .collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "{name}: the build script and the sources table disagree.\n  \
             declared but never unpacked: {missing:?}\n  \
             unpacked but never declared: {extra:?}\n  \
             A renamed Debian package in a version bump lands here first."
        );
    }
}

#[test]
fn the_gcc_payload_declares_one_deb_set_per_architecture() {
    let recipes = deb_recipes();
    let gcc = recipes
        .iter()
        .find(|r| r.path.ends_with("pkgs/g/gcc.lua"))
        .expect("the gcc recipe is the deb-set payload this check exists for");
    let arches = arch_map(&gcc.body);
    assert_eq!(
        arches.len(),
        3,
        "expected one deb set per architecture, got {arches:?}"
    );
    let templates = loop_templates(&gcc.body).expect("the gcc recipe unpacks by loop");
    for (arch, triplet) in &arches {
        let owned: Vec<String> = templates
            .iter()
            .map(|template| {
                source_key(
                    &template.replace("$dt", triplet).replace("$a", arch),
                    arch,
                    triplet,
                )
            })
            .collect();
        assert!(
            !owned.is_empty(),
            "the {arch} deb set is empty; the arch map and the unpack loop disagree"
        );
        for key in &owned {
            assert!(
                gcc.declared.contains(key),
                "the {arch} deb set names {key}, which the sources table does not declare"
            );
        }
    }
}
