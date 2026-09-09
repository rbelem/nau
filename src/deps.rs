//! Dependency resolution — resolve requires/build_deps fields into build order.
//!
//! Traverses `requires` and `build_deps` fields declared in `shuttle.lua`
//! files and returns a topologically sorted build order. Used by
//! `shuttle deps` and `shuttle build --order`.
//!
//! `requires` are runtime dependencies (ADR-0018); `build_deps` are
//! build-time-only. Both edges order a build (a dependency must exist
//! before whatever consumes it), so resolution and the topological sort
//! walk both; only the runtime `requires` edges shape the `deps` tree
//! display and closure reporting.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::snap::SnapMeta;

/// A resolved dependency node with its transitive closure.
#[derive(Debug, Clone)]
pub struct DepNode {
    pub name: String,
    pub requires: Vec<String>,
    pub build_deps: Vec<String>,
}

impl DepNode {
    /// Every dependency edge of this node: `requires` + `build_deps`,
    /// deduplicated, declaration order preserved.
    pub fn all_deps(&self) -> Vec<String> {
        let mut all = Vec::new();
        for dep in self.requires.iter().chain(&self.build_deps) {
            if !all.contains(dep) {
                all.push(dep.clone());
            }
        }
        all
    }
}

/// Resolve transitive dependencies for a list of seed packages.
///
/// `seeds` can be package names (resolved via pkgs/) or paths to shuttle.lua files.
/// Returns packages in topological build order (leaf dependencies first).
pub fn resolve_deps(seeds: &[String], recursive: bool) -> miette::Result<Vec<DepNode>> {
    let mut nodes: Vec<DepNode> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut pending: Vec<String> = seeds.to_vec();

    while let Some(name) = pending.pop() {
        if !visited.insert(name.clone()) {
            continue;
        }

        let meta = load_meta(&name)?;
        let requires: Vec<String> = meta
            .requires
            .iter()
            .filter(|r| !r.is_empty())
            .cloned()
            .collect();
        let build_deps: Vec<String> = meta
            .build_deps
            .iter()
            .filter(|r| !r.is_empty())
            .cloned()
            .collect();

        nodes.push(DepNode {
            name: name.clone(),
            requires: requires.clone(),
            build_deps: build_deps.clone(),
        });

        if recursive {
            for dep in requires.iter().chain(&build_deps) {
                if !visited.contains(dep) {
                    pending.push(dep.clone());
                }
            }
        }
    }

    // Topological sort: leaves first
    let sorted = topological_sort(&nodes);
    Ok(sorted)
}

/// Resolve transitive dependencies and return names in build order.
pub fn resolve_dep_names(seeds: &[String], recursive: bool) -> miette::Result<Vec<String>> {
    let nodes = resolve_deps(seeds, recursive)?;
    Ok(nodes.into_iter().map(|n| n.name).collect())
}

/// The declared build-time dependency seeds of `meta`: `requires` ∪
/// `build_deps`, deduplicated, declaration order preserved (ADR-0018).
///
/// A seed naming the package itself is the self-host marker (issue #33):
/// the package builds that dependency's payload — a glibc-from-source
/// package IS its own glibc — so the payload must not materialize into
/// the merged build prefix. It would inject the pool payload's installed
/// headers (`-I/shuttle-build-prefix/usr/include` via `CPPFLAGS`) ahead
/// of the package's own build tree, and the build compiles against the
/// pool copy (empirically: glibc's gen-as-const probes die on pool
/// glibc headers). The runtime closure keeps the entry; only the
/// build-time view drops it.
pub fn build_dep_seeds(meta: &SnapMeta) -> Vec<String> {
    let mut seeds: Vec<String> = Vec::new();
    for dep in meta.requires.iter().chain(&meta.build_deps) {
        if dep == &meta.name || seeds.contains(dep) {
            continue;
        }
        seeds.push(dep.clone());
    }
    seeds
}

/// Format deps as a tree string.
pub fn format_tree(seeds: &[String], _recursive: bool) -> miette::Result<String> {
    let nodes = resolve_deps(seeds, true)?;
    let mut output = String::new();

    // Build adjacency: name → children
    let mut children: HashMap<String, Vec<String>> = HashMap::new();
    let all_names: HashSet<String> = nodes.iter().map(|n| n.name.clone()).collect();

    for node in &nodes {
        for dep in &node.requires {
            if all_names.contains(dep) {
                children
                    .entry(node.name.clone())
                    .or_default()
                    .push(dep.clone());
            }
        }
    }

    // Print tree for each seed
    for seed in seeds {
        if all_names.contains(seed) {
            print_tree_node(&format!(" {}", seed), &children, &mut output, 0);
        }
    }

    Ok(output)
}

fn print_tree_node(
    name: &str,
    children: &HashMap<String, Vec<String>>,
    output: &mut String,
    depth: usize,
) {
    let indent = "  ".repeat(depth);
    output.push_str(&format!("{}{}\n", indent, name));

    if let Some(deps) = children.get(name.trim()) {
        for dep in deps {
            print_tree_node(dep, children, output, depth + 1);
        }
    }
}

/// Topological sort (Kahn's algorithm): leaf dependencies first.
///
/// Edges come from both `requires` and `build_deps` — either kind of
/// dependency must build before its consumer.
fn topological_sort(nodes: &[DepNode]) -> Vec<DepNode> {
    let names: Vec<String> = nodes.iter().map(|n| n.name.clone()).collect();
    let name_set: HashSet<&str> = names.iter().map(|n| n.as_str()).collect();

    // Build in-degree and adjacency
    let mut in_degree: HashMap<&str, usize> = HashMap::new();
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();

    for node in nodes {
        in_degree.entry(&node.name).or_insert(0);
        // Both edge kinds borrow from `node` (which outlives the sort).
        let mut edges: Vec<&str> = Vec::new();
        for dep in node.requires.iter().chain(&node.build_deps) {
            if !edges.contains(&dep.as_str()) {
                edges.push(dep.as_str());
            }
        }
        for dep in edges {
            if name_set.contains(dep) {
                adj.entry(dep).or_default().push(&node.name);
                *in_degree.entry(&node.name).or_insert(0) += 1;
            } else {
                // Dependency not in graph — leaf from outside
            }
        }
    }

    // Kahn's algorithm
    let mut queue: Vec<&str> = in_degree
        .iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(name, _)| *name)
        .collect();
    let mut sorted: Vec<String> = Vec::new();

    while let Some(name) = queue.pop() {
        sorted.push(name.to_string());
        if let Some(neighbors) = adj.get(name) {
            for next in neighbors {
                if let Some(deg) = in_degree.get_mut(next) {
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push(next);
                    }
                }
            }
        }
    }

    // Reorder nodes by sorted order
    let mut node_map: HashMap<&str, &DepNode> =
        nodes.iter().map(|n| (n.name.as_str(), n)).collect();
    let mut result: Vec<DepNode> = sorted
        .iter()
        .filter_map(|name| node_map.remove(name.as_str()).cloned())
        .collect();

    // Add any nodes not reachable through the graph
    for (_name, node) in node_map {
        result.push(node.clone());
    }

    result
}

/// Load SnapMeta by package name or path, falling back to input sources.
///
/// Resolution order:
/// 1. Filesystem path or resolved pkgs/<letter>/<name>.lua
/// 2. Package source inputs (cached GitHub repos, local paths)
pub fn load_meta(name_or_path: &str) -> miette::Result<SnapMeta> {
    match crate::pkg_source::resolve_pkg(name_or_path) {
        crate::pkg_source::PkgResult::File(path) => {
            let outputs = crate::lua::evaluate_file(&path)?;
            outputs
                .into_values()
                .next()
                .ok_or_else(|| miette::miette!("no outputs found in '{}'", path))
        }
        crate::pkg_source::PkgResult::Found { content, .. } => {
            let outputs = crate::lua::evaluate_string(name_or_path, &content)?;
            outputs
                .into_values()
                .next()
                .ok_or_else(|| miette::miette!("no outputs found in package '{}'", name_or_path))
        }
        crate::pkg_source::PkgResult::NotFound => {
            let path = resolve_path(name_or_path);
            Err(miette::miette!(
                "package '{}' not found at {:?} (not on disk or in input sources)",
                name_or_path,
                path
            ))
        }
    }
}

/// Resolve a package name to a path: checks local file system and input sources.
pub fn resolve_path(name_or_path: &str) -> PathBuf {
    crate::pkg_source::resolve_path(name_or_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topological_sort_simple() {
        let nodes = vec![
            DepNode {
                name: "gcc".into(),
                requires: vec!["gmp".into(), "mpfr".into()],
                build_deps: vec![],
            },
            DepNode {
                name: "mpfr".into(),
                requires: vec!["gmp".into()],
                build_deps: vec![],
            },
            DepNode {
                name: "gmp".into(),
                requires: vec![],
                build_deps: vec![],
            },
        ];

        let sorted = topological_sort(&nodes);
        let names: Vec<&str> = sorted.iter().map(|n| n.name.as_str()).collect();

        // gmp should come before mpfr, mpfr before gcc
        let gmp_pos = names.iter().position(|&n| n == "gmp").unwrap();
        let mpfr_pos = names.iter().position(|&n| n == "mpfr").unwrap();
        let gcc_pos = names.iter().position(|&n| n == "gcc").unwrap();

        assert!(gmp_pos < mpfr_pos, "gmp should be before mpfr");
        assert!(mpfr_pos < gcc_pos, "mpfr should be before gcc");
    }

    #[test]
    fn test_resolve_path() {
        // Package name -> pkgs/<letter>/<name>.lua (single file)
        let p = resolve_path("gcc");
        assert!(p.to_string_lossy().ends_with("pkgs/g/gcc.lua"));

        // File path -> raw path
        let p = resolve_path("examples/full-system/system-base/shuttle.lua");
        assert!(p
            .to_string_lossy()
            .ends_with("examples/full-system/system-base/shuttle.lua"));
    }

    #[test]
    fn test_topological_sort_linear() {
        let nodes = vec![
            DepNode {
                name: "d".into(),
                requires: vec!["c".into()],
                build_deps: vec![],
            },
            DepNode {
                name: "c".into(),
                requires: vec!["b".into()],
                build_deps: vec![],
            },
            DepNode {
                name: "b".into(),
                requires: vec!["a".into()],
                build_deps: vec![],
            },
            DepNode {
                name: "a".into(),
                requires: vec![],
                build_deps: vec![],
            },
        ];

        let sorted = topological_sort(&nodes);
        let names: Vec<&str> = sorted.iter().map(|n| n.name.as_str()).collect();

        // All deps before dependents
        for &n in &["a", "b", "c", "d"] {
            assert!(names.contains(&n), "missing {}", n);
        }
        let a = names.iter().position(|&n| n == "a").unwrap();
        let b = names.iter().position(|&n| n == "b").unwrap();
        let c = names.iter().position(|&n| n == "c").unwrap();
        let d = names.iter().position(|&n| n == "d").unwrap();
        assert!(a < b);
        assert!(b < c);
        assert!(c < d);
    }

    fn seeds_meta(name: &str, requires: &[&str], build_deps: &[&str]) -> SnapMeta {
        SnapMeta {
            name: name.into(),
            version: "1.0".into(),
            summary: None,
            description: None,
            license: None,
            source: None,
            sources: None,
            build: Some("make".into()),
            parts: None,
            architectures: Some(vec!["amd64".into()]),
            grade: "stable".into(),
            confinement: "strict".into(),
            type_: Some("source".into()),
            adopt_info: None,
            version_adopted: false,
            icon_source: None,
            icon: None,
            compression: None,
            environment: None,
            layout: None,
            hooks: None,
            plugs: None,
            slots: None,
            aliases: vec![],
            requires: requires.iter().map(|s| s.to_string()).collect(),
            build_deps: build_deps.iter().map(|s| s.to_string()).collect(),
            leaks_ok: vec![],
            target: None,
            toolchain: None,
            inputs: None,
            confined: None,
            apps: std::collections::HashMap::new(),
            deps: None,
            floating: false,
            definition_dir: None,
        }
    }

    #[test]
    fn build_dep_seeds_drop_self_referenced_payloads() {
        // Self-host marker (issue #33): a requires entry naming the
        // package itself declares the package builds that payload — it
        // must not seed the merged build prefix (pool headers would
        // shadow its own build tree). Regular deps pass through.
        let meta = seeds_meta("glibc", &["glibc", "linux-headers"], &["glibc", "make"]);
        assert_eq!(build_dep_seeds(&meta), vec!["linux-headers", "make"]);
    }

    /// Build_deps edges order a build exactly like requires edges: a
    /// build-time dependency must be built before whatever consumes it
    /// (ADR-0018, issue #17).
    #[test]
    fn test_topological_sort_build_deps_order() {
        let nodes = vec![
            DepNode {
                name: "app".into(),
                requires: vec![],
                build_deps: vec!["libdev".into()],
            },
            DepNode {
                name: "libdev".into(),
                requires: vec![],
                build_deps: vec![],
            },
        ];

        let sorted = topological_sort(&nodes);
        let names: Vec<&str> = sorted.iter().map(|n| n.name.as_str()).collect();
        let libdev = names.iter().position(|&n| n == "libdev").unwrap();
        let app = names.iter().position(|&n| n == "app").unwrap();
        assert!(libdev < app, "build_deps must build before their consumer");
    }

    /// all_deps merges both edge kinds, deduplicated.
    #[test]
    fn test_all_deps_dedupes() {
        let node = DepNode {
            name: "app".into(),
            requires: vec!["glibc".into(), "ncurses".into()],
            build_deps: vec!["ncurses".into()],
        };
        assert_eq!(node.all_deps(), vec!["glibc", "ncurses"]);
    }
}
