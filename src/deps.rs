//! Dependency resolution — resolve requires fields into build order.
//!
//! Traverses `requires` fields declared in `shoot.lua` files and returns
//! a topologically sorted build order. Used by `shoot deps` and
//! `shoot build --order`.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::snap::SnapMeta;

/// A resolved dependency node with its transitive closure.
#[derive(Debug, Clone)]
pub struct DepNode {
    pub name: String,
    pub requires: Vec<String>,
}

/// Resolve transitive dependencies for a list of seed packages.
///
/// `seeds` can be package names (resolved via pkgs/) or paths to shoot.lua files.
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

        nodes.push(DepNode {
            name: name.clone(),
            requires: requires.clone(),
        });

        if recursive {
            for dep in &requires {
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
fn topological_sort(nodes: &[DepNode]) -> Vec<DepNode> {
    let names: Vec<String> = nodes.iter().map(|n| n.name.clone()).collect();
    let name_set: HashSet<&str> = names.iter().map(|n| n.as_str()).collect();

    // Build in-degree and adjacency
    let mut in_degree: HashMap<&str, usize> = HashMap::new();
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();

    for node in nodes {
        in_degree.entry(&node.name).or_insert(0);
        for dep in &node.requires {
            if name_set.contains(dep.as_str()) {
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

/// Load SnapMeta from a shoot.lua file, resolving the path by package name.
pub fn load_meta(name_or_path: &str) -> miette::Result<SnapMeta> {
    let path = resolve_path(name_or_path);
    if !path.exists() {
        return Err(miette::miette!(
            "package '{}' not found at {:?}",
            name_or_path,
            path
        ));
    }

    let outputs = crate::lua::evaluate_file(&path.to_string_lossy())?;
    // Return the first output's meta
    outputs
        .into_values()
        .next()
        .ok_or_else(|| miette::miette!("no outputs found in '{}'", name_or_path))
}

/// Resolve a package name to a path: try pkgs/<letter>/<name>.lua first,
/// then fall back to the raw path (for absolute/relative paths).
fn resolve_path(name_or_path: &str) -> PathBuf {
    if name_or_path.contains('/') || name_or_path.ends_with(".lua") {
        return PathBuf::from(name_or_path);
    }

    let first = name_or_path
        .chars()
        .next()
        .unwrap_or('x')
        .to_ascii_lowercase();
    let pkg_base = PathBuf::from("pkgs").join(first.to_string());

    // Try pkgs/<letter>/<name>.lua (single file)
    let single = pkg_base.join(format!("{}.lua", name_or_path));
    if single.exists() {
        return single;
    }

    // Try pkgs/<letter>/<name>/init.lua (directory package)
    let dir_pkg = pkg_base.join(name_or_path).join("init.lua");
    if dir_pkg.exists() {
        return dir_pkg;
    }

    // Fall back to the raw name as a file path
    PathBuf::from(name_or_path)
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
            },
            DepNode {
                name: "mpfr".into(),
                requires: vec!["gmp".into()],
            },
            DepNode {
                name: "gmp".into(),
                requires: vec![],
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
        let p = resolve_path("examples/full-system/system-base/shoot.lua");
        assert!(p
            .to_string_lossy()
            .ends_with("examples/full-system/system-base/shoot.lua"));
    }

    #[test]
    fn test_topological_sort_linear() {
        let nodes = vec![
            DepNode {
                name: "d".into(),
                requires: vec!["c".into()],
            },
            DepNode {
                name: "c".into(),
                requires: vec!["b".into()],
            },
            DepNode {
                name: "b".into(),
                requires: vec!["a".into()],
            },
            DepNode {
                name: "a".into(),
                requires: vec![],
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
}
