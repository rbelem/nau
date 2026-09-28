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
use std::path::{Path, PathBuf};

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

/// A resolved dependency node plus the constraint its edges selected
/// (ADR-0047): `None` when every edge named the package bare; `Some(c)`
/// when the edges carried `name@c` — the line the member's recipe must
/// evaluate at.
#[derive(Debug, Clone)]
pub struct DepSpec {
    pub name: String,
    pub constraint: Option<String>,
}

/// Split a requires/build_deps edge that may carry an `@constraint`
/// (`name` or `name@constraint`) — the pod-spec grammar
/// (`parse_pod_package`) applied to dependency edges (ADR-0047: a
/// consumer pins a version line with the constraint, not a renamed
/// sibling). A spec containing `/` is a path, not a name — never split.
/// An empty or whitespace constraint is a malformed edge and errors.
fn split_dep_spec(spec: &str) -> miette::Result<(&str, Option<&str>)> {
    let Some((name, constraint)) = spec.split_once('@') else {
        return Ok((spec, None));
    };
    if name.is_empty() || name.contains('/') {
        return Ok((spec, None));
    }
    if constraint.is_empty() {
        miette::bail!("invalid dependency spec '{spec}': version constraint must not be empty");
    }
    if constraint.contains(char::is_whitespace) {
        miette::bail!(
            "invalid dependency spec '{spec}': version constraint must not contain whitespace"
        );
    }
    Ok((name, Some(constraint)))
}

/// One walked node: canonical name, effective constraint, raw edges.
struct WalkNode {
    name: String,
    constraint: Option<String>,
    requires: Vec<String>,
    build_deps: Vec<String>,
}

/// Collapse the per-name edge-constraint sets into one effective
/// constraint per name: the single declared line, or None when every
/// edge was bare. Two DIFFERENT constraints for one name fail named:
/// one pod holds one version of a name (ADR-0047 Decision 2), and
/// disagreeing lines are a declaration conflict, not a first-match
/// race. Bare edges impose no constraint and compose with any
/// constrained edge of the same name.
fn effective_constraints(
    edge_constraints: &HashMap<String, Vec<String>>,
) -> miette::Result<HashMap<String, Option<String>>> {
    let mut out = HashMap::with_capacity(edge_constraints.len());
    let mut ordered: Vec<&String> = edge_constraints.keys().collect();
    ordered.sort();
    for name in ordered {
        let seen = &edge_constraints[name];
        let constraint = match seen.len() {
            0 => None,
            1 => Some(seen[0].clone()),
            _ => miette::bail!(
                "conflicting version lines for '{name}' in one dependency closure: {} — \
                 one pod holds one version of a name (ADR-0047); align the constraints",
                seen.iter()
                    .map(|c| format!("@{c}"))
                    .collect::<Vec<_>>()
                    .join(" vs ")
            ),
        };
        out.insert(name.clone(), constraint);
    }
    Ok(out)
}

/// The shared resolution walk: loads each seed (its edge may carry an
/// `@constraint` — the constraint rides the recipe eval), follows
/// `requires` ∪ `build_deps` transitively when `recursive`, and returns
/// nodes in topological build order. Constraints merge through
/// [`effective_constraints`].
fn resolve_walk(seeds: &[String], recursive: bool) -> miette::Result<Vec<WalkNode>> {
    let mut nodes: Vec<WalkNode> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    // name → every constraint any edge used to reach it (deduped).
    let mut edge_constraints: HashMap<String, Vec<String>> = HashMap::new();
    let mut pending: Vec<(String, Option<String>)> = Vec::new();
    for seed in seeds {
        let (base, constraint) = split_dep_spec(seed)?;
        pending.push((base.to_string(), constraint.map(str::to_string)));
    }

    while let Some((seed, constraint)) = pending.pop() {
        let meta = load_meta_for(&seed, constraint.as_deref())?;
        // Canonical identity: a seed may name a package through an alias
        // (e.g. "toolchain" → toolchain-gcc-gnu-x86_64). Every downstream
        // consumer — payload naming, cache keys, build order — keys on the
        // meta's own name, so the node carries the canonical form and the
        // visited set dedupes on it (a seed and its canonical name meeting
        // in one closure resolve to one node).
        let name = if meta.name.is_empty() {
            seed.clone()
        } else {
            meta.name.clone()
        };
        if let Some(c) = &constraint {
            let seen = edge_constraints.entry(name.clone()).or_default();
            if !seen.contains(c) {
                seen.push(c.clone());
            }
        }
        if !visited.insert(name.clone()) {
            continue;
        }

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

        nodes.push(WalkNode {
            name: name.clone(),
            constraint,
            requires: requires.clone(),
            build_deps: build_deps.clone(),
        });

        if recursive {
            for dep in requires.iter().chain(&build_deps) {
                let (base, c) = split_dep_spec(dep)?;
                if !visited.contains(base) {
                    pending.push((base.to_string(), c.map(str::to_string)));
                } else {
                    // Already resolved — still record the edge's
                    // constraint so a conflict between two edges that
                    // both name an already-visited node fails loud.
                    if let Some(c) = c {
                        let seen = edge_constraints.entry(base.to_string()).or_default();
                        if !seen.contains(&c.to_string()) {
                            seen.push(c.to_string());
                        }
                    }
                }
            }
        }
    }

    // Conflicting lines: one name, two different constraints — refuse
    // instead of letting edge order pick the winner silently.
    let effective = effective_constraints(&edge_constraints)?;
    for node in &mut nodes {
        node.constraint = effective.get(&node.name).cloned().flatten();
    }

    // Topological sort: leaves first
    let sorted = topological_sort(
        &nodes
            .iter()
            .map(|n| DepNode {
                name: n.name.clone(),
                requires: n.requires.clone(),
                build_deps: n.build_deps.clone(),
            })
            .collect::<Vec<_>>(),
    );
    let mut order: HashMap<String, usize> = HashMap::new();
    for (i, node) in sorted.iter().enumerate() {
        order.insert(node.name.clone(), i);
    }
    nodes.sort_by_key(|n| order.get(&n.name).copied().unwrap_or(usize::MAX));
    Ok(nodes)
}

/// Resolve transitive dependencies for a list of seed packages.
///
/// `seeds` can be package names (resolved via pkgs/), paths to shuttle.lua files,
/// or `name@constraint` edges — the constraint rides the recipe eval
/// (ADR-0047). Returns packages in topological build order (leaf
/// dependencies first).
pub fn resolve_deps(seeds: &[String], recursive: bool) -> miette::Result<Vec<DepNode>> {
    Ok(resolve_walk(seeds, recursive)?
        .into_iter()
        .map(|n| DepNode {
            name: n.name,
            requires: n.requires,
            build_deps: n.build_deps,
        })
        .collect())
}

/// Like [`resolve_deps`], but each node also carries the constraint its
/// edges selected — the load-with-constraint input for closure members
/// (ADR-0047).
pub fn resolve_dep_specs(seeds: &[String], recursive: bool) -> miette::Result<Vec<DepSpec>> {
    Ok(resolve_walk(seeds, recursive)?
        .into_iter()
        .map(|n| DepSpec {
            name: n.name,
            constraint: n.constraint,
        })
        .collect())
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
    load_meta_for(name_or_path, None)
}

/// [`load_meta`] with the eval-context constraint (ADR-0047 Decision 4):
/// the pod spec's or dependency edge's `@constraint` rides the recipe
/// eval as the `constraint` global, so a version-lined recipe selects its
/// line. `name_or_path` must already be constraint-free — use
/// [`split_dep_spec`] on raw edge specs.
pub fn load_meta_for(name_or_path: &str, constraint: Option<&str>) -> miette::Result<SnapMeta> {
    match crate::pkg_source::resolve_pkg(name_or_path) {
        crate::pkg_source::PkgResult::File(path) => {
            let outputs = crate::lua::evaluate_file_with_constraint(&path, constraint)?;
            outputs
                .into_values()
                .next()
                .ok_or_else(|| miette::miette!("no outputs found in '{}'", path))
        }
        crate::pkg_source::PkgResult::Found { content, .. } => {
            let outputs =
                crate::lua::evaluate_string_with_constraint(name_or_path, &content, constraint)?;
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

/// The constraint-free base of a recipe reference: [`split_dep_spec`]
/// without the error cases — pod code uses this to strip a spec before
/// re-resolution (`resolve_pkg` matches file names, not constraints).
pub fn dep_spec_base(spec: &str) -> &str {
    match split_dep_spec(spec) {
        Ok((base, _)) => base,
        Err(_) => spec,
    }
}

/// The directory that ships beside a package's recipe: the parent of the
/// `<name>.lua` file for single-file packages, of the `init.lua` for
/// directory-form packages — the same resolution [`load_meta`] applies,
/// local `pkgs/` and input-source trees alike. `recipe/`-prefixed
/// `deps.*.lock` paths (ADR-0017) resolve against it. `None` when the
/// package does not resolve to a recipe file on disk.
pub fn recipe_dir(name_or_path: &str) -> Option<PathBuf> {
    let path = match crate::pkg_source::resolve_pkg(name_or_path) {
        crate::pkg_source::PkgResult::File(path) => path,
        crate::pkg_source::PkgResult::Found { path, .. } => path,
        crate::pkg_source::PkgResult::NotFound => return None,
    };
    Path::new(&path).parent().map(Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

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
            compression_level: None,
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
            services: std::collections::BTreeMap::new(),
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

    // ── topological sort branches (pure) ──

    #[test]
    fn topological_sort_treats_outside_graph_deps_as_leaves() {
        let nodes = vec![DepNode {
            name: "app".into(),
            requires: vec!["glibc".into()],
            build_deps: vec![],
        }];
        let names: Vec<String> = topological_sort(&nodes)
            .iter()
            .map(|n| n.name.clone())
            .collect();
        assert_eq!(names, vec!["app"]);
    }

    #[test]
    fn topological_sort_appends_nodes_trapped_in_cycles() {
        let nodes = vec![
            DepNode {
                name: "a".into(),
                requires: vec!["b".into()],
                build_deps: vec![],
            },
            DepNode {
                name: "b".into(),
                requires: vec!["a".into()],
                build_deps: vec![],
            },
            DepNode {
                name: "c".into(),
                requires: vec![],
                build_deps: vec![],
            },
        ];
        let names: Vec<String> = topological_sort(&nodes)
            .iter()
            .map(|n| n.name.clone())
            .collect();
        assert_eq!(names.len(), 3, "cycle members are not dropped: {names:?}");
        assert_eq!(names[0], "c", "free node sorts first");
    }

    // ── requires-edge constraints (ADR-0047) ──

    #[test]
    fn split_dep_spec_parses_name_and_constraint() {
        assert_eq!(split_dep_spec("glibc").unwrap(), ("glibc", None));
        assert_eq!(split_dep_spec("node@22").unwrap(), ("node", Some("22")));
        assert_eq!(split_dep_spec("node@22.2").unwrap(), ("node", Some("22.2")));
        // A path is never split, even when it contains '@'.
        assert_eq!(
            split_dep_spec("examples/x@1/pkg.lua").unwrap(),
            ("examples/x@1/pkg.lua", None)
        );
        // Malformed edges error.
        assert!(split_dep_spec("node@").is_err());
        assert!(split_dep_spec("node@2 2").is_err());
    }

    #[test]
    fn effective_constraints_pick_the_single_line() {
        let map = HashMap::from([
            ("glibc".to_string(), Vec::new()),
            ("node".to_string(), vec!["22".to_string()]),
        ]);
        let eff = effective_constraints(&map).unwrap();
        assert_eq!(eff["glibc"], None);
        assert_eq!(eff["node"].as_deref(), Some("22"));
    }

    #[test]
    fn effective_constraints_refuse_conflicting_lines() {
        // Two edges naming one package with different constraints: one
        // pod holds one version of a name (ADR-0047 D2) — the walk
        // refuses instead of letting edge order pick the winner.
        let map = HashMap::from([("node".to_string(), vec!["22".to_string(), "26".to_string()])]);
        let err = effective_constraints(&map).expect_err("conflicting lines must refuse");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("conflicting version lines for 'node'")
                && msg.contains("@22")
                && msg.contains("@26"),
            "refusal must name the package and both lines: {msg}"
        );
    }

    #[test]
    fn effective_constraints_compose_bare_and_constrained_edges() {
        // A bare edge imposes no constraint: bare + @22 of one name is
        // one node at line 22, not a conflict.
        let map = HashMap::from([("node".to_string(), vec!["22".to_string()])]);
        let eff = effective_constraints(&map).unwrap();
        assert_eq!(eff["node"].as_deref(), Some("22"));
    }

    // ── input-source resolution (no eval; process-global state, serialized) ──
    //
    // load_meta/format_tree evaluate recipes through the eval worker
    // subprocess, which re-executes argv[0] — under the test harness that
    // is the test binary, so the worker protocol breaks ("running 0
    // tests"). Those paths stay with the eval_* integration suites; only
    // the resolution seam is exercised here.

    static INPUTS_LOCK: Mutex<()> = Mutex::new(());

    fn init_local_input_source(root: &Path) {
        crate::pkg_source::init_global_inputs(&HashMap::from([(
            "test".to_string(),
            crate::snap::PackageInput {
                url: format!("path:{}", root.display()),
                submodules: None,
            },
        )]))
        .unwrap();
    }

    #[test]
    fn recipe_dir_is_the_recipe_file_parent_through_input_sources() {
        let src = tempfile::tempdir().unwrap();
        let pkg = src.path().join("pkgs/b");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(pkg.join("bpkg.lua"), "-- recipe body").unwrap();
        let _guard = INPUTS_LOCK.lock().unwrap();
        init_local_input_source(src.path());
        assert_eq!(recipe_dir("bpkg"), Some(src.path().join("pkgs/b")));
        assert_eq!(recipe_dir("missing-pkg"), None);
    }
}
