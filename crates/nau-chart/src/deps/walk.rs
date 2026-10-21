//! The dependency walk: seeds → nodes, with the exclusion set (issue
//! #18) and the edge policy (issue #15) the build view needs.

use std::collections::{HashMap, HashSet};

use nau_core::snap_types::SnapMeta;

use super::{effective_constraints, load_meta_for, split_dep_spec, topological_sort, DepNode};

/// Which edge kinds the walk follows below its seeds.
///
/// `All` follows `requires` ∪ `build_deps` — the runtime closure
/// (ADR-0018). `RequiresOnly` follows `requires` alone — the build view
/// (issue #15): a member's build tools belong to that member's own view.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Edges {
    All,
    RequiresOnly,
}

/// One walked node: canonical name, effective constraint, raw edges.
pub(super) struct WalkNode {
    pub(super) name: String,
    pub(super) constraint: Option<String>,
    pub(super) requires: Vec<String>,
    pub(super) build_deps: Vec<String>,
}

/// The shared resolution walk: loads each seed (its edge may carry an
/// `@constraint` — the constraint rides the recipe eval), follows the
/// edges `edges` selects transitively when `recursive`, and returns
/// nodes in topological build order. Constraints merge through
/// [`effective_constraints`].
///
/// `excluded` names the packages already under construction: an edge or
/// a seed naming one of them drops, at any depth, compared on CANONICAL
/// names. Runtime callers pass an empty set.
pub(super) fn resolve_walk(
    seeds: &[String],
    recursive: bool,
    excluded: &HashSet<String>,
    edges: Edges,
) -> miette::Result<Vec<WalkNode>> {
    resolve_walk_with(seeds, recursive, excluded, edges, &load_meta_for)
}

/// [`resolve_walk`] with the recipe loader injected: the unit-test seam
/// (recipes cannot be evaluated under the test harness — the eval worker
/// re-executes `argv[0]`) and the one place the exclusion rule lives.
pub(super) fn resolve_walk_with(
    seeds: &[String],
    recursive: bool,
    excluded: &HashSet<String>,
    edges: Edges,
    load: &dyn Fn(&str, Option<&str>) -> miette::Result<SnapMeta>,
) -> miette::Result<Vec<WalkNode>> {
    let mut nodes: Vec<WalkNode> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    // name → every constraint any edge used to reach it (deduped).
    let mut edge_constraints: HashMap<String, Vec<String>> = HashMap::new();
    let mut pending: Vec<(String, Option<String>)> = Vec::new();
    for seed in seeds {
        let (base, constraint) = split_dep_spec(seed)?;
        // Fast path: the seed already spells an excluded package. The
        // canonical check below catches the alias spellings.
        if excluded.contains(base) {
            continue;
        }
        pending.push((base.to_string(), constraint.map(str::to_string)));
    }

    while let Some((seed, constraint)) = pending.pop() {
        let meta = load(&seed, constraint.as_deref())?;
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
        // Issue #18: the exclusion compares CANONICAL names, so an alias
        // spelling of an excluded package drops here.
        if excluded.contains(&name) {
            continue;
        }
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
            // Issue #15: the build view follows `requires` alone below the
            // host's direct seeds — a member's own build tools ride that
            // member's own view, not the host's.
            let followed: &[String] = match edges {
                Edges::All => &build_deps,
                Edges::RequiresOnly => &[],
            };
            for dep in requires.iter().chain(followed) {
                let (base, c) = split_dep_spec(dep)?;
                // Transitive self-host rule (issue #4) widened to the
                // whole building stack (issue #18): a package under
                // construction supplies its own payload, so an edge back
                // to it is not walked.
                if excluded.contains(base) {
                    continue;
                }
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
