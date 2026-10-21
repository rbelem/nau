//! The build-time dependency view (issues #33, #4, #18, #15): the merged
//! build prefix closure of the package under construction.
//!
//! The view is TWO-LEVEL. A package's build view is its DIRECT SEEDS
//! (`requires` ∪ `build_deps`, minus itself) plus the runtime-`requires`
//! CLOSURE of those seeds; below the direct seeds the walk follows
//! `requires` ONLY. A member's own `build_deps` are NOT followed into
//! the host's view — they are reached through that member's OWN view,
//! because every lane already recurses per member.
//!
//! That is what fixes issue #15: a consumer (tmux) no longer carries
//! glibc's build tools (bison, gawk, gcc, make) in its build prefix,
//! because glibc reaches the consumer as a member, not as a seed of the
//! consumer's own tool set. glibc's build tools still reach glibc's own
//! build, where they belong.
//!
//! The second rule is the exclusion set (issue #18): an edge OR a seed
//! naming a package currently under construction is dropped, at any
//! depth. The exclusion is the lane's `building` stack — the chain of
//! packages under construction — and the comparison is on CANONICAL
//! names, so a member that names an excluded package through an alias
//! drops too. The host's own name joins the set: the package under
//! construction supplies its own payload, so its edge back into itself
//! never walks.
//!
//! Dropping the edge is also the answer to the ancestor case: an
//! ancestor's payload does not exist yet (it is the build in progress),
//! so the member links against whatever libc the toolchain provides
//! rather than staging a payload that is not there.
//!
//! Cycle refusal is NOT re-implemented here. The build lanes already fail a
//! genuine recursion by name from their `building` stack
//! (`ensure_pod_dep_payload`, `ensure_dep_payload`, `ensure_farm_dep_payload`).
//! This view keeps that detector's input intact for the members it does
//! carry: a cycle among members (`a → b → a`) still reaches the stack
//! whole, because neither `a` nor `b` is under construction when the
//! host's view is computed.

use std::collections::HashSet;

use nau_core::snap_types::SnapMeta;

use super::{
    build_dep_seeds,
    walk::{resolve_walk_with, Edges, WalkNode},
    DepNode, DepSpec,
};

/// The build view of `meta`: its direct seeds (`requires` ∪ `build_deps`,
/// minus itself) plus the runtime-`requires` closure of those seeds.
///
/// `exclude` names the packages already under construction — the lanes'
/// `building` stack. An edge or a seed naming one of them drops, at any
/// depth, compared on canonical names (issue #18). `meta`'s own name
/// joins the set: the package under construction supplies its own
/// payload, so an edge back into itself never walks.
fn host_view(
    meta: &SnapMeta,
    exclude: &[String],
    load: &dyn Fn(&str, Option<&str>) -> miette::Result<SnapMeta>,
) -> miette::Result<Vec<WalkNode>> {
    let seeds = build_dep_seeds(meta);
    if seeds.is_empty() {
        return Ok(Vec::new());
    }
    let mut excluded: HashSet<String> = exclude.iter().cloned().collect();
    excluded.insert(meta.name.clone());
    resolve_walk_with(&seeds, true, &excluded, Edges::RequiresOnly, load)
}

/// The build-prefix closure of `meta`, each member carrying the constraint
/// its edge selected (ADR-0047) — the pod and chart lanes' entry point.
///
/// `exclude` names the packages already under construction (the lane's
/// `building` stack); see [`host_view`].
pub fn resolve_build_dep_specs(
    meta: &SnapMeta,
    exclude: &[String],
) -> miette::Result<Vec<DepSpec>> {
    Ok(host_view(meta, exclude, &super::load_meta_for)?
        .into_iter()
        .map(|n| DepSpec {
            name: n.name,
            constraint: n.constraint,
        })
        .collect())
}

/// [`resolve_build_dep_specs`] names only, in build order.
pub fn resolve_build_dep_names(meta: &SnapMeta, exclude: &[String]) -> miette::Result<Vec<String>> {
    Ok(host_view(meta, exclude, &super::load_meta_for)?
        .into_iter()
        .map(|n| n.name)
        .collect())
}

/// [`resolve_build_dep_specs`] with each member's resolved edges — the
/// build-order report and the scheduler's dep graph.
pub fn resolve_build_dep_nodes(
    meta: &SnapMeta,
    exclude: &[String],
) -> miette::Result<Vec<DepNode>> {
    Ok(host_view(meta, exclude, &super::load_meta_for)?
        .into_iter()
        .map(|n| DepNode {
            name: n.name,
            requires: n.requires,
            build_deps: n.build_deps,
        })
        .collect())
}

/// [`resolve_build_dep_specs`] over an injected loader: the unit-test seam
/// (recipes cannot be evaluated under the test harness, so the tests hand
/// in an in-memory metadata map). The exclusion is `&str` here — the
/// tests name packages as literals.
#[cfg(test)]
pub(super) fn resolve_build_dep_names_with(
    meta: &SnapMeta,
    metas: &std::collections::HashMap<String, SnapMeta>,
    exclude: &[&str],
) -> miette::Result<Vec<String>> {
    let load = |name: &str, _constraint: Option<&str>| match metas.get(name) {
        Some(m) => Ok(m.clone()),
        None => Err(miette::miette!("package '{name}' not found")),
    };
    let excluded: Vec<String> = exclude.iter().map(|name| name.to_string()).collect();
    Ok(host_view(meta, &excluded, &load)?
        .into_iter()
        .map(|n| n.name)
        .collect())
}
