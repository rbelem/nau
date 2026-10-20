//! The build-time dependency view (issues #33, #4): the merged build
//! prefix closure of the package under construction.
//!
//! [`build_dep_seeds`](super::build_dep_seeds) drops a seed naming the
//! package itself — the self-host marker. That drop is not enough on its
//! own: a build-dep member's own `requires` walks back to the package
//! under construction (`bison` requires `glibc`, `gawk` requires `glibc`),
//! and the plain walk cannot tell that the package being built is the very
//! payload that edge names. Restoring glibc's `build_deps` without this
//! view therefore refuses with "circular dependency while building
//! 'glibc'" — `bison`'s prefix asks for the glibc payload while glibc is
//! the build in progress.
//!
//! The self-host reasoning is the same one level down: the prefix must not
//! carry the pool copy of the payload the package is about to produce, or
//! the build compiles against pool headers instead of its own tree. So the
//! walk here is host-scoped: [`resolve_walk`](super::resolve_walk) drops an
//! edge naming the host at any depth, and follows every other edge — a
//! member's remaining `requires` still resolve, because bison needs libc to
//! link. Scoping matters: dropping every `requires` edge of a build-dep
//! member would strip bison's own libc and m4.
//!
//! Cycle refusal is NOT re-implemented here. The build lanes already fail a
//! genuine recursion by name from their `building` stack
//! (`ensure_pod_dep_payload`, `ensure_dep_payload`, `ensure_farm_dep_payload`).
//! This view keeps that detector's input intact: only host-named edges
//! disappear, so a cycle among members (`a → b → a`) still reaches the
//! stack whole. An eager refusal here would be wrong, not merely redundant —
//! once glibc declares its build tools, `glibc → bison → glibc` is a real
//! edge pair in any package that pulls glibc, and it resolves because each
//! member's own prefix is walked with that member as the host.

use nau_core::snap_types::SnapMeta;

use super::{build_dep_seeds, resolve_walk_with, DepNode, DepSpec, WalkNode};

/// The host-scoped closure of `meta`: `meta` is the package under
/// construction and never appears in its own result.
fn host_view(
    meta: &SnapMeta,
    load: &dyn Fn(&str, Option<&str>) -> miette::Result<SnapMeta>,
) -> miette::Result<Vec<WalkNode>> {
    let seeds = build_dep_seeds(meta);
    if seeds.is_empty() {
        return Ok(Vec::new());
    }
    resolve_walk_with(&seeds, true, Some(meta.name.as_str()), load)
}

/// The build-prefix closure of `meta`, each member carrying the constraint
/// its edge selected (ADR-0047) — the pod and chart lanes' entry point.
pub fn resolve_build_dep_specs(meta: &SnapMeta) -> miette::Result<Vec<DepSpec>> {
    Ok(host_view(meta, &super::load_meta_for)?
        .into_iter()
        .map(|n| DepSpec {
            name: n.name,
            constraint: n.constraint,
        })
        .collect())
}

/// [`resolve_build_dep_specs`] names only, in build order.
pub fn resolve_build_dep_names(meta: &SnapMeta) -> miette::Result<Vec<String>> {
    Ok(host_view(meta, &super::load_meta_for)?
        .into_iter()
        .map(|n| n.name)
        .collect())
}

/// [`resolve_build_dep_specs`] with each member's resolved edges — the
/// build-order report and the scheduler's dep graph.
pub fn resolve_build_dep_nodes(meta: &SnapMeta) -> miette::Result<Vec<DepNode>> {
    Ok(host_view(meta, &super::load_meta_for)?
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
/// in an in-memory metadata map).
#[cfg(test)]
pub(super) fn resolve_build_dep_names_with(
    meta: &SnapMeta,
    metas: &std::collections::HashMap<String, SnapMeta>,
) -> miette::Result<Vec<String>> {
    let load = |name: &str, _constraint: Option<&str>| match metas.get(name) {
        Some(m) => Ok(m.clone()),
        None => Err(miette::miette!("package '{name}' not found")),
    };
    Ok(host_view(meta, &load)?
        .into_iter()
        .map(|n| n.name)
        .collect())
}
