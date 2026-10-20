//! The build-time (host-scoped) dependency view — issue #4.
//!
//! The graph these tests pin is glibc's real one: a package under
//! construction whose build tools declare `requires = { "glibc" }` back at
//! it. Recipes cannot be evaluated under the test harness (the eval worker
//! re-executes `argv[0]`), so the walk runs over an in-memory metadata map
//! through the loader seam in `deps::build_view`.

use super::*;
use crate::deps::build_view::resolve_build_dep_names_with;

/// bison/glibc/m4, the shape 7a7ea70 dodged: `bison` requires the package
/// being built, `m4` requires it too, and `bison` also requires `m4`.
fn glibc_graph() -> (SnapMeta, HashMap<String, SnapMeta>) {
    let host = seeds_meta("glibc", &[], &["bison"]);
    let mut metas = HashMap::new();
    metas.insert(
        "bison".to_string(),
        seeds_meta("bison", &["glibc", "m4"], &["gcc", "make"]),
    );
    metas.insert("m4".to_string(), seeds_meta("m4", &["glibc"], &[]));
    metas.insert("gcc".to_string(), seeds_meta("gcc", &["glibc"], &[]));
    metas.insert("make".to_string(), seeds_meta("make", &["glibc"], &[]));
    // The host's own metadata: the runtime view resolves it as a member
    // (that is the pre-rule shape); the host-scoped view never asks.
    metas.insert("glibc".to_string(), host.clone());
    (host, metas)
}

/// The rule: a build-dep member's `requires` naming the package under
/// construction is dropped, so the host's pool payload never enters its own
/// build prefix. Before this rule the same walk returned glibc itself, and
/// the lane's `building` stack refused with "circular dependency while
/// building 'glibc'".
#[test]
fn host_scoped_walk_drops_the_edge_back_to_the_host() {
    let (host, metas) = glibc_graph();
    let names = resolve_build_dep_names_with(&host, &metas).unwrap();
    assert!(names.contains(&"bison".to_string()), "closure: {names:?}");
    assert!(!names.contains(&"glibc".to_string()), "closure: {names:?}");
}

/// The drop is scoped to the host name alone: a member's other runtime
/// `requires` still resolve, because the member needs them to build (bison
/// links against libc and runs m4).
#[test]
fn member_requires_other_than_the_host_still_walk() {
    let (host, metas) = glibc_graph();
    let names = resolve_build_dep_names_with(&host, &metas).unwrap();
    for expected in ["m4", "gcc", "make"] {
        assert!(names.contains(&expected.to_string()), "closure: {names:?}");
    }
}

/// One level deeper: a transitive member's edge back to the host drops too,
/// and its own subtree still resolves (`readline` → `ncurses`), so the rule
/// works at any depth rather than only on the first ring.
#[test]
fn transitive_member_subtree_survives_the_host_drop() {
    let host = seeds_meta("glibc", &[], &["gawk"]);
    let mut metas = HashMap::new();
    metas.insert(
        "gawk".to_string(),
        seeds_meta("gawk", &["glibc", "readline"], &[]),
    );
    metas.insert(
        "readline".to_string(),
        seeds_meta("readline", &["glibc", "ncurses"], &[]),
    );
    metas.insert(
        "ncurses".to_string(),
        seeds_meta("ncurses", &["glibc"], &[]),
    );
    let names = resolve_build_dep_names_with(&host, &metas).unwrap();
    assert!(
        names.contains(&"readline".to_string()),
        "closure: {names:?}"
    );
    assert!(names.contains(&"ncurses".to_string()), "closure: {names:?}");
    assert!(!names.contains(&"glibc".to_string()), "closure: {names:?}");
}

/// The pre-rule (runtime) view of the same graph, for contrast: the host is
/// a closure member, which is exactly the input that made
/// `ensure_pod_dep_payload` recurse into the payload being built and refuse
/// with "circular dependency while building 'glibc'".
#[test]
fn runtime_view_still_contains_the_host() {
    let (host, metas) = glibc_graph();
    let seeds = build_dep_seeds(&host);
    let load = |name: &str, _c: Option<&str>| match metas.get(name) {
        Some(m) => Ok(m.clone()),
        None => Err(miette::miette!("package '{name}' not found")),
    };
    let names: Vec<String> = resolve_walk_with(&seeds, true, None, &load)
        .unwrap()
        .into_iter()
        .map(|n| n.name)
        .collect();
    assert!(names.contains(&"glibc".to_string()), "closure: {names:?}");
}

/// A genuine cycle among members is untouched by the rule: `a → b → a` is
/// not an edge to the host, so both members still reach the lanes'
/// `building` stack, which refuses them by name. The walk terminates
/// because the visited set breaks the loop — the drop never turns a real
/// cycle into infinite recursion.
#[test]
fn genuine_cycle_among_members_survives_the_drop() {
    let host = seeds_meta("app", &[], &["a"]);
    let mut metas = HashMap::new();
    metas.insert("a".to_string(), seeds_meta("a", &["b"], &[]));
    metas.insert("b".to_string(), seeds_meta("b", &["a"], &[]));
    let names = resolve_build_dep_names_with(&host, &metas).unwrap();
    assert_eq!(names.len(), 2, "closure: {names:?}");
    assert!(names.contains(&"a".to_string()), "closure: {names:?}");
    assert!(names.contains(&"b".to_string()), "closure: {names:?}");
    assert!(!names.contains(&"app".to_string()), "closure: {names:?}");
}

/// A host that also names itself as a dependency (the self-host marker)
/// contributes no seed: the seed-level drop and the walk-level drop agree.
#[test]
fn self_named_seeds_never_reach_the_walk() {
    let host = seeds_meta("glibc", &["glibc", "linux-headers"], &["glibc", "bison"]);
    let mut metas = HashMap::new();
    metas.insert("bison".to_string(), seeds_meta("bison", &["glibc"], &[]));
    metas.insert(
        "linux-headers".to_string(),
        seeds_meta("linux-headers", &[], &[]),
    );
    let names = resolve_build_dep_names_with(&host, &metas).unwrap();
    assert_eq!(names.len(), 2, "closure: {names:?}");
    assert!(
        names.contains(&"linux-headers".to_string()),
        "closure: {names:?}"
    );
    assert!(names.contains(&"bison".to_string()), "closure: {names:?}");
}

/// A host with an empty seed list resolves to an empty closure — no walk, no
/// error (the lanes' early-out depends on it being harmless).
#[test]
fn empty_seeds_resolve_to_nothing() {
    let host = seeds_meta("standalone", &[], &[]);
    let metas: HashMap<String, SnapMeta> = HashMap::new();
    assert!(resolve_build_dep_names_with(&host, &metas)
        .unwrap()
        .is_empty());
}
