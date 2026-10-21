//! The build-time dependency view — issues #4, #15, #18.
//!
//! The graph these tests pin is glibc's real one: a package under
//! construction whose build tools declare `requires = { "glibc" }` back at
//! it. Recipes cannot be evaluated under the test harness (the eval worker
//! re-executes `argv[0]`), so the walk runs over an in-memory metadata map
//! through the loader seam in `deps::build_view`.
//!
//! Two rules shape the view:
//!
//!   * it is TWO-LEVEL — the host's direct seeds (`requires` ∪
//!     `build_deps`) plus the runtime-`requires` closure of those seeds;
//!     a member's own build tools ride that member's own view (issue #15).
//!   * the exclusion set is the lane's `building` stack — an edge or a
//!     seed naming a package under construction drops, compared on
//!     CANONICAL names (issue #18).

use super::*;
use crate::deps::build_view::resolve_build_dep_names_with;
use crate::deps::walk::resolve_walk_with;

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
    // (that is the pre-rule shape); the build view never asks.
    metas.insert("glibc".to_string(), host.clone());
    (host, metas)
}

/// The rule: an edge naming a package under construction is dropped, so
/// the host's pool payload never enters its own build prefix. Before this
/// rule the same walk returned glibc itself, and the lane's `building`
/// stack refused with "circular dependency while building 'glibc'".
#[test]
fn edge_back_to_the_package_under_construction_is_dropped() {
    let (host, metas) = glibc_graph();
    let names = resolve_build_dep_names_with(&host, &metas, &[]).unwrap();
    assert!(names.contains(&"bison".to_string()), "closure: {names:?}");
    assert!(!names.contains(&"glibc".to_string()), "closure: {names:?}");
}

/// The drop is scoped to the excluded package alone: a member's other
/// runtime `requires` still resolve, because the member needs them to
/// build (bison links against libc and runs m4).
#[test]
fn member_requires_other_than_the_excluded_package_still_walk() {
    let (host, metas) = glibc_graph();
    let names = resolve_build_dep_names_with(&host, &metas, &[]).unwrap();
    assert!(names.contains(&"m4".to_string()), "closure: {names:?}");
}

/// Issue #15: a member's own build tools do NOT ride the host's view.
/// `bison` declares `build_deps = { "gcc", "make" }`; the host reaches
/// bison as a member, and the host's prefix must not carry bison's build
/// tools — they belong to bison's own build.
#[test]
fn member_build_deps_do_not_reach_the_hosts_view() {
    let (host, metas) = glibc_graph();
    let names = resolve_build_dep_names_with(&host, &metas, &[]).unwrap();
    assert!(!names.contains(&"gcc".to_string()), "closure: {names:?}");
    assert!(!names.contains(&"make".to_string()), "closure: {names:?}");
}

/// The two-level property: bison's build tools ride BISON's own view, not
/// the host's. Every lane recurses per member, so bison's own build gets
/// the compiler and make it declares — and glibc, the package under
/// construction beside it, drops out of bison's view.
#[test]
fn member_build_deps_reach_the_members_own_view() {
    let (_, metas) = glibc_graph();
    let member = metas["bison"].clone();
    let names = resolve_build_dep_names_with(&member, &metas, &["glibc"]).unwrap();
    assert!(names.contains(&"gcc".to_string()), "closure: {names:?}");
    assert!(names.contains(&"make".to_string()), "closure: {names:?}");
    assert!(names.contains(&"m4".to_string()), "closure: {names:?}");
    assert!(!names.contains(&"glibc".to_string()), "closure: {names:?}");
}

/// One level deeper: a transitive member's edge back to the excluded
/// package drops too, and its own subtree still resolves (`readline` →
/// `ncurses`), so the rule works at any depth rather than only on the
/// first ring.
#[test]
fn transitive_member_subtree_survives_the_drop() {
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
    let names = resolve_build_dep_names_with(&host, &metas, &[]).unwrap();
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
    let names: Vec<String> = resolve_walk_with(&seeds, true, &HashSet::new(), Edges::All, &load)
        .unwrap()
        .into_iter()
        .map(|n| n.name)
        .collect();
    assert!(names.contains(&"glibc".to_string()), "closure: {names:?}");
}

/// A cycle among members keeps both members in the view: `a → b → a` names
/// no package under construction, so nothing drops. The view no longer
/// hands the lane the re-entry to detect — the walk's visited set ends the
/// loop — and the lanes' own `building` stack still refuses a genuine
/// recursion when it recurses a → b → a.
#[test]
fn member_cycle_keeps_both_members_in_the_view() {
    let host = seeds_meta("app", &[], &["a"]);
    let mut metas = HashMap::new();
    metas.insert("a".to_string(), seeds_meta("a", &["b"], &[]));
    metas.insert("b".to_string(), seeds_meta("b", &["a"], &[]));
    let names = resolve_build_dep_names_with(&host, &metas, &[]).unwrap();
    assert_eq!(names.len(), 2, "closure: {names:?}");
    assert!(names.contains(&"a".to_string()), "closure: {names:?}");
    assert!(names.contains(&"b".to_string()), "closure: {names:?}");
    assert!(!names.contains(&"app".to_string()), "closure: {names:?}");
}

/// The same cycle, seen from the lane's side: with `a` on the building
/// stack, the edge back to `a` drops and the view stops at the stack
/// boundary — the ancestor's payload does not exist yet, so the member
/// links against whatever libc the toolchain provides.
#[test]
fn member_cycle_is_truncated_at_the_building_stack() {
    let host = seeds_meta("app", &[], &["b"]);
    let mut metas = HashMap::new();
    metas.insert("a".to_string(), seeds_meta("a", &["b"], &[]));
    metas.insert("b".to_string(), seeds_meta("b", &["a"], &[]));
    let names = resolve_build_dep_names_with(&host, &metas, &["a"]).unwrap();
    assert!(names.contains(&"b".to_string()), "closure: {names:?}");
    assert!(!names.contains(&"a".to_string()), "closure: {names:?}");
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
    let names = resolve_build_dep_names_with(&host, &metas, &[]).unwrap();
    assert_eq!(names.len(), 2, "closure: {names:?}");
    assert!(
        names.contains(&"linux-headers".to_string()),
        "closure: {names:?}"
    );
    assert!(names.contains(&"bison".to_string()), "closure: {names:?}");
}

/// Issue #18: the exclusion is the lane's whole `building` stack, not just
/// the package under construction. A member whose edge names an ANCESTOR
/// under construction drops that edge.
#[test]
fn edge_naming_a_package_on_the_building_stack_is_dropped() {
    let host = seeds_meta("app", &[], &["member"]);
    let mut metas = HashMap::new();
    metas.insert(
        "member".to_string(),
        seeds_meta("member", &["ancestor", "kept"], &[]),
    );
    metas.insert("ancestor".to_string(), seeds_meta("ancestor", &[], &[]));
    metas.insert("kept".to_string(), seeds_meta("kept", &[], &[]));
    let names = resolve_build_dep_names_with(&host, &metas, &["ancestor"]).unwrap();
    assert!(names.contains(&"member".to_string()), "closure: {names:?}");
    assert!(names.contains(&"kept".to_string()), "closure: {names:?}");
    assert!(
        !names.contains(&"ancestor".to_string()),
        "closure: {names:?}"
    );
}

/// The exclusion compares CANONICAL names: a member whose edge spells an
/// excluded package through an ALIAS still drops (issue #18). The
/// pre-load check compares the raw edge spelling and cannot see this — the
/// recipe's own name is the authority.
#[test]
fn exclusion_matches_the_canonical_name_not_the_edge_spelling() {
    let host = seeds_meta("app", &[], &["member"]);
    let mut metas = HashMap::new();
    // The edge spells the excluded package by an alias; the recipe's own
    // name — the canonical one — is the authority.
    metas.insert(
        "member".to_string(),
        seeds_meta("member", &["alias-spelling"], &[]),
    );
    metas.insert(
        "alias-spelling".to_string(),
        seeds_meta("canonical-spelling", &[], &[]),
    );
    let names = resolve_build_dep_names_with(&host, &metas, &["canonical-spelling"]).unwrap();
    assert!(names.contains(&"member".to_string()), "closure: {names:?}");
    assert!(
        !names.contains(&"canonical-spelling".to_string()),
        "closure: {names:?}"
    );
}

/// The ancestor case (issue #18): a package's DIRECT SEED naming a package
/// on the building stack drops too. The ancestor's payload does not exist
/// yet — it is the build in progress — so the member links against whatever
/// libc the toolchain provides.
#[test]
fn seed_naming_a_package_on_the_building_stack_is_dropped() {
    let host = seeds_meta("member", &["ancestor", "other"], &[]);
    let mut metas = HashMap::new();
    metas.insert("ancestor".to_string(), seeds_meta("ancestor", &[], &[]));
    metas.insert("other".to_string(), seeds_meta("other", &[], &[]));
    let names = resolve_build_dep_names_with(&host, &metas, &["ancestor"]).unwrap();
    assert!(names.contains(&"other".to_string()), "closure: {names:?}");
    assert!(
        !names.contains(&"ancestor".to_string()),
        "closure: {names:?}"
    );
}

/// The glibc shape (issues #4, #15): glibc's own view carries the build
/// tools it declares (gcc, make, bison, gawk), and a consumer of glibc
/// does not — the consumer's prefix stops at glibc's runtime closure.
#[test]
fn glibc_view_carries_its_build_tools_and_a_consumer_does_not() {
    let glibc = seeds_meta(
        "glibc",
        &["linux-headers"],
        &["gcc", "make", "bison", "gawk"],
    );
    let mut metas = HashMap::new();
    metas.insert("glibc".to_string(), glibc.clone());
    metas.insert(
        "linux-headers".to_string(),
        seeds_meta("linux-headers", &[], &[]),
    );
    metas.insert("gcc".to_string(), seeds_meta("gcc", &["glibc"], &[]));
    metas.insert("make".to_string(), seeds_meta("make", &["glibc"], &[]));
    metas.insert(
        "bison".to_string(),
        seeds_meta("bison", &["glibc", "m4"], &["gcc", "make"]),
    );
    metas.insert("gawk".to_string(), seeds_meta("gawk", &["glibc"], &[]));
    metas.insert("m4".to_string(), seeds_meta("m4", &["glibc"], &[]));
    metas.insert("tmux".to_string(), seeds_meta("tmux", &["glibc"], &[]));

    let glibc_view = resolve_build_dep_names_with(&glibc, &metas, &[]).unwrap();
    for tool in ["gcc", "make", "bison", "gawk"] {
        assert!(
            glibc_view.contains(&tool.to_string()),
            "glibc view: {glibc_view:?}"
        );
    }

    let tmux_view = resolve_build_dep_names_with(&metas["tmux"], &metas, &[]).unwrap();
    assert!(
        tmux_view.contains(&"glibc".to_string()),
        "tmux view: {tmux_view:?}"
    );
    for tool in ["gcc", "make", "bison", "gawk"] {
        assert!(
            !tmux_view.contains(&tool.to_string()),
            "tmux view: {tmux_view:?}"
        );
    }
}

/// A host with an empty seed list resolves to an empty closure — no walk, no
/// error (the lanes' early-out depends on it being harmless).
#[test]
fn empty_seeds_resolve_to_nothing() {
    let host = seeds_meta("standalone", &[], &[]);
    let metas: HashMap<String, SnapMeta> = HashMap::new();
    assert!(resolve_build_dep_names_with(&host, &metas, &[])
        .unwrap()
        .is_empty());
}
