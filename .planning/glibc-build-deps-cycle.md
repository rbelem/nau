# glibc's build tools: the cycle and the rule that has to change

Status: recorded 2026-10-20, with the declaration left off glibc's recipe.
Tracked as issue #18. The recipe comment cannot carry this, because the
content key hashes the recipe's bytes and a comment edit moves the key
and forces a source rebuild of glibc, libgcc, gcc and the toolchain meta.

## What glibc needs

glibc's `configure` demands bison and awk unconditionally. `config.status`
runs awk even when the tarball carries pre-generated parsers, and the build
needs a compiler and make to do anything at all. Every one of those tools
requires glibc back.

## The cycle, measured

With `build_deps = { "gcc", "make", "bison", "gawk" }` declared on glibc,
the toolchain pod's sync refuses:

```
Error: × circular dependency while building 'gawk': toolchain-gcc-gnu-x86_64 → gawk → glibc → libgcc → gawk
```

The chain is the building stack, outermost first: the toolchain meta is the
outer build, glibc and libgcc are in the middle, and gawk is the package
that was already being built when the walk came back to it.

- The toolchain meta's closure reaches gawk through glibc, because glibc's
  own `build_deps` are walked with the runtime closure.
- Building gawk pulls glibc, because `gawk` requires `{ "glibc" }`.
- Building glibc pulls libgcc, because gcc requires libgcc and gcc is one
  of glibc's build tools.
- Building libgcc reaches gawk again, because libgcc's closure goes through
  glibc, and glibc's `build_deps` set contains gawk. libgcc's walk has host
  `libgcc`, so the host-scoped drop does not touch the gawk edge.

gawk was already being built, so the pod refuses.

## Why the host-scoped rule is not enough

Issue #4's rule drops an edge naming the package under construction. It is
scoped to the immediate host of the walk, so it breaks the direct cycle
glibc → gawk → glibc and leaves the one that closes through a sibling
tool.

Widening the exclusion to every package under construction is the obvious
next step, and the building stack is available at every lane that computes
a prefix: `src/pod.rs::pod_build_prefix` holds `building: &mut Vec<String>`,
and `src/build_orch.rs` and `src/farm_prefix.rs` hold their own twins.

Two constraints pull against a naive widening.

**The host's own build tools must survive as members.** glibc's `configure`
needs bison and gawk. If the exclusion were applied to the host's direct
seeds as well as to the recursive expansion, glibc's prefix would lose them
and the source build would fail at configure. The exclusion has to apply to
the recursive expansion and not to the host's direct seeds, which is how the
rule already works: `build_dep_seeds` drops only a seed naming the package
itself, and the walk's drop applies to the edges expanded out of each
visited node.

**An ancestor whose payload does not exist yet has no answer.** libgcc's
closure reaches glibc through `libgcc`'s own `requires`. glibc is an
ancestor and it is being built, so there is no payload to stage. Three
answers, and the repo has to pick one.

- Stage the ancestor's pool payload. This is the classic bootstrap answer:
  the tool links against the already-built glibc rather than the one in
  progress. The pod builds payloads into its own store, so the pool copy
  has to be present and reachable, and the pod has to know which pool
  payload to use.
- Drop the edge. libgcc's prefix carries no glibc and libgcc links against
  whatever libc the toolchain provides. This is what the host-scoped rule
  already does for the immediate host.
- Reuse the ancestor's payload when it is finished. When the ancestor has
  already been built its payload exists and can be staged directly. This
  does not cover the in-progress case, but it removes most of the
  re-entries, and it composes with the widened exclusion.

## The cost of leaving it

Declaring the build tools moves glibc's content key, and with it libgcc's,
gcc's and the toolchain meta's, because the key covers the closure. The pod
then rebuilds all four from source. A glibc source build is about forty
minutes of heavy compile, which is pool-only, and it invalidates a locally
built toolchain.

So the declaration stays off the recipe until the rule is settled. The
resolver half of PR #11 stays too: it is inert without the declaration, and
it is the right shape for the fix that follows.

## What has to be decided

- Which of the three answers the pod lane takes for an ancestor whose
  payload does not exist yet.
- Whether the exclusion set is the building stack, the host's build-dep
  set, or the union. The building stack is the one that matches the pod
  lane's refusal, which is the thing that actually fires.
- Whether the drop compares canonical names. The comparison is made on the
  pre-canonicalization base while alias canonicalization happens
  separately, so a member that names the host through an alias would let
  the pool payload back in. No such edge exists today for glibc.
