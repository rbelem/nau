# glibc's build tools: the cycle and the rule that replaced it

Status: settled 2026-10-20. The rule is implemented; glibc declares its
build tools again. Tracked as issues #18 (the cycle), #4 (glibc cannot be
source-built on a stock host) and #15 (the declaration widens every
consumer's build prefix).

The recipe's bytes feed the content key, so glibc's declaration moves
glibc's content key and, through the closure, libgcc's, gcc's and the
toolchain meta's. That is the intended cost of the fix, not a side effect.

## What glibc needs

glibc's `configure` demands bison and awk unconditionally. `config.status`
runs awk even when the tarball carries pre-generated parsers, and the build
needs a compiler and make to do anything at all. Every one of those tools
requires glibc back.

## The cycle, measured

With `build_deps = { "gcc", "make", "bison", "gawk" }` declared on glibc,
the toolchain pod's sync refused:

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

## The rule: a two-level build view

A package's build view is its DIRECT SEEDS (`requires` ∪ `build_deps`,
minus itself) plus the runtime-`requires` CLOSURE of those seeds. Below the
direct seeds the walk follows `requires` ONLY. A member's own `build_deps`
are not followed into the host's view; they are reached through that
member's OWN view, because every lane already recurses per member.

That is what removes the measured cycle. The toolchain meta's view no
longer reaches gawk THROUGH glibc's build_deps — glibc's build tools are
not part of glibc's runtime closure, so a consumer of glibc never carried
them (issue #15). glibc's own build still does: its build tools are its
direct seeds, and each of them (bison, gawk, gcc, make) is built with its
own view, where glibc itself drops out.

The lanes' own circular detector stays: `building.iter().any(|n| n == name)`
still refuses a genuine recursion by name. The view no longer feeds it a
re-entry; it truncates the cycle at the stack boundary instead.

## The two chosen answers

**An ancestor whose payload does not exist yet: DROP THE EDGE.** The
ancestor is the build in progress, so its payload is not staged; the member
links against whatever libc the toolchain provides. This generalizes the
old host-scoped self-host rule to the whole building stack.

**The exclusion set is the BUILDING STACK.** Every lane already holds
`building: &mut Vec<String>` — the chain of packages under construction —
at the moment it computes a view: `src/pod.rs::pod_build_prefix`,
`src/build_orch.rs::ensure_build_prefix` and
`src/farm_prefix.rs::farm_build_prefix` all receive it, and each lane
pushes the package under construction before computing that package's
view. An edge OR a seed naming a package on the stack drops.

The drop compares CANONICAL names, not the raw edge spelling. The
pre-load check compares the edge's base before the target is loaded, so it
cannot see an alias; a post-load check on the canonical name catches it,
and an alias spelling of an excluded package drops too.

The host's own name joins the exclusion set: the package under
construction supplies its own payload, so an edge back into itself never
walks. The host's own build tools survive, because they are not on the
stack when the host's view is computed.

## The ambient `build-deps` meta

The `build-deps` meta stays the meta chart's OWN seeds. It is not an
ambient floor injected into every package's prefix, and nothing reads it
as one. glibc no longer relies on it: `build_dep_seeds` is exactly
`requires` ∪ `build_deps`, so a package that does not declare its build
tools gets a prefix of its `requires` alone — which is why glibc, whose
`configure` demands bison and awk, has to declare them itself (issue #4).

## What is not proven here

The end-to-end glibc source build is a ~40 minute heavy compile, pool-only,
and no farm worker is provisioned on the development host. The rule is
pinned by unit tests over the resolver; the source build itself is
unproven here and must run on a pool worker before the declaration ships.
