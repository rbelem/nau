# The pod loader path: shellenv `LD_LIBRARY_PATH` entries threaded through the `current` link

## Status

Accepted (2026-09-14). Resolves the one code-level cutover blocker left by the
#29 T13 audit (§5.7 of `docs/t13-cutover-checklist.md`). Grounded in issue #89.

## Context

Packages whose binaries link against libraries from their own requires closure
(git → libpcre2/libz/libssl/libcurl; tmux → libncursesw/libevent; htop, tig —
the same family) install those libs **per generation**, under
`generations/<n>/extensions/<pkg>/usr/usr/lib` (the `usr/usr` doubling is the
sysext tree root plus the payload's `/usr` prefix; the glibc/libgcc/libstdcpp
toolchain layout lands at `usr/usr/lib64`). The #29 audit proved the layout is
correct — exporting `LD_LIBRARY_PATH` over those dirs by hand makes every one
of the four tools run — but nothing on the host puts them on the dynamic
loader path. Farm entries are direct store symlinks (the issue #3 hard rule:
no shims, no wrappers), `$ORIGIN`/RUNPATH point into per-package assemblies,
not across packages, so an unconfined farm binary simply fails at the loader
stage as linked.

The seam has three hard requirements: it must survive rollback (a dead
generation's lib dir must never stay on the path), it must not leak across
pods, and it must not pollute the ambient environment beyond the pod's own
activation surface.

## Decision

1. **The seam lives in the pod's own activation surface — the #47 shellenv —
   as a generation-scoped `LD_LIBRARY_PATH`, threaded through the `current`
   link.** `farm::emit` records the generation's loader-lib dirs into
   `generations/<n>/loader-libs` (one generation-relative dir per line,
   `extensions/<pkg>/usr/usr/lib` or `usr/usr/lib64`, higher composition
   layer first, name ascending within a layer; only dirs that exist in the
   freshly staged tree). `pod::shellenv` reads that list and `render_shellenv`
   emits, per pod with lib payloads:

   ```sh
   export PATH="<root>/<pod>/current:$PATH"
   export LD_LIBRARY_PATH="<root>/<pod>/current/../extensions/tmux-deps/usr/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
   ```

   The load-bearing trick is `current/../`: `current` is a symlink to
   `generations/<n>/farm`, so the entry resolves — at every exec/dlopen,
   under plain kernel path resolution — to `generations/<n>/extensions/...`.
   An already-eval'd shell needs no re-eval after a rollback: the flip alone
   re-scopes every entry to the target generation, and a package the target
   generation lacks becomes unreachable through the seam (a dangling
   `LD_LIBRARY_PATH` element is silently ignored by glibc, exactly like a
   PATH entry pointing at a removed dir). Proven by probe before
   implementation: dlopen through `current/../extensions/...` finds a lib in
   the pointed-to generation, loses it on flip-away, and finds it again on
   flip-back.

2. **Rollback clears the seam two ways, both automatic.** (a) The env entries
   resolve through the link, so the flip re-targets them (above). (b) The
   list file itself is re-written by the emit that every activation path runs
   (`pod sync` tail and `rollback_pod` both call `farm::emit` +
   `flip_current`), including the empty case — a re-emit of a lib-less
   generation withdraws the stale list, so a shellenv eval'd after the
   rollback exports nothing. GC drops the file with the generation: it lives
   inside the generation directory, like the farm and launchers.

3. **Layer precedence follows the farm's.** `LD_LIBRARY_PATH` is a
   first-match search, so the recorded order is `layered_packages` reversed
   (Overlay > Own > Loaded): an overlay's library shadows a loaded pod's
   same-soname library, the same precedence the farm's shared-name overwrite
   encodes.

4. **Eval safety is exact.** The export uses the `${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}`
   idiom (the pool's own build-script convention): safe under `set -u`, and
   never a trailing empty element — which the loader would read as the
   current working directory. A pod whose generation ships no lib dirs (the
   common statically-linked case) emits no `LD_LIBRARY_PATH` line at all, and
   a pre-#89 generation (no `loader-libs` file) degrades to the unchanged #47
   PATH-only export. `--json` carries the list as `libs` (omitted when
   empty).

5. **Alternatives rejected, with reasons:**
   - *Launcher contract (the issue's preferred option) — insufficient for
     this closure shape.* The per-app launcher pattern (go.lua's GOROOT
     launchers) resolves siblings relative to `$0`, which works because the
     needed trees ship INSIDE the launcher's own package. git/tmux/htop's
     libraries ship in OTHER packages' extension trees; a launcher would
     have to locate `<gen>/extensions/*` from `$0`, and for a single-binary
     app the farm link's `readlink -f` lands in the content STORE, which has
     no generation context at all — the pattern cannot reach cross-package
     lib dirs without breaking the issue #3 no-wrapper rule for unconfined
     apps or retrofitting every requires-closure recipe with duplicated
     discovery logic. The mechanism stays the right tool for same-package
     payload resolution; it is the wrong layer for cross-package closure.
   - *Staged RPATH — fights the content address.* The libs live in sibling
     packages' trees, so the RPATH must name a pod- and generation-specific
     absolute path; baking that into a shared store blob would fork
     content-addressed binaries per pod and strand them on rollback. An
     `$ORIGIN`-relative RPATH resolves to the farm/store dir, which contains
     no libs. Patching binaries at emit would mean per-generation copies —
     the assembly machinery exists for multi-file payloads and must not
     become a general ELF rewriter.
   - *`ld.so.conf.d` drop under the pod surface — ambient pollution.* A
     conf.d fragment (plus the required `ldconfig` run) puts the pod's libs
     on EVERY process's loader path on the host, needs root for the system
     cache, and leaks across pods. Directly violates two of the three
     requirements; not considered further.

## Consequences

**Positive**: `pod add git`/`tmux`/`htop`/`tig` work with nothing but
`eval "$(shuttle pod shellenv)"` — the same one-line activation as every
other pod tool; rollback is honored by construction (link flip + re-emit)
rather than by cleanup code; pods without dynamic closure pay nothing (no
line, no file beyond an empty one); no state outside the pod directory is
ever read or written.

**Negative**: `LD_LIBRARY_PATH` is per-shell state, so non-shell activation
consumers do not get it — desktop launchers (issue #7) exec the farm path
directly and keep relying on per-package assembly (`$ORIGIN`-beside) or
self-contained payloads; a GUI app needing cross-package libs is future work
(likely a `shuttle run` env hook, ADR-0016 §7). The recorded list is a
convention scan (`usr/usr/lib`, `usr/usr/lib64`), not a per-file manifest —
a pool package shipping shared objects somewhere else would need the
convention extended (the pool ships flat today; both shapes exist in the
pilot). Binaries dynamically linked against HOST paths outside any pod
(`RUNPATH=/shuttle-build-prefix/usr/lib` — the recorded #22 leak-scan
escapes) are unaffected by this seam, by design.

**Revisit triggers**: GUI/desktop activation needs cross-package libs (the
`shuttle run` env hook); a pool package grows multiarch libdirs
(`usr/usr/lib/<triplet>`) — extend `LOADER_LIB_SUBDIRS`; the launcher
contract gains a generation-context channel (making per-package launchers
closure-aware without wrappers).

## Evidence

- #29 audit (§5.7): `LD_LIBRARY_PATH` over the generation's extension lib
  dirs makes git 2.47.1, tmux 3.5a, tig 2.6.1, htop 3.5.3 run — the layout
  was right, only the seam was missing.
- Path-resolution probe (pre-implementation): dlopen with
  `LD_LIBRARY_PATH=<pod>/current/../extensions/<pkg>/usr/usr/lib` resolves
  through the link; the flip redirects it without re-eval; the dead
  generation's dir becomes unreachable.
- Unit tests: `farm::tests::emit_records_loader_lib_dirs_higher_layer_first`,
  `farm::tests::reemit_withdraws_a_stale_loader_lib_list`,
  `farm::tests::loader_lib_lists_never_bleed_across_generations`,
  `pod::tests::test_shellenv_lib_dirs_thread_through_the_current_link`,
  `pod::tests::test_shellenv_without_a_loader_lib_list_exports_none`,
  `pod::tests::test_render_shellenv_is_eval_safe_under_nounset` (evals the
  rendered script under `set -u` with the variable unset, set, and empty).
- Live check (issue #89 acceptance, redirected root): `pod add tmux`, eval
  the shellenv, `tmux -V` runs with no manual `LD_LIBRARY_PATH`; rollback
  withdraws the export. Transcribed in the issue-89 branch report.
