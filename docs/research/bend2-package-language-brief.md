# Bend 2 as shuttle's package language — research brief

> **Purpose:** Evaluate what moving shuttle (Rust CLI; Snap packages from Luau
> declarations) to Bend 2 would buy a package manager — package language,
> implementation language, or neither — against primary sources.
> **Question:** "what are the benefits of moving shuttle to bend2, and how can
> it help us build a better package manager?"
> **Sources:** bendlang/bend main branch (`README.md`, `guide/GUIDE.md`,
> `guide/EFFECTS.md`, `WONTFIX.txt`, `CHANGELOG.md`, `LICENSE`, GitHub
> releases API), the Bend 2 launch HN thread (#49746163), and a day-2
> third-party port experiment (AkitaOnRails, 2026-09-19). All bend2 facts
> verified against first-party files fetched 2026-09-24; language is 7 days
> old (v2.0.27), so everything here has a short shelf life.
> **Companion docs:** `docs/adr/0009-package-language-nickel.md` (why the
> language layer is re-examined at all), `docs/adr/0010-package-language-luau.md`
> (current decision), `docs/adr/archive/0002-lua-dsl-as-schema-source-of-truth.md`,
> `docs/lua-dialects.md`, `docs/nix-language-design-lessons.md`.

---

## 1. Verdict

**No migration.** The two hard blockers are first-party documented:

1. **Bend 2 cannot be embedded in a Rust host.** The implementation is
   TypeScript (`bend2/comp.ts`); the only build outputs are a whole-program C
   file (clang-only) or JS. A native library target is explicitly
   "planned, not scheduled" (`WONTFIX.txt`, #813). Shuttle's entire eval model
   — in-process mlua, one JSON line to a re-exec'd worker, structured outputs
   back — has no Bend equivalent.
2. **The toolchain is 7 days old and already shipped a sandbox escape.**
   Bend 2.0.27's changelog documents that until 2026-09-23, `bend` (a Bun
   program) read `bunfig.toml`/`.env` from the project being checked, so a
   malicious package could preload code into bend itself, print a forged
   `All terms check.`, swap hub packages for forgeries, and exfiltrate the
   user's Bender API key on `--publish`. Shuttle's core premise is evaluating
   *untrusted, AI-authored* definitions before the build sandbox — exactly the
   threat that hole lived in.

What Bend 2 genuinely contributes is **ideas, not a migration target**: its
laws/proofs model is the first credible answer to "how do we make AI-authored
package definitions provably honor the manifest contract", and its
termination-by-construction eval is the property ADR-0009 said the language
layer actually needs. §6 lists what to steal without the rewrite, and §7
lists the concrete upstream changes that would reopen the question.

**Decision path:** this brief is a no-op recommendation, so it does not
supersede ADR-0010; it extends its "accepted trade-offs" with bend2 evidence
and hands §7 to ADR-0010's revisit conditions. If §6's law layer is wanted,
that is a new ADR, not this brief.

## 2. What Bend 2 is

Released 2026-09-17 (bend-lang.com; launch HN thread #49746163, 615 points).
Pitch: *"a fast language that blocks AI mistakes via proof: C speed · CUDA
parallelism · Lean proofs · Python syntax"* (README). It is **not an
increment of Bend 1**: bend1 programs don't load; the HVM interaction-net
runtime is gone ("inets live in it architecturally, but they don't exist at
runtime" — Taelin); Bend 2 compiles to a single C file that clang builds for
CPU and Metal/CUDA build for GPU (`GUIDE.md` §Under the Hood). Six releases
landed in the three days before this brief (v2.0.22…v2.0.27,
2026-09-20…09-23, releases API);
launch week cadence was "nine releases in ten hours" (AkitaOnRails).

Language model (`GUIDE.md`):

- **Pure core + IO monad.** Effects are `IO`-typed defs whose bodies are
  foreign `.c` + `.js` imports; Base's own effects (files, sockets, window)
  are built the same way (`EFFECTS.md`). A file with no `main` "just checks";
  a value-returning `main` is normalized and printed.
- **Termination is mandatory.** Structural recursion only — "recursive calls
  must use smaller parts of their inputs"; mutual recursion banned; `@unsafe`
  escapes the guarantee and merely prints a note while exiting 0
  (`WONTFIX.txt` DESIGN #776/#805).
- **Affine quantities instead of GC.** Values are used 0/1/many times by
  kind (`-`/`+`, `Type` vs `Data`); closures callable at most once.
- **Laws and proofs.** `law` states a proposition; a same-named `def` proves
  it; the convention is a human-written `LAWS.bend` plus an AI-written
  `PROOF.bend`, and "`bend PROOF.bend` is the gate". No tactics, no
  inference — "Bend does almost no inference, meaning it requires more
  annotations than similar languages" — which is what keeps checks at ~0.1 s.
- **Dependent types with a consistency caveat.** "One universe and no
  positivity check: `Type : Type` holds"; soundness rests on a live/dead
  checking-mode wall, mechanized in `bend2/bend.lean`, "though it lags
  `bend.ts`" (`GUIDE.md` §Under the Hood).
- **BendHub.** `import <name>@<version>/main.bend` or by content hash;
  `--publish` uploads; publishes are "public and permanent, under BendHub's
  terms"; packages default to MIT-0 without a LICENSE file.

Third-party reality check, day 2 (AkitaOnRails port experiment: three real
Rust projects ported): *"No number here shows Bend faster than Rust on the
same work"*, ~62 s clean builds for ~1 kLOC (clang `-O3` dominates; checking
is 0.1 s), and the honest niche is "a small pure core, with a sharp spec that
tests cover poorly, inside a thin shell of effects". The checker-benchmark
comparison to Lean/Rocq is disputed (Nezk: Bend skips elaboration, unification
and implicit arguments — the phases where those tools spend their time;
Liam Powell: the site claims nowhere "formal verification", and GNATprove
proves the demo game's properties automatically, no hand proofs).

## 3. The evaluation/embedding facts that decide shuttle's case

| Question | Bend 2 answer (source) | Luau today (shuttle) |
|---|---|---|
| Rust library API | None. TS compiler; emits whole-program C/JS only; "native library target for pure defs… planned, not scheduled" (`WONTFIX.txt` #813) | `mlua = "0.10"` vendored, in-process (Cargo.toml:10) |
| Structured results back to host | JS lane: constructors as `{$: "Name", field: value}` (`GUIDE.md`); C lane: runtime-internal `Term` API (`EFFECTS.md`) | Validated table → JSON → typed `SnapMeta` (src/lua.rs:145-167) |
| Untrusted-input isolation | Language purity + checker only. No process isolation shipped; the 2.0.27 bunfig preload incident shows toolchain-level trust holes (CHANGELOG) | Re-exec'd worker, empty-cwd tempdir, RLIMIT AS/CPU/FSIZE/NOFILE, stdlib mask, IPC `require` allowlist (src/isolate.rs) |
| Resource bounds | None in-language; "Allocation failure fail-stops the runtime" (#792) | 5 s wall, 512 MB AS, 384 MB VM cap (isolate.rs:36-60) |
| Native Rust callbacks (e.g. `index()`) | Impossible — no host linkage | Native callback over shipped JSON (isolate.rs:846-859) |
| Determinism | Semantic: pure defs can't touch clock/random; but lazy checker-eval vs strict compiled-lane divergence is WONTFIX (#775) | Enforced by sandbox: `os`/`debug`/`math.random` excised (isolate.rs:683-692, 884-892) |
| Static analysis of definitions | The 0.1 s checker (its one superpower) | Luau strict analyzer + hot-comment pinning (analysis.rs) |

Moving the DSL to Bend 2 therefore means: ship Bun (or clang 14+ per eval) in
the eval worker's TCB, round-trip manifests through JS glue or C-runtime
internals, keep shuttle's whole rlimit/tempdir/IPC isolation layer anyway
(purity is not isolation — see 2.0.27), and lose the native `index()`
callback. Nothing in shuttle's threat model gets easier; the trust base gets
younger.

## 4. Steelman — what Bend 2 would actually give the package language

Recorded because these are the real benefits the question asks about, and
they're not zero:

1. **Termination by construction.** ADR-0009's recorded lesson is that
   "reproducibility is a runtime property, not a language property" and the
   language only needs "deterministic, side-effect-free evaluation with a
   real termination bound". Bend 2 makes that bound a type-check property
   instead of a wall-clock kill. Elegant; but shuttle already has the
   subprocess bound, and `@unsafe` (exit 0, WONTFIX) means it's a *policy*
   guarantee we'd have to enforce by linting the source anyway — the same
   way shuttle already rejects `--!nonstrict` hot-comments (analysis.rs:523-555).
2. **Purity by construction.** No stdlib denylist to maintain, no
   `math.random` to excise, no `os` table to exclude. Genuine maintenance
   win over the sandbox mask — worth maybe a few hundred lines of
   isolate.rs, which is code that already works and has tests.
3. **Laws over manifest contracts.** This is the strongest idea for shuttle.
   Shuttle's premise (ADR-0009) is that definitions will be AI-authored and
   untrusted. Today the manifest contract lives in Rust validators
   (lua.rs:314-402) — the *host* checks, the package author sees nothing.
   Bend's model inverts it: `LAWS.bend` states e.g. "every entry in `inputs`
   carries a content pin", "two outputs never declare the same path", and
   the AI-authored definition ships with machine-checked evidence. The
   failure Akita documented — a mutation that passed a test suite but the
   proof gate rejected — is exactly the guarantee class shuttle wants for
   package definitions. Nothing about it requires *adopting Bend as the
   package language*; the model ports (§6).
4. **BendHub's content-addressed imports** (`import 0x<hash>/main.bend`)
   validate shuttle's existing design (lockfile pins, content hashes,
   ADR-0037's sideload blob pins) rather than improve it — shuttle already
   has all three mechanics, self-hosted, without a third-party terms-of-service.

## 5. What the migration would cost

- **Corpus:** every one of the 112 Luau definitions, `pkgs/lib/`, and
  `src/dsl/init.lua` rewritten in a language with no inference, no `if`
  (match-only), and affine use-counts — the exact "corpus continuity" reason
  ADR-0010 rejected Nickel, multiplied by a far steeper language.
- **Authoring DX:** package manifests are data-heavy; Luau tables + the
  `snap{}`/`merge()`/`require` surface fit that. Bend's constructors,
  quantity annotations (`+` or the value won't reuse), `Map` API that hands
  the map back beside every result, and mandatory per-bind IO annotations
  fight data description. Error messages are precise but the authoring
  burden is real ("more verbose on purpose").
- **Toolchain:** full_moon/selene/StyLua/mlua and the vendored Luau analyzer
  replaced by a Bun/clang dependency chain per eval worker; clang-only
  ("The C compiler is clang only", #773); Windows unsupported (irrelevant to
  shuttle, but the pod/gate images gain a new moving part either way).
- **Ecosystem risk:** 21k GitHub stars are inherited from the Bend 1 repo
  rename; Taelin on launch week: *"there is also my own failure into making
  the language actually be used, rather than just a viral moment"* (HN
  #49747338 context, Akita quoting the Bend 2 thread); compiler is 99%
  AI-written with only the checking kernel human-audited (gihyo interview,
  via Akita); Type:Type consistency rests on a lean formalization that lags
  the implementation. Betting a package manager's language layer on this in
  week one is not a defensible risk.
- **Proving cost:** Base ships almost no lemmas ("We need a mathlib!" —
  Taelin, HN). Porting Akita's experience: 93 lines of laws/proofs to prove
  two facts about a 30-line guard. Manifest-shape laws are cheaper than
  arithmetic laws, but someone still writes the proof — for 112 packages, forever.

## 6. What to steal without migrating

1. **A machine-checkable law layer for package definitions** — the actionable
   outcome. Keep Luau for description; add a `laws` table per package
   (or a `shuttle law` subcommand) whose predicates run over the evaluated
   `SnapMeta` in Rust, with results cached into the lockfile. Same trust
   shape as Bend's gate (evidence travels with the definition), zero new
   TCB. Start with the invariants shuttle already enforces implicitly
   (pinned inputs, output-path disjointness) so authors can state and see
   them per-package.
2. **Termination discipline as lint policy.** A `shuttle lint` rule
   rejecting non-tail unbounded recursion patterns in definitions would be a
   cheap nod toward the same guarantee — optional; the wall-clock bound
   already covers the failure mode.
3. **The 0.1 s check-loop DX.** Bend's real product insight is that
   AI-authored code needs a sub-second gate it can iterate against. Shuttle's
   Luau analyzer is already in that class; keeping check latency a budgeted
   metric is the transferable practice.
4. **Watch BendHub's mechanics** (hash imports, LICENSE-in-hash, publish
   permanence) for the `shuttle index`/store layer's evolution — adopt ideas,
   not the hub.

## 7. Revisit triggers

The answer changes if bend2 lands these (tracked upstream):

- **#813 — native library target for pure defs.** The single blocker for any
  embedding story; until then bend2 cannot live inside shuttle's binary or
  worker.
- A stable, versioned effects ABI (today: "rebuild your effects with every
  update" — no ABI promise, per the guide as quoted by Akita's port notes).
- A lemma library and U64/F64 (both on Akita's "what would change the
  verdict" list), making manifest-law proofs cheap enough for a package corpus.
- Six months of the eval toolchain without a trust incident (the 2.0.27
  bunfig hole reset that clock to zero on 2026-09-23).
- Bend 2.1+: evidence of usage outside demos — the killer-app test bend 1
  failed.

**Alternative reading — implementing shuttle *in* Bend 2:** even less
viable today. The dep-resolver/scheduler core is squarely in Bend's proven-
pure-core niche (Akita's list: "allocators, schedulers, rate limiters"),
but with no library target (#813) the output cannot link into the existing
Rust binary, and the runtime/IO surface a package manager needs (processes,
sandboxing, squashfs) is all foreign effects behind an unstable ABI.

## 8. Sources

First-party (bendlang/bend @ main, fetched 2026-09-24):

- `guide/GUIDE.md` — language model, termination, laws/proofs, IO/effects,
  modules/BendHub, tooling, `Type : Type` caveat. https://github.com/bendlang/bend/blob/main/guide/GUIDE.md
- `WONTFIX.txt` — #813 no library target (planned, not scheduled); #776 `@unsafe`
  exits 0; #775 lazy/strict divergence; #792 allocation fail-stop; #773
  clang-only; #788 Windows unsupported. https://github.com/bendlang/bend/blob/main/WONTFIX.txt
- `CHANGELOG.md` §2.0.27 (2026-09-23) — bunfig/`.env` preload, forged check
  output, Bender-key exfiltration, hub-package swap; fix + ping gate. https://github.com/bendlang/bend/blob/main/CHANGELOG.md
- `guide/EFFECTS.md` — effect ABI is runtime-internal (`io_eff`/`CID`);
  compiler source is `bend2/comp.ts` (+ `bend2/effs/`). https://github.com/bendlang/bend/blob/main/guide/EFFECTS.md
- `LICENSE` — Apache-2.0. GitHub releases API — v2.0.22…v2.0.27, 2026-09-20…09-23.
- `README.md` — positioning ("blocks AI mistakes via proof", post-AGI framing).

Third-party (screened with jev_screen before use; injection prob. ≤0.09):

- HN launch thread #49746163 (615 pts, 326 comments) — author on scheduler
  ("only a very simple scheduler is shipped"), laws underspecification debate,
  adoption admission. https://news.ycombinator.com/item?id=49746163
- AkitaOnRails, "New AI-Focused Language Just Released: Bend 2" (2026-09-19)
  — day-2 port experiment, build/run numbers, effects/ABI findings, ecosystem
  assessment; source of the "nine releases in ten hours", 99%-AI-written
  compiler (gihyo), and "Expect bugs" site-warning quotes. https://akitaonrails.com/en/2026/09/19/new-ai-language-just-released-bend-2/
- Nezk, "Why the benchmarks of Bend's 2 typechecker are misleading" —
  https://gist.github.com/Nezk/dda0511c492cf9bd673885f0341dca0e
- Liam Powell, "Bend 2 and the Vibe-Coding Trap" — https://blog.liampwll.com/posts/bend_vibe_coding/

Shuttle internals: file:line refs as cited in §3-§5 (src/lua.rs, src/isolate.rs,
src/analysis.rs, src/dsl/, Cargo.toml), docs/adr/0009, docs/adr/0010.
