# Council report: same-package-different-version conflict handling

Council session 2026-09-27 (four seats + synthesis). Input evidence:
`docs/research/package-version-conflicts.md` (external survey), the local
conflict model (build prefix, farm, manifest), and three live WIP recipes in
the working tree at session time (`node22.lua`, `toolchain-gcc-gnu-x86_64.lua`,
`valkey-search.lua`). Companion policy deliverable: ADR-0043 (ticket T1
below drafts it; nothing here ratifies policy — the ADR does).

## Question

How should shuttle handle conflicts of the same package at different versions
on the same system or in the same pod, at the build level (merged prefix) and
the pod runtime level (manifest, farm, loader wrappers)?

## Verdict (one line)

Coexistence is a payload-naming discipline, never a merge mechanism: the
build prefix stays fail-closed, the pod manifest stays keyed by name, the
loader's per-app closure list becomes authoritative, and every same-path /
different-content case is resolved by renaming, splitting, or ownership
repair at the recipe level.

## Rulings at a glance (details in the decisions table)

1. Build prefix: fail-closed unchanged; `conflict()` gains complete-set,
   per-class remedies (T2); preflight before the build (T3); one toolchain
   per prefix.
2. Binutils: ownership restored — gcc keeps the triplet namespace, pool
   binutils owns plain names (T4, three pre-gates, flip contingency).
3. Pod: one version per name per pod permanently; suffixed package =
   sanctioned coexistence; `@constraint` selects within a line only (T7).
4. Loader: per-app closure-scoped wrapper lists (T5), then within-closure
   soname gate + cross-closure warn (T6); RUNPATH advisory, wrapper
   authoritative.
5. Never build: priority, slots, instance keys, manifest rekey, sub-
   prefixes, shims, soname registry, include-precedence machinery.

## Decisions table

| Sub-question | Consensus decision | Vote | Dissent note |
|---|---|---|---|
| **Q1 build prefix** | Keep the hard error and zero merge semantics. Enrich `conflict()` to report the complete conflicting-path set, classified by path class with a per-class remedy (`usr/bin/*` → require the owner or vendor behind shims; `usr/include/c++/*` → one-toolchain-per-build, `-idirafter` is recipe debt; `usr/lib/lib*.so*` → soname twin handled at farm emit; dir-vs-file → shape bug). Add a plan-time preflight: the full conflict set is computable from signed file-hash manifests before any build runs. Binutils case = payload ownership bug: de-hack gcc, restore `binutils` to toolchain requires. Valkey-search = gcc driver-config repair (baked absolute gxx-include dir dead in sandbox) + upstream missing-`<mutex>` fix; no include-precedence machinery. New rule: **one compiler toolchain per build prefix**. | 4/4 fail-closed + diagnostics + valkey; 3/1 on de-hack/restore | Delta ratifies the vendor-drop as already-correct, wants diagnostics only. Overruled: `pkgs/b/binutils.lua` already negotiates the namespace (drops triplet names because gcc's deb set owns them); the status quo violates the negotiation. Delta's skepticism survives as T4's pre-gates. |
| **Q2 pod runtime** | Never rekey the manifest. One version per package name per pod is a permanent invariant. Sanctioned story, three axes: store coexistence free → same system different versions = different pods → same-pod parallel lines = **suffixed package** (suffixed name + suffixed apps + relocated internal trees + never restage counterpart-owned build trees). `name@constraint` = which-version-of-one-name, never a coexistence mechanism. `@` is the constraint sigil (`parse_pod_package`), so `node@22` as a name is impossible — `node22` is forced; record in the ADR. | 4/4 | None. |
| **Q3 library interleaving** | Per-app closure-scoped LD lists: each wrapper's lib-dir list is the owning package's transitive requires closure (full walk — DT_RUNPATH non-transitive), layer-first preserved within the closure, prepend-don't-replace (#89) kept. Hard error on same-soname/different-content within one closure at mutation/activation, zero-write, message shaped like the build-prefix `conflict()`; byte-identical → silent dedup; across disjoint closures → warn via `warn_emit_collision("soname", ...)`. Document: "RUNPATH is advisory; the wrapper's closure list is authoritative." Recipe norms: SONAME matches filename; ABI break = soname bump. Lands as ADR-0028/0034 addenda. | 3/1 | Delta keeps the generation-wide list + emit-time warn, deferring narrowing. Overruled: delta's objection targets per-package lists; closure ⊇ own package answers it, and delta's own D6 argument (the loader first-matches sonames silently — no warning channel) is the strongest pro-majority evidence. Delta's emit-warn and doctor report retained verbatim. |
| **Q4 what NOT to build** | Unified reject list: Nix-style priority in the merged prefix (loud failure → silently wrong toolchain; Nix itself aborts unprioritized); **the word "priority" stays reserved** — `ClaimLayer` means composition precedence; Gentoo SLOTs/sub-slots; manifest rekey / same-name multiplicity; snapd instance keys in a pod; update-alternatives / shims / env-per-selection / per-cwd dispatch (ADR-0015 D7 re-rejection); grafts; virtual-provides + versioned-provides solver beyond `@constraint`; automatic payload relocation / generation-time patchelf of blobs (violates content addressing); per-package or per-version sub-prefixes (breaks `PKG_CONFIG_SYSROOT_DIR` one-root + toolchain `cp -a` sysroot contracts); soname/ABI registry; `ld.so.conf.d` host registration; runtime farm dispatch wrappers; check_deps/host_deps splits; include-precedence machinery. Scoped exception: ADR-0003 multi-output stays usable case-by-case (contingency for T4), rejected only as a general coexistence mechanism. | 4/4 on the union | Alpha-vs-beta tension on multi-output resolved by scoping. |

## Adjudications

1. **Binutils disposition (3–1).** Restore `binutils` to toolchain requires;
   gcc stages only the triplet namespace + drivers; plain names owned by pool
   binutils (gamma's command-name ownership rule: *each PATH-visible command
   name, like each shared subtree, has exactly one owning payload in a
   merge*). Default implementation: beta's — drop plain-name staging, move
   LD-fixing to the #12 portability pass or launcher env (precedented at
   `toolchain-gcc-gnu-x86_64.lua` launcher). Contingency: alpha's ADR-0003
   multi-output split, only if the shim layer must survive (#171 libbfd) and
   both namespaces must ship from one recipe. Delta's ratify-in-place is
   rejected as policy but preserved as the gate: if verification shows the
   Debian 2.44-3 pairing is load-bearing, flip ownership to the Debian set
   (documented) instead of adding mechanism.
2. **Q3 scope (3–1).** Majority carries; delta's instruments retained
   (emit-warn, doctor report, deferral trigger inverted into the ADR-review
   criterion). Caveat: the within-closure hard error will fire on known
   benign twins (byte-different `libgcc_s.so` across gcc and libstdcpp
   payloads), so the gate lands paired with ownership assignment of those
   twins.
3. **gcc fix vehicle.** Gamma's ownership rule is the policy; beta's
   #12/launcher-env route is the default implementation; alpha's multi-output
   split is the shim-must-survive fallback.

## Unified ticket plan

Dependency graph: T1 → {T2, T4, T5, T7}; T2 → T3; T5 → T6. After T1, T2 ∥
T4 ∥ T5 ∥ T7.

| # | Ticket | Scope | Files | Verification gate |
|---|---|---|---|---|
| T1 | ADR-0043 + ADR-0015 addendum + glossary | Full policy layer; three-axis story; reject list; vocabulary traps (never "global", never "slot"/"instance"/"variant"/"channel"/"alternative"; "priority" reserved); `@`-sigil note; rekey blast radius | `docs/adr/0043-*.md`, ADR-0015/0018 addenda, `CONTEXT.md` | Doc review; lands first |
| T2 | `conflict()` path-class diagnostics | Complete conflicting-path set; per-class remedy; owning payload named | `src/build_prefix.rs` + tests | Unit tests per path class (incl. dir-vs-file, multi-conflict single report); `bash scripts/gate.sh` |
| T3 | Plan-time preflight | Full conflict set from signed file-hash manifests at dependency resolution, before any build | plan/resolve site | Multi-conflict reported in one pass pre-build; gate |
| T4 | gcc/binutils ownership de-hack + valkey repair | gcc drops plain-name staging (keeps triplet + drivers); toolchain restores `binutils`; LD-fix → #12 pass / launcher env; repair gcc's baked gxx-include path; retire valkey `-idirafter`; ADR-0018 addendum #2 | `pkgs/g/gcc.lua`, `pkgs/t/toolchain-gcc-gnu-x86_64.lua`, `pkgs/b/binutils.lua` (verify), #12 portability site | Pre-gates: pool binutils standalone-good re #171; triplet names not equally fragile; Debian 2.44-3 pairing check. Gate: toolchain probe build + valkey-search rebuild + `bash scripts/gate.sh` |
| T5 | Per-app closure-scoped LD wrapper lists | Wrapper lib list = transitive requires closure (layer-first within closure; #89 prepend kept); loader-libs stays diagnostic; rollback re-emit from recorded data | `src/farm.rs`, `src/pod.rs` | Regression: same-layer two packages, same soname, different content → alphabetically-later owner's app must not bind the earlier copy; disjoint closures → no interference; rollback re-emit test; gate |
| T6 | Soname collision gate + emit warn | Within-closure same-soname/different-content → hard error before writes, `conflict()`-shaped; byte-identical → dedup; cross-closure → warn; pre-#8 manifests degrade to warn; SONAME norms into recipe docs | pod sync/mutation, `src/farm.rs` emit, doctor | Within-closure twin → named error; dedup; digest-less → warn; **libgcc_s twin case exercised**; gate. **Depends on T5** |
| T7 | Suffixed-package lint + doctor + docs | Eval lint (`<base><N>` declaring app `<base>` warns); doctor: co-installable pairs, classifier guidance, runtime-only-not-build_deps; node22.lua promoted to reference recipe | eval/lint site, doctor, `pkgs/n/node22.lua`, docs | Lint unit test on the node22 `include/` bug class; docs review; gate |

## Risk register

| # | Risk | Mitigation |
|---|---|---|
| R1 | #171 libbfd shim necessity — plain-name LD-fixing shims may be load-bearing | T4 pre-gates; fallbacks: ownership flip (R2) or multi-output split (R7) |
| R2 | Debian binutils 2.44-3 ↔ gcc pairing load-bearing | Pre-authorized contingency in ADR-0043: flip ownership to the Debian set; human sign-off (open item 1) |
| R3 | Per-file digest availability — `InstalledPackage.files` is names only | Pick cheaper: staged-tree compare at sync vs manifest extension; pre-#8 manifests degrade to warn |
| R4 | ADR-0028/0034 amendment review — narrowing a ratified generation-wide export scope | Land as addenda; delta's deferral trigger inverted into the review criterion |
| R5 | Soname-gate false positives — ABI-compatible same-soname twins (`libgcc_s`) hard-error inside a toolchain closure | Pair T6 with payload ownership assignment for the known twins; exercise in T6 tests |
| R6 | `InstalledPackage.requires` completeness for the closure walk + rollback re-emit | Verify against existing manifests in T5; rollback re-emit test required |
| R7 | Multi-output contingency installability | If ADR-0003 outputs are not independently installable, separate package file, same shape |
| R8 | `-idirafter` debt window — valkey hack stays until gcc's gxx-include repair lands | Log as explicit debt against T4; upstream report is open item 5 |
| R9 | Councillor file/line citations not independently re-read by the council | Folded into T2/T4 verification gates rather than trusted |

## Open items only the human can decide

1. **R2 flip authorization** — pre-authorize the Debian-set ownership flip in
   ADR-0043, or require a return to council if the pairing check fires.
   (Blocks only T4's contingency branch; T4 can start.)
2. **Delta's Q3 dissent** — accept the ADR-0034 amendment with the
   inverted-trigger review criterion, or adopt delta's defer-narrowing
   posture. (T1 documents either; blocks T5/T6 landing order.)
3. **Multi-output fallback scope** — ratify the contingency-only use of
   ADR-0003 multi-output. (Non-blocking; needed only if R1/R2 fire.)
4. **`libgcc_s` owner assignment** — which payload (gcc or libstdcpp) owns
   the canonical copy. (Blocks T6's toolchain test case only.)
5. **Upstream valkey-search report** — file the missing-`<mutex>` issue
   upstream (delta's root-cause finding) as an external action.

## Per-seat contributions

- **alpha**: multi-output machinery as the fix vehicle (demoted to
  contingency); "sound-by-luck" framing of the wrapper list; conflict()
  enrichment naming sanctioned fixes.
- **beta**: gcc vendoring = the #174 addendum's forbidden move extended to
  whole files; the no-shared-soname invariant already does not hold
  (`libgcc_s` twins); complete-conflict-set reporting; plan-time preflight;
  three-axis story; `@`-sigil makes `node@22` impossible.
- **gamma**: command-name ownership rule generalized from the existing
  binutils/gcc namespace negotiation; named the arbitrary-binding failure
  shape (layer-first then name-ascending); the three hard facts against
  RUNPATH/$ORIGIN; "RUNPATH is advisory" documentation line.
- **delta**: the real problem is undiscoverable knowledge — make `conflict()`
  classify and teach; the loader-silence argument (farm warns binaries,
  loader first-matches sonames silently — any design admitting two
  same-soname payloads makes incidental ordering load-bearing, contradicting
  D6); "priority" stays reserved; valkey's root cause is an upstream missing
  include. Outvoted 3–1 twice, structurally influential throughout.
