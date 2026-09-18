# Declared pod env: generation-scoped `env = { … }`, resolved at emit

## Status

Accepted (2026-09-18). Resolves the env-var half of the #29 T13 audit
(§5.3 of `docs/t13-cutover-checklist.md`); the `shuttle run` command half
already landed (#102). Grounded in ADR-0016 §7, which reserved `shuttle
run` as "the future home for env hooks", and ADR-0028's activation
contract.

## Context

devbox-global served four login-critical env vars through `devbox.json`'s
`env:` block: `EDITOR`/`VISUAL`, `LOCALE_ARCHIVE`, `PYTHONPATH` +
`VENV_DIR`, and `OPENCODE_EXPERIMENTAL_BACKGROUND_SUBAGENTS`. The cutover
kept them alive as exports in `examples/cutover/90-shuttle.sh` — ambient
shell state outside any pod surface. Pods had no way to declare
environment: `pod.lua` declares packages, overlays, and loads, and the
activation surface (`shuttle pod shellenv`, #47/#89) emits only the two
computed seams, farm-first `PATH` and the loader-lib `LD_LIBRARY_PATH`.

The requirement is devbox `env:` parity: a declared var reaches every
shell that evals the shellenv and every process `shuttle run` execs,
with one env contract — never a second one.

## Decision

1. **Pods declare literal env vars in `pod.lua`:**

   ```lua
   pod {
     packages = { "neovim", "python" },
     env = {
       EDITOR = "vi",
       VENV_DIR = "/home/rodrigo/.local/share/shuttle/python-venv",
     },
   }
   ```

   Values are literal UTF-8 strings — no expansion, no interpolation of
   farm or generation paths. Keys must match `[A-Za-z_][A-Za-z0-9_]*`.
   `PATH` and `LD_LIBRARY_PATH` are rejected at parse: they are the
   pod-computed seams (ADR-0028), and a declared value would silently
   break the farm-first contract.

2. **The resolved env is generation-scoped, like everything else the
   activation surface serves.** Staging a new generation resolves the
   declaration — own env wins per key over loaded pods (the issue #8
   own-over-loaded rule, silent); loaded pods fold transitively,
   first-declared load winning same-key collisions (one stderr warning;
   determinism over surprise) — and records the result as sorted JSON at
   `generations/<n>/env.json`. Validation runs before any write: a bad
   declaration fails the sync with zero writes, like every other
   declared-field failure.

3. **`shuttle pod shellenv` reads the active generation's `env.json` and
   renders one `export KEY='value'` per var** (POSIX single-quote
   escaped, sorted by key), after the `PATH` and `LD_LIBRARY_PATH`
   lines. `--json` carries the map as `vars`. `shuttle run` overlays the
   same map onto the exec'd process, declared value replacing any
   inherited value — the devbox `env:` semantics — through the same
   `PodShellenv` struct #102 already consumes. No second env contract.

4. **Rollback restores the recorded env by construction.** `env.json`
   lives inside the generation; the flip alone re-scopes the vars, and
   rollback never rewrites the file. Re-staging a generation without a
   declared env writes the empty object, withdrawing stale vars — the
   loader-libs re-emit rule.

## Alternatives considered

- **Read `pod.lua` at shellenv time (decl-level, not generation-scoped)
  — rejected.** It would make the read verb parse Lua and walk the loads
  graph on every shell startup, and it would be the only pod surface a
  rollback cannot restore: edit-then-rollback would leave the new env
  live against an old generation. ADR-0028's three hard requirements
  (rollback-survivable, no cross-pod leak, no ambient pollution) are
  satisfied by generation scoping by construction; decl-level reads
  satisfy none of them structurally.
- **Package-level declared env (a `pkg()` `env` block unioned across the
  closure) — deferred, not designed here.** The devbox gap being closed
  is pod-level (`devbox.json` `env:` is pod-level). Package-level env
  needs manifest-surface changes and per-package composition rules;
  filed as a follow-up, not absorbed silently.
- **Line-oriented `KEY=VALUE` record instead of JSON — rejected.**
  Values with `=`, quotes, or shell metacharacters make the format
  ambiguous; sorted JSON parses strictly and fails loudly on corruption,
  which is the trusted-data rule the loader-libs reader already follows.

## Consequences

**Positive**: the four devbox env vars become pod state — declared once,
versioned with the tool set, restored by rollback, gone when the pod is;
`shuttle run` needs no flag to honor them; the login-shell snippet no
longer carries env exports, only init lines (ble.sh, prompt, bindings)
that genuinely belong to the shell.

**Negative**: env edits take effect on the next sync, not immediately —
consistent with every other declared surface (packages, fonts,
launchers), but a change from the devbox init-hook, which re-exported on
every shell start. Values are literal: a value that must reference the
pod root has to be written out in full. `LOCALE_ARCHIVE` is declarable
but not auto-generated — the system-locales-vs-pod-locale-payload
decision stays open (checklist §5.3).

## Revisit triggers

- Package-level env lands → extend the resolution order (package env
  beneath pod env, own-over-loaded unchanged).
- A var must reference pod-computed paths → design an explicit
  interpolation vocabulary; do not grow one implicitly.
- A var needs to differ per confinement level → move resolution into the
  `shuttle run` assembly (ADR-0016 §7 hooks).

## Evidence

- Unit gates: `devbox run -- test` (full suite green, including the
  eleven new `pod::`/`confine::` tests: parse + reserved-seam rejection,
  own-over-loaded and first-declared-wins fold, standalone cycle
  detection, staging records/withdraws the env object, shellenv serves
  the recorded env and the flip alone restores it, corrupt `env.json`
  fails loudly, `set -u`-eval-safe render with a value containing
  quotes/`$`/spaces/empty, overlay replaces inherited values), clippy
  `-D warnings` clean, fmt-check clean.
- Live proof (2026-09-18, redirected root `/tmp/opencode/adr30-proof`):
  a `proof` pod declaring `jq` plus `EDITOR`/`GREETING`/`EMPTY` (value:
  `it's $fine, 'quoted' with spaces`) syncs green through the
  jq/glibc/linux-headers pool chain; `generations/1/env.json` holds the
  three keys sorted and literal; `eval "$(shuttle pod shellenv)"` under
  `set -u` round-trips every value (the empty one stays set-but-empty)
  and `jq` resolves from the farm; `shuttle run --pod proof -- sh -c …`
  under `env -i` sees the same env; adding `BETA` + `tree` stages a new
  generation whose `env.json` carries `BETA`, and `pod rollback 1`
  withdraws `BETA` while keeping `EDITOR` — the recorded-env flip
  semantics, proven live. Transcript: `/tmp/opencode/adr30-proof/run-proof.sh`
  (exits 0: `ALL GATES GREEN`).
- Dogfood finding from the same session (filed, not absorbed): a
  loads-only pod with a stale own pin in its lockfile re-syncs by
  rebuilding the closure cold; tracked as its own issue.
