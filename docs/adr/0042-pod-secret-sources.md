# ADR-0042: Pod secret sources

Status: Accepted (2026-09-26). Four-seat council review the same day:
unanimous accept-with-changes; every council-required change is
incorporated below. One mechanism the council left split was resolved
by the ratification run, not by council consensus: the services
rotation mechanism is the refresh verb (Decision 3), not the
envfile-digest-into-unit_hash option two seats had leaned toward — the
rationale is recorded in Alternatives. The decisive council findings
that would otherwise have made D3 false as originally drafted were the
services rotation mechanism itself and the reboot story. Input: the
2026-09-24 grill proposal
(`.planning/grill-input-2026-09-24-pod-secrets.md`) and its landscape
survey (`.planning/research/secret-manager-survey-2026-09-24.md`). The
draft ADR number in those documents (0040) was taken by the distributed
build workers ADR in the meantime; this ADR renumbers to 0042.
Ratification ran under the operator's overnight autonomy grant
(recorded on #181); any decision here can be reversed by a superseding
ADR in the normal way.

## Context

Pods need credentials (tokens, keys) that must not live in `env`
literals: `pod.lua` is checked in, sync records env values into the
generation tree at rest, and rotation would churn generations. Today the
operator bootstraps such values outside shuttle (devbox-global's
`setup-bws` pipeline: token in libsecret, `bws` fetch at shell start,
tmpfs cache) and pastes them into `env` by hand or exports them ad hoc.

The seams for a declared surface already exist. `PodDeclaration` carries
`env` with a full contract (ADR-0030): validation, reserved names, fold
rules (own-over-loaded per key, first-declared load wins across loads),
and one consumers' side every exec form already reads. Consumers are
`pod shellenv`, the `shuttle run` overlay, and service units
(`Environment=` lines). Nothing secret exists in the codebase today.
Host-side fetch is sanctioned outside the offline build sandbox
(ADR-0039 Decision 5), and `run` forms are unsandboxed by design while
confined apps gate network on a boolean grant, so a host-side fetch adds
no isolation surface.

## Decision

Pods declare **secret references**; generations pin references, never
values; values resolve at serve time from built-in providers and reach
consumers through the existing env contract.

1. **Sibling declared surface, not interpolation (D1).** A new `secrets`
   table on `pod`, shaped per key:
   `KEY = { source = "...", <per-source fields> }`. `env` stays literal
   and ADR-0030 is untouched; this answers ADR-0030's interpolation
   revisit trigger by declining to interpolate. A key present in both
   `env` and `secrets` refuses at parse with a named error. Reserved
   names (`PATH`, `LD_LIBRARY_PATH`) are rejected for secrets too.
   Unknown per-source fields are rejected fail-closed (the
   `src/snap.rs` unknown-field precedent); deep per-source validation
   lives in Rust at the boundary (ADR-0014).
2. **Generations record references only (D2).** Sync validates the
   declaration (schema, known source, per-source field shape) and writes
   the folded reference set as sorted canonical JSON at
   `generations/<n>/secrets.json`, mode 0600 (stricter than
   `env.json`; these are live credential destinations), in the staging
   tail after env. Fold rules match env for precedence (own-over-loaded
   per key) with one deliberate tightening: a secret-key collision
   across loads is a **hard error**, not a warning. Env literals warn
   because they are inert; a losing credential reference silently
   changes live credentials under masking. Note the transitive fold
   gives loads a trust edge env never had: a loaded pod's `exec`
   references run at the loader's serve time with the loader's
   credentials in reach. Declare loads accordingly.
   Rollback re-scopes the live reference set by construction and
   deliberately does not resurrect old values: recorded-value restore
   would resurrect rotated credentials (contrast env literals, which are
   generation-recorded because they cannot rotate).
   **The lockfile gains no secrets section**: references come from the
   declaration, values are never pinned, and rotation never writes
   `shuttle.lock`. (`src/lock.rs` calls the lockfile "the pin record"
   and ADR-0030 env is generation-recorded; this sentence exists so the
   lockfile expectation is not read onto secrets.)
3. **Resolve at serve time; session cache on tmpfs (D3).** One resolve
   entry point serves all three consumers: `pod shellenv` (exports after
   the env lines), `shuttle run` (overlay, declared replaces inherited,
   same rule as env), and services (units reference a 0600
   `EnvironmentFile=`). Sync never resolves: it validates shape only,
   so sync keeps no network dependency and works without credentials.
   Values cache at `$XDG_RUNTIME_DIR/shuttle/secrets/<pod>/<decl-hash>.json`
   (0600, tmpfs, dies at reboot), written atomically (temp + rename).
   The key drops the generation component on purpose: a rollback to an
   old generation must not serve that generation's pre-rotation cached
   value. `decl-hash` is the SHA-256 of the folded canonical reference
   JSON (the `secrets.json` bytes), so any reference change is a fresh
   fetch. Refresh and sync prune cache entries whose generation is no
   longer active; `pod remove` prunes the pod's subtree. First resolve
   per session pays the fetch; the rest are hits (the devbox-secrets
   pattern). Nothing secret is written under the pod root, and
   specifically the envfile lives in this tmpfs tree, never under
   `generations/<n>/` (ADR-0032's emit-into-generation norm must not be
   read onto it). Rotation is `pod secrets refresh` or cache expiry at
   reboot; no new generation.

   **Services rotation contract.** The `EnvironmentFile=` indirection
   removes values from the unit text, so ADR-0032's unit-hash
   diff-and-restart never sees a rotation (the hash covers rendered
   unit text plus package digest only). The mechanism is the refresh
   verb instead: `pod secrets refresh` rewrites the envfile and
   restarts the pod's secret-consuming units whose envfile digest
   changed. The unit text stays value-free and the unit hash stays
   package-only; there is deliberately no second write path into the
   services reconcile. The envfile is rendered without the `-` prefix:
   a missing file fails the unit start and names the path (fail loud),
   never silently starts without secrets.

   **Boot story.** The tmpfs tree dies at reboot and the systemd user
   manager holds no provider credentials, so no boot-time helper can
   fetch. Secret-bearing services therefore start failed after a reboot
   until a login-side `pod secrets refresh` (or sync-triggered resolve)
   materializes the envfile; then `systemctl --user start` (or the next
   reconcile) brings them up. The operator's login init-hook is the
   natural place for the refresh. This is an accepted cost of
   values-never-at-rest.

   **Isolation interaction.** At `sandbox`/`machine` levels
   (ADR-0038), the boundary is `env_clear()` plus explicit re-injection
   of the declared overlay. Resolved secret values ride that declared
   re-injection path; they are never inherited ambient env. Provider
   credentials (`BWS_ACCESS_TOKEN`, `VAULT_TOKEN`, and friends) are
   deliberately NOT re-injected into any boundary. Resolution is
   host-side only: an invocation already inside a boundary (ephemeral
   shell, nested `shuttle run`) serves from the session cache if
   present and fails loud naming the isolation level otherwise.

4. **Built-in provider registry, minimal v1 (D4).** Compiled-in registry
   (ADR-0014 shape), deep validation in Rust, grow by demand:

   | source | ref fields | fetch | auth (caller env) |
   |---|---|---|---|
   | `bitwarden` | `id` | shell out to `bws secret get <id>`, read `.value` | `BWS_ACCESS_TOKEN` |
   | `vault` | `mount`, `path`, `field` | KV v2 REST `GET /v1/{mount}/data/{path}` (OpenBao identical; crate vs raw REST decided at implementation, raw-REST lean) | `VAULT_ADDR` + `VAULT_TOKEN` |
   | `libsecret` | `attributes` (at least one pair) | `keyring` crate (Secret Service; kwalletd/gnome-keyring behind it) | D-Bus session + unlocked keyring |
   | `exec` | `command` (argv array, no shell string) | run, trim stdout | whatever the command uses |
   | `env` | `var` | read caller env | none |

   `exec` is the deliberate escape hatch: 1Password, Doppler, Infisical,
   AWS, GCP, Azure, pass/gopass, and systemd-creds are covered day one
   with zero per-provider code. There is no GitHub provider: Actions
   secrets are write-only by protocol. SOPS is a non-goal in v1 (one
   decrypt yields many vars, a different ref shape).

   **Provider argv resolution.** `bitwarden`'s `bws` and every `exec`
   argv[0] resolve against the HOST PATH with the pod farm prepend
   stripped (shells that eval the shellenv carry the farm first; a pool
   package shipping a binary named `bws`, `op`, `vault`, or `gh` would
   otherwise shadow the host tool and capture the caller's provider
   tokens). Resolution inside the pod state root fails loud. Values
   resolved from any provider may contain newlines (PEM keys are a
   day-one case); the envfile consumer escapes them per systemd's
   quoting rules, and the shellenv path already single-quotes.
5. **Provider credentials come from the caller's environment (D5).** No
   nested credential chains in v1: `BWS_ACCESS_TOKEN`, `VAULT_TOKEN`, and
   friends are inherited env, bootstrapped outside shuttle exactly as
   devbox-global does today. A `credential = { ... }` nesting is v2 only
   if demanded. These credentials stay login-side by design (see the
   isolation interaction above).
6. **Host-side fetch; isolation boundaries untouched (D6).** Resolution
   runs in the shuttle process before exec or render, on the host.
   Provider CLIs (`bws`, `op`, `gh`) are host tools, never pod packages
   (and resolve as host tools per D4's argv rule). `sandbox` and
   `machine` isolation (ADR-0038) need no network grant for secrets:
   values arrive through the declared re-injection, not ambient env
   (see D3). The build sandbox stays offline (ADR-0039); secrets never
   enter builds.
7. **Fail loud, never partial (D7).** Validation failure at sync means
   zero writes (house norm); sync never resolves, so a provider outage
   never blocks sync (it does block entry: see Consequences). Fetch
   failure at serve fails the command naming the var and source; never
   an empty value, never a truncated shellenv. No `optional` flag in
   v1. `pod secrets check` prefights by resolving every reference and
   reporting per-source health (doctor integration follows).
   `pod secrets list` shows references and cache state, values never.
   `$XDG_RUNTIME_DIR` absent or not on tmpfs is a hard failure naming
   the gap (no silent disk fallback; WSL2-no-systemd and SysV hosts are
   out of scope for secrets in v1).
8. **Masking (D8).** Values never logged, never appear in errors or
   `--trace` output, and appear in no machine-readable output: `pod
   secrets list` prints references only, and `pod shellenv --json`
   carries names, sources, and cache state only, never resolved values
   (a CI script dumping shellenv JSON must not become an exfiltration
   path). POSIX shellenv exports and the envfile are the only value
   surfaces, both mode-contained (runtime dir is 0700 by spec).

## Alternatives considered

- **Extend `env` with reference values** (interpolation vocabulary in
  ADR-0030). Rejected: one surface would carry two value kinds, every
  consumer grows a resolve branch, and literal env's generation semantics
  would need per-key exceptions. The sibling keeps ADR-0030 intact.
- **Record resolved values in the generation** (env-style). Rejected:
  secrets rotate; a recorded value resurrects stale credentials on
  rollback and puts values at rest on persistent disk, both unacceptable.
- **Envfile content digest folded into `unit_hash`** for rotation pickup.
  Rejected: the reconcile would have to resolve secrets (network,
  credentials) to hash the file, coupling sync to providers, or hash a
  file that legitimately does not exist post-reboot. The refresh verb
  restart keeps the unit hash package-only and puts rotation behind one
  explicit, daemon-law-clean verb.
- **`EnvironmentFile=-` prefix** so units start without the envfile.
  Rejected by every review seat: silent start-without-secrets violates
  D7 exactly where credentials matter most.
- **`ExecStartPre=` boot-time refresher.** Rejected as the boot story:
  the systemd user manager holds no provider credentials and the tmpfs
  cache is gone at that point, so the helper has nothing to fetch or
  restore. Retained as a possible convenience that runs AFTER a
  login-side refresh, not instead of it.
- **Per-provider built-ins now** (1Password, AWS, ...). Rejected: `exec`
  covers them with argv arrays and no code; built-ins grow by demand.
- **SOPS/file-shaped multi-var sources.** Deferred with a revisit
  trigger: one decrypt yielding many vars is a different reference shape,
  not a harder version of this one.
- **Nested credential chains** (`credential = { source = "libsecret", ... }`).
  Deferred: the operator already bootstraps provider tokens in the
  caller env; nesting can be added without breaking the v1 schema.
- **Watch/re-render daemons** (envconsul model). Rejected: against the
  daemon law (ADR-0011); refresh is a verb, not a process.

## Consequences

**Positive**

- Credentials stop being pasted into checked-in `pod.lua` or ad hoc
  exports; the declaration is reviewable while values never are. (The
  review surface is the declaration only: loaded pods' `exec`
  references run with the loader's credentials at serve time, per D2.)
- Rollback stays rotation-correct by construction (references re-resolve
  live; the cache key cannot serve a dead generation's values).
- One resolve path, three consumers, zero new isolation surface; the
  build sandbox contract (ADR-0039) is untouched, and the envfile
  indirection strengthens masking over today's plaintext `Environment=`
  lines, which `systemctl show` exposes.
- The escape hatch keeps the built-in registry minimal (ADR-0014's
  grow-by-demand rule).

**Negative**

- Serve-time resolution adds a fetch latency on first use per session
  (cached after; tmpfs cache dies at reboot by design). tmpfs is
  swap-backed: under memory pressure values can reach the swap device,
  the same caveat the devbox-secrets pattern already accepts.
- Services pick up rotations only on `pod secrets refresh`, and only
  start once that verb has run after each reboot. Operators of
  secret-bearing services gain a login-time step.
- A provider outage blocks pod ENTRY, not just the secret-using command:
  `pod shellenv` hard-fails, so entering the pod waits on the provider
  (D7's trade, revisit trigger below).
- A new failure mode at exec time (provider down, token expired) where
  env literals never failed. Fail-loud naming the var and source keeps
  it diagnosable.
- A confined app with a `network = true` grant can exfiltrate whatever
  secrets it receives. The operator declares both; the boundary exists
  to make that declaration explicit, not to referee it.
- Rotated values can linger in tmpfs under pruned keys only until the
  next refresh/sync/remove; the boot bounds the worst case.

## Revisit triggers

- A real need for SOPS or other file-shaped multi-var sources.
- A provider whose auth cannot ride the caller env (nested credentials).
- Headless `libsecret` edge cases (fall back to `secret-tool` parity).
- Missing-secret UX: if hard-fail-at-shellenv hurts real usage, revisit
  with data (skip+warn candidate).
- Portable service backends (ADR-0032): the envfile shape may need a
  per-backend mapping; `ExecStartPre ensure-envfile` as a
  post-refresh convenience unit is the candidate there.
- Services rotation: if refresh-verb restart proves too coarse
  (units restarting on unrelated keys' rotations), fold a per-unit
  envfile digest into the reconcile as a second-generation refinement.

## Evidence

- The operator's live pipeline this design reproduces: devbox-global
  `setup-bws` + init-hook (token in libsecret, manifest of names,
  `bws` fetch, tmpfs cache at `$XDG_RUNTIME_DIR/devbox-secrets.sh`),
  surveyed in `.planning/research/secret-manager-survey-2026-09-24.md`.
- Landscape verdicts per provider (crates.io + vendor docs, verified
  2026-09) in the same survey, including the GitHub Actions write-only
  protocol finding that kills a GitHub source.
- Codebase seam recon (2026-09-24) recorded in
  `.planning/grill-input-2026-09-24-pod-secrets.md` §1: declaration,
  validation, fold, generation-write, and consumer seams all exist and
  are cited by symbol and line there.
- Council review 2026-09-26 (four seats, unanimous accept-with-changes):
  the two findings that reshaped D3 are anchored in
  `src/services.rs` (unit-hash restart key `unit_hash`/`:672-683`,
  action table `:1034`) and `src/pod.rs` (`render_shellenv` farm PATH
  prepend `:5718`), plus the ADR-0038 contract-3 re-injection analysis.

## References

- ADR-0030 (declared pod env, the surface this extends beside), ADR-0032
  (declarative services, the envfile consumer), ADR-0038 (pod isolation,
  the re-injection contract secrets ride), ADR-0039 (offline build
  sandbox, secrets never enter builds), ADR-0014 (registry shape, deep
  validation at the boundary), ADR-0017 (dependency fetch precedent for
  host-side fetch with pins), ADR-0011 (daemon law, no watch processes).
- Issues: #181 (ratification), #182-#187 (implementation series,
  unblocked by this ADR).
