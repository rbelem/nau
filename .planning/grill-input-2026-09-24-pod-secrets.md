# Grill input — pod secret sources (2026-09-24)

Proposal to grill: pods fetch secrets from external secret managers.
Research: `.planning/research/secret-manager-survey-2026-09-24.md`.
Draft ADR below is **pre-ratification** — the grill settles the open
questions (§3), then ADR-0040 lands and the tickets (#T2…) unblock.

Scope statement: pods declare **secret references**; values resolve at
serve time from built-in providers and surface as ordinary env vars
through the one existing env contract (ADR-0030's consumers). Build
sandbox untouched; no new network surface; no values at rest on
persistent disk.

## 1. Codebase seams (recon, 2026-09-24)

- Pod declaration: `PodDeclaration` `src/pod.rs:258-274`; allowed pod
  table keys hardcoded at `validate_pod_table` `src/pod.rs:348` (error
  string :354-357, field assignment :365-379, round-trip renderer
  :827-872). New `secrets` field slots exactly where `env` lives.
- Env precedent (ADR-0030): `expect_env` :477 (string→string, newline
  rejected), `validate_env_key` :581 (identifier shape; `PATH` +
  `LD_LIBRARY_PATH` reserved), resolve/fold :1179/:1192 (own-over-loaded
  silent, first-declared load wins collisions with warning),
  `write_generation_env` farm.rs:189 (sorted canonical JSON, byte
  deterministic) written in the staging tail `present_active`
  pod.rs:4570-4599 — **order fixed: env → services::record → farm emit
  → flip**.
- Consumers, already a single env contract: `render_shellenv` pod.rs:5717
  (POSIX single-quote exports, sorted); `overlay_pod_env_with`
  confine.rs:236 + `overlay_declared_vars` :151 (every exec form,
  declared replaces inherited); services `ResolveCtx.gen_env`
  services.rs:247/351 → `Environment=` lines :425.
- No existing secret code (all grep hits are the signing key,
  `src/sign.rs`). Greenfield.
- Network policy: arbitrary-command `run` is unsandboxed by design
  (confine.rs:11-13); confined apps gate on a boolean `network` grant
  (snap.rs:1453, bwrap `--unshare-net` confine.rs:301); build sandbox is
  offline unconditionally (ADR-0039). **Host-side fetch needs no
  isolation changes at all.**
- Fetch precedents: host-side http(s) + hash pin `src/dep_fetch.rs`;
  fail-closed zero-write trust gate `add_snap_pod` pod.rs:1516-1530;
  ADR-0039 Decision 5 sanctions dynamic fetch outside the offline build.
- Tests: `tests/pod_declare.rs` (canonical harness: real binary, tempdirs,
  loopback HTTP server, tool gating via PATH), `tests/pod_cmd.rs:698-773`
  (shellenv assertions), in-module env tests pod.rs:5980-7100.

## 2. Draft decisions (to be ratified as ADR-0040)

**D1 — Sibling declared surface, not interpolation.**

```lua
pod {
  packages = { "cargo", "jq" },
  secrets = {
    GITHUB_TOKEN = { source = "bitwarden", id = "8848da48-…" },
    NIX_TOKEN    = { source = "vault", mount = "secret",
                     path = "ci/tokens", field = "nix" },
    SM_TOKEN     = { source = "libsecret",
                     attributes = { bitwarden = "sm-access-token" } },
    OPENAI_KEY   = { source = "exec",
                     command = { "op", "read", "op://Vault/openai/key" } },
    GH_PAT       = { source = "env", var = "GITHUB_TOKEN" },
  },
}
```

`env` stays literal (ADR-0030 untouched). A key in both `env` and
`secrets` refuses at parse — one source of truth per key, named error.
Reserved seams (`PATH`, `LD_LIBRARY_PATH`) rejected for secrets too.
This answers ADR-0030's "interpolation vocabulary" revisit trigger by
declining to interpolate: references are their own surface.

**D2 — Generations pin references, never values.** Sync validates the
declaration (schema, known source, per-source field shape — deep
validation in Rust per ADR-0014's boundary rule) and records the folded
reference set as sorted canonical JSON at `generations/<n>/secrets.json`
(0600, references only), written in the staging tail after env. Fold
rules identical to env: own-over-loaded per key, first-declared load
wins cross-load collisions (one warning). Rollback re-scopes the live
reference set by construction — and deliberately does NOT resurrect old
values (rotation correctness; contrast env literals, which are
generation-recorded because they cannot rotate).

**D3 — Resolve at serve time; session cache on tmpfs.** One resolve
entry point serves all three consumers: `shuttle pod shellenv` (exports
after the env lines; `--json` carries a separate `secrets` map),
`shuttle run` (overlay, declared replaces inherited — same rule as env),
and services (units reference a 0600 `EnvironmentFile=` under the
runtime path; refreshed by sync and by `pod secrets refresh`; ADR-0032's
diff-and-restart picks up rotations on next sync). Values cache at
`$XDG_RUNTIME_DIR/shuttle/secrets/<pod>/<gen>/<decl-hash>.json` (0600,
tmpfs, dies at reboot) keyed by generation + canonical declaration
hash; first resolve per session pays the fetch, the rest are hits — the
devbox `devbox-secrets.sh` pattern (§1 of the survey). Nothing secret is
written under the pod root. Rotation = `shuttle pod secrets refresh` (or
cache expiry at reboot), no new generation.

**D4 — Built-in provider registry, minimal v1** (ADR-0014's shape:
compiled-in registry, deep validation in Rust, grow by demand):

| source | ref fields | fetch | auth (caller env) |
|---|---|---|---|
| `bitwarden` | `id` | shell out to `bws secret get <id>`, read `.value` | `BWS_ACCESS_TOKEN` |
| `vault` | `mount`, `path`, `field` | KV v2 REST `GET /v1/{mount}/data/{path}` (crate vs raw REST decided at implementation; OpenBao identical) | `VAULT_ADDR` + `VAULT_TOKEN` |
| `libsecret` | `attributes` (≥1 pair) | `keyring` crate (Secret Service; kwalletd/gnome-keyring behind it) | D-Bus session + unlocked keyring |
| `exec` | `command` (argv array, no shell string) | run, trim stdout | whatever the command uses |
| `env` | `var` | read caller env | none |

`exec` is the deliberate escape hatch covering 1Password, Doppler,
Infisical, AWS, GCP, Azure, pass/gopass, systemd-creds on day one with
zero per-provider code (survey §2 verdicts). **No GitHub provider** —
Actions secrets are write-only by protocol (libsodium sealed box, no
read path); the real need is served by `env`/`exec`. SOPS is a
non-goal v1 (one decrypt yields many vars — a different ref shape;
revisit trigger).

**D5 — Provider credentials come from the caller's environment.** v1
has no nested credential chains: `BWS_ACCESS_TOKEN`,
`VAULT_TOKEN`, and friends are inherited env, bootstrapped outside
shuttle exactly as devbox-global does today (token stored in libsecret
by `setup-bws`, exported by the init-hook). A `credential = { … }`
nesting is v2 only if demanded.

**D6 — Host-side fetch; isolation boundaries untouched.** Resolution
runs in the shuttle process before exec/render. Provider CLIs (`bws`,
`gh`, `op`) are host tools, never pod packages. `sandbox`/`machine`
isolation (ADR-0038, draft) needs no network grant for secrets: values
arrive as env like everything else. Build sandbox stays offline
(ADR-0039) — secrets never enter builds.

**D7 — Fail loud, never partial.** Validation failure at sync: zero
writes (house norm). Fetch failure at serve: the command fails naming
the var + source, never an empty value, never a truncated shellenv. No
`optional` flag v1. `shuttle pod secrets check` = preflight resolving
every reference, reporting per-source health (doctor integration
follows). `shuttle pod secrets list` shows references + cache state,
values never.

**D8 — Masking.** Values never logged, never appear in errors or
`--trace` output; `pod secrets list` prints references only.

## 3. Open questions for the grill

| # | Question | Draft lean |
|---|---|---|
| Q1 | `secrets` vs extending `env` with ref values | `secrets` sibling (D1) — env stays literal, ADR-0030 intact |
| Q2 | Rollback semantics for rotated secrets | re-resolve live (D2); recorded-value restore would resurrect rotated credentials |
| Q3 | services: `EnvironmentFile=` vs bake at emit | envfile (D3) — rotations reach services without re-emit; portable-backend envfile shape is an open sub-question for ADR-0032 backends |
| Q4 | vault: `vaultrs` (tokio dep) vs raw REST on existing fetch stack | raw REST lean — one GET; decide at implementation |
| Q5 | libsecret: `keyring` crate vs shell out to `secret-tool` | `keyring` crate lean (no external tool dep); `secret-tool` parity easy if headless edge cases bite |
| Q6 | cache location/perm details | `$XDG_RUNTIME_DIR/shuttle/secrets/`, 0600, decl-hash keyed (D3) |
| Q7 | missing-secret UX on shellenv (hard fail vs skip+warn) | hard fail (D7); revisit with real usage |
| Q8 | exec `command`: argv array only, or allow shell string? | argv only — no injection surface, no quoting layer |
| Q9 | does `pod add/remove` need secret verbs, or is `pod.lua`/declare the only write path? | follow env's precedent exactly (declare/edit path) |

## 4. Ticket sketch (to file after ratification)

T1 ratify ADR-0040 (this grill) → T2 declaration surface + validation +
generation record (pod.rs seams in §1) → T3 resolve engine + registry +
`env`/`exec` + `pod secrets {list,check,refresh}` + tmpfs cache → T4
serve-time emission (shellenv/run/services envfile, D3/D7/D8) → T5
`bitwarden` + `libsecret` providers ∥ T6 `vault` provider + loopback
KV-v2 test harness (parallel) → T7 docs, CONTEXT.md glossary, gate-pod
dogfood round (GH_TOKEN through bitwarden).

Each ticket ends verifiable: T2 unit gates (parse/reject/fold/record),
T3 `pod secrets check` green against a fake `exec` provider, T4
shellenv/run/services assertions (pod_cmd.rs / pod_services.rs style),
T5/T6 provider tests with loopback doubles (pod_declare.rs harness
pattern), T7 live proof transcript per house style.

## 5. Non-goals (v1)

Per-provider built-ins beyond D4's five sources · SOPS/file-shaped
multi-var sources · write paths (creating/rotating secrets in managers)
· nested credential chains (D5) · watch/re-render daemons (envconsul
model) · GitHub as a source (impossible by protocol) · secrets inside
the build sandbox (ADR-0039).
