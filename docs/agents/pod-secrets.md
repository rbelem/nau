# Pod secrets (ADR-0042)

Pods declare **secret references** in `pod.lua`; generations pin
references, never values; values resolve at **serve time** through
built-in **secret sources** and reach consumers through the existing
env contract (ADR-0030). There is no credential material anywhere in
the declaration, the lockfile, or the generation tree — the two value
surfaces are the POSIX exports of `pod shellenv`/`shuttle run` and the
0600 services envfile, both under the session tmpfs.

## Declaration surface

A sibling of `env` on `pod {}` — never an interpolation into it:

```lua
pod {
    packages = { "jq" },
    env     = { LOG_LEVEL = "debug" },
    secrets = {
        GH_TOKEN  = { source = "bitwarden", id = "378c3347-1667-4341-8312-b49f01887394" },
        DB_PASS   = { source = "vault", mount = "secret", path = "prod/db", field = "pass" },
        LOGIN_KEY = { source = "libsecret", attributes = { schema = "io.devbox.Secret", key = "login" } },
        ONEPASS   = { source = "exec", command = { "op", "read", "op://vault/item/field" } },
        GH_PAT    = { source = "env", var = "GITHUB_TOKEN" },
    },
}
```

Validation is fail-closed and every rule fires before anything is
written (sync validates shape only — it never resolves, so a provider
outage never blocks sync):

- An unknown `source` is a parse error; so is any per-source field the
  source does not declare (the `src/snap.rs` unknown-field precedent).
- Reserved names (`PATH`, `LD_LIBRARY_PATH`) are rejected as secret
  keys, exactly as for `env` keys.
- A key present in both `env` and `secrets` refuses at parse with a
  named error — `env` stays literal, `secrets` stays referenced.
- A secret-key collision across `loads` is a **hard error**, not the
  warning env literals get: a losing credential reference silently
  changes live credentials under masking, so precedence is refused
  instead of folded.
- Loaded pods add a trust edge env never had: a loaded pod's `exec`
  references run at serve time with the *loader's* provider
  credentials in reach. Declare loads accordingly.

## The five sources

| source | reference fields | fetch | auth (caller env) |
| --- | --- | --- | --- |
| `bitwarden` | `id` | `bws secret get <id>`, read `.value` | `BWS_ACCESS_TOKEN` |
| `vault` | `mount`, `path`, `field` | KV v2 `GET /v1/{mount}/data/{path}` (OpenBao identical) | `VAULT_ADDR` + `VAULT_TOKEN` |
| `libsecret` | `attributes` (≥ 1 pair) | Secret Service attribute search (`dbus-secret-service`, sync libdbus; gnome-keyring / kwalletd behind it) | unlocked login keyring (D-Bus session) |
| `exec` | `command` (argv array, never a shell string) | run, trim stdout | whatever the command uses |
| `env` | `var` | read the caller's environment | none |

Two argv rules apply to `bitwarden`'s `bws` and every `exec` argv[0]:

- Resolution is against the **host PATH** with the pod farm prepend
  stripped — shells that eval the shellenv carry the farm first, and a
  pool package shipping a binary named `bws`, `op`, or `vault` must not
  shadow the host tool and capture the caller's provider tokens.
- An `exec` program resolving **inside the pod state root** fails loud.

Resolved values may contain newlines (PEM keys are a day-one case);
the envfile escapes them per systemd's quoting rules and the shellenv
path single-quotes. Empty values fail the resolve (D7: never an empty
secret).

## Serve-time semantics

**One resolve entry point serves three consumers.** `pod shellenv`
(exports after the `env` lines), the `shuttle run` overlay (declared
replaces inherited, same rule as env), and services (units reference a
0600 `EnvironmentFile=` rendered *without* the `-` prefix — a missing
file fails the unit start and names the path, never a silent
start-without-secrets).

**All-or-nothing (D7).** Resolution runs host-side in the shuttle
process before exec or render. Any fetch failure fails the command
naming the var and source; there is never a partial serve, never a
truncated shellenv, and no `optional` flag in v1. Sync never resolves:
it validates the reference shape only.

**Masking (D8).** Values never appear in logs, errors, `--trace`
output, or any machine-readable output: `pod secrets list` prints
references only, and `pod shellenv --json` carries names, sources, and
cache state — never resolved values. The POSIX shellenv exports and
the envfile are the only value surfaces, both mode-contained (the
runtime dir is 0700 by spec).

**Cache lifecycle (D3).** Values cache at
`$XDG_RUNTIME_DIR/shuttle/secrets/<pod>/<decl-hash>.json` — 0600,
tmpfs-verified, dies at reboot, written atomically (temp + rename).
`<decl-hash>` is the SHA-256 of the folded canonical reference JSON
(the same bytes `generations/<n>/secrets.json` records), and the cache
key **drops the generation on purpose**: a rollback re-resolves live
instead of serving a dead generation's pre-rotation values. The
generation rides inside the entry body for prune bookkeeping only.

- `miss` — no entry for this session: the first resolve per session
  pays the fetch, the rest are hits.
- `hit` — entry present, generation current: zero provider calls.
- `stale` — entry's recorded generation is no longer active; refresh
  and sync prune stale entries, and `pod remove` prunes the pod's
  whole subtree.

`pod secrets refresh` is the rotation verb: bust the pod's cache,
re-resolve every reference, rewrite the active entry, and re-materialize
the envfile. Restarting the units that consume a changed envfile is the
rotation-restart half of the contract and lands with its own ticket
(#224); sync never resolves — it only prunes — and nothing secret is
written under the pod root: the envfile lives in the tmpfs tree, never
under `generations/<n>/`. After a reboot the tmpfs is gone and the
systemd user manager holds no provider credentials, so **secret-bearing
services start failed until a login-side `pod secrets refresh` (or the
next sync that finds a warm cache entry) materializes the envfile** —
the operator's login init-hook is the natural place. This is an
accepted cost of values-never-at-rest; ADR-0042 records the full
services contract.

## Verbs

```console
$ shuttle pod --name work secrets list
secret references for pod 'work':
  DB_PASS   vault secret/prod/db#pass   miss
  GH_TOKEN  bitwarden id 378c3347-…     miss
(cache: hit = current entry · stale = resolved for an older generation · miss = not yet resolved this session; values never print)
```

```console
$ shuttle pod --name work secrets check
secret health for pod 'work':
  DB_PASS   vault      ok
  GH_TOKEN  bitwarden  ok
```

`check` probes every reference (one probe per key, so every failing
key is named) and exits 1 if any is unhealthy. It never touches the
session cache — a probe is a probe, and a partial success must not
land a partial entry.

```console
$ shuttle pod --name work secrets refresh
dropped 1 cached entry
resolved 2 secret(s) from [bitwarden=1, vault=1] — values cached for this session
```

`refresh` picks up a rotation without a new generation and
re-materializes the envfile; restarting the units that consume a
changed envfile lands with #224.

## `exec` recipes for the long tail

`exec` is the deliberate escape hatch: any provider with a CLI is a
reference, with zero per-provider code. Each recipe resolves one var;
the command must print the value on stdout (trimmed). Provider auth
comes from the caller's environment (D5) — the same exports your
shell already has. Keep it an argv array; there is no shell string.

| provider | `pod.lua` reference |
| --- | --- |
| 1Password | `{ source = "exec", command = { "op", "read", "op://vault/item/field" } }` |
| Doppler | `{ source = "exec", command = { "doppler", "secrets", "get", "API_KEY", "--project", "myproj", "--config", "prd" } }` |
| Infisical | `{ source = "exec", command = { "infisical", "secrets", "get", "API_KEY", "--env", "prod", "--silent" } }` |
| AWS Secrets Manager | `{ source = "exec", command = { "aws", "secretsmanager", "get-secret-value", "--secret-id", "prod/api", "--query", "SecretString", "--output", "text" } }` |
| AWS SSM Parameter Store | `{ source = "exec", command = { "aws", "ssm", "get-parameter", "--name", "/prod/api/key", "--with-decryption", "--query", "Parameter.Value", "--output", "text" } }` |
| GCP Secret Manager | `{ source = "exec", command = { "gcloud", "secrets", "versions", "access", "latest", "--secret=api-key", "--project=myproj" } }` |
| Azure Key Vault | `{ source = "exec", command = { "az", "keyvault", "secret", "show", "--vault-name", "myvault", "--name", "api-key", "--query", "value", "-o", "tsv" } }` |
| pass | `{ source = "exec", command = { "pass", "show", "prod/api-key" } }` |
| gopass | `{ source = "exec", command = { "gopass", "show", "prod/api-key" } }` |
| systemd-creds | `{ source = "exec", command = { "systemd-creds", "decrypt", "--name=api_key", "prod/api.cred", "-" } }` |

## Non-goals (v1)

- **GitHub as a source is impossible by protocol**: Actions secrets
  are write-only (libsodium sealed box on the API); there is no read
  path to build a provider on. Not deferred — ruled out.
- **SOPS and file-shaped multi-var decrypts are a different reference
  shape**: one decrypt yields many vars, which is not a harder version
  of the one-ref-one-var contract above. Deferred with a revisit
  trigger in ADR-0042, not a v1 gap.

## devbox-global interop

The devbox-global `setup-bws` bootstrap stores its Bitwarden Secrets
Manager access token in the login keyring under the attributes
`{ bitwarden = "sm-access-token" }`. Pods and devbox share the same
credential bootstrap, so a libsecret reference with those attributes
reads it:

```lua
pod {
    secrets = {
        BWS_ACCESS_TOKEN = { source = "libsecret", attributes = { bitwarden = "sm-access-token" } },
    },
}
```

Once exported into the caller's env (your init-hook does this for
devbox already), it is also the `BWS_ACCESS_TOKEN` that `bitwarden`
references authenticate with — the provider-credential rule (D5) is
the same bootstrap, not a second chain. Deep credential *nesting*
(`credential = { … }`) stays a v2 question per ADR-0042.
