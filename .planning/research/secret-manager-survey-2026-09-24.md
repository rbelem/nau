# Secret manager survey for pod secret sources (2026-09-24)

Input for the pod secret sources design (grill input
`.planning/grill-input-2026-09-24-pod-secrets.md`, draft ADR-0040). Two
evidence sources: (a) the devbox-global secret pipeline the operator runs
today, (b) a landscape survey of secret managers and Rust crates
(crates.io API + vendor docs, verified 2026-09). Codebase seams come from
a recon pass recorded in the grill input.

## 1. The pattern to reproduce: devbox-global's bws pipeline

`~/.local/share/devbox/global/current/bin/setup-bws` + the init-hook run
this chain today, and pods must speak to the same mental model:

1. **Provider credential in the OS keyring.** `BWS_ACCESS_TOKEN` is
   validated, then stored via `secret-tool store --label='bws SM token'
   bitwarden sm-access-token` (libsecret → freedesktop Secret Service →
   KWallet on this machine via `setup-kde-secrets-service`, which pins
   `org.freedesktop.secrets` to kwalletd).
2. **A manifest of desired env var names** at `~/.config/bws/sm.ini`
   (0700/0600): one canonical name per line, plus an `[aliases]` section
   mapping third-party names to canonical secrets (`GH_TOKEN =
   GITHUB_TOKEN`, `WIGOLO_GITHUB_TOKEN = GITHUB_TOKEN`).
3. **Fetch + export at shell start**, filtered by the manifest, from
   `bws secret list --output env`.
4. **Session cache on tmpfs**: the rendered exports live at
   `$XDG_RUNTIME_DIR/devbox-secrets.sh`; refresh is `rm` that file and
   re-exec the shell. Nothing secret persists on disk across reboots.

Properties worth keeping in shuttle: names/aliases declared, values
never at rest on persistent disk, provider credential bootstrapped
through libsecret, explicit refresh verb, fail-loud on auth errors
(`setup-bws` validates before storing and refuses to clobber a good
token with a rejected one).

## 2. Backend survey (fetch shape, auth, Rust crate, verdict)

Crate facts from crates.io (2026-09): `vaultrs` 0.8.0 (2026-03, alive),
`keyring` 4.2.0 (very active), `secret-service` 5.2.0, `bitwarden`
2.1.0 (official SDK, beta), `aws-sdk-secretsmanager` 1.118.0,
`infisical` 0.0.3 (embryonic).

| Backend | Fetch | Auth | Crate | Verdict for shuttle v1 |
|---|---|---|---|---|
| Bitwarden SM | `bws secret get <ID>` (JSON `.value`); also `bws run --` | `BWS_ACCESS_TOKEN` env; headless-native | official `bitwarden` crate — beta + heavy crypto stack | built-in provider, **shell out to `bws`**; embed later if ever |
| Vault / OpenBao | KV v2 REST `GET /v1/{mount}/data/{path}` (field `.data.data.<key>`); `vault kv get -field=` CLI | `VAULT_TOKEN`/`VAULT_ADDR` env; AppRole; agent | `vaultrs` 0.8.0 (async/tokio) — or raw REST, trivial | built-in provider; OpenBao is the same API surface (`bao`, fork of 1.14) — covered by the same code |
| libsecret / Secret Service | `secret-tool lookup <attr> <value>` | D-Bus session bus + unlocked keyring (gnome-keyring / kwalletd) | `keyring` 4.2.0 (pluggable backends) or `secret-service` 5.2.0 | built-in provider; **workstation-only** (headless servers lack the bus/keyring — document) |
| 1Password | `op read "op://vault/item/field"` | `OP_SERVICE_ACCOUNT_TOKEN` (headless) or desktop app agent | none official for reads | **`exec` provider recipe** |
| Doppler | `doppler secrets get KEY --plain` / `doppler run --` | `DOPPLER_TOKEN` service token | none notable | `exec` recipe (REST embed trivial later) |
| Infisical | `infisical secrets get KEY` | machine identity: `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID/SECRET` | official crate v0.0.3 — too immature | `exec` recipe |
| AWS SM / SSM | `aws secretsmanager get-secret-value --query SecretString --output text`; `aws ssm get-parameter --with-decryption` | standard AWS cred chain | official `aws-sdk-*` — drags the whole smithy stack (~200+ crates) | `exec` recipe; embed only if AWS becomes first-class |
| GCP Secret Manager | `gcloud secrets versions access latest --secret=X` | ADC / service-account JSON | official crate maturing | `exec` recipe |
| Azure Key Vault | `az keyvault secret show -n K --query value -o tsv` | `az login` / service principal | official SDK GA-ish | `exec` recipe |
| pass / gopass | `pass show path` / `gopass show` | GPG agent | none (they shell to gpg themselves) | `exec` recipe |
| SOPS + age | different model: whole-file decrypt → `sops exec-env file.env -- cmd` | per-file recipient keys (age/GPG/KMS) | `sops` not published as a library | **non-goal v1** — one decrypt yields many vars, a different ref shape; revisit trigger |
| systemd-creds | `systemd-creds decrypt --name=n credfile -` | TPM2 or symML key, no network | none | `exec` recipe; thematic fit for services later |
| Kernel keyutils | `keyctl pipe <id>` | session/user keyring, in-kernel only | `linux-keyutils` (pure Rust, tiny) | future **cache sink**, not a source; not v1 |

### GitHub is a trap as a *source*

Three things get called "GitHub secrets" (docs.github.com/en/rest/actions/secrets):

1. **Actions/repo/org secrets API** — reads return metadata only;
   values are libsodium-sealed to the repo public key and GitHub never
   exposes the private key. **There is no read path.** Not viable.
2. **`gh auth token`** — the local CLI credential. Fetchable, but it is
   a *credential for GitHub*, not a store.
3. PATs/deploy tokens stored elsewhere — nothing to fetch from GitHub.

The real user need ("put my GitHub token in the pod") is served by an
**env passthrough** ref (`{ source = "env", var = "GITHUB_TOKEN" }`) or
an exec ref (`{ source = "exec", command = { "gh", "auth", "token" }
}`) — not by a GitHub provider.

## 3. Resolution-timing prior art

Declare refs in config → resolve to env vars, ranked by ecosystem
precedent:

- **Fetch-per-invocation with child-process injection** (dominant):
  `op run --env-file`, `bws run`, `doppler run --`, `infisical run --`,
  `sops exec-env`, `vault`-style exec wrappers, `direnv`+pass.
- **Cached render, long-running re-renderer**: `envconsul` (watch loop),
  vault-agent templating (sidecar, render-on-change).
- **Pull-to-disk cache**: dotenv-vault `pull` (writes a local `.env`).

Shuttle's match is **fetch-per-invocation at serve time** (`shuttle
pod shellenv`, `shuttle run`, service start) with a **session-scoped
tmpfs cache** — the devbox pattern in §1 and the ecosystem norm agree.
Generations pin the *references*; values stay live (rotation = refresh,
not re-sync), and nothing lands on persistent disk.

## 4. Crates summary (embed decisions)

| Need | Crate | Note |
|---|---|---|
| Secret Service provider | `keyring` 4.2.0 | one dep, standard trait; Linux = Secret Service |
| Vault KV v2 | `vaultrs` 0.8.0 or raw `reqwest` REST | REST is one GET; vaultrs is async (tokio) — check against shuttle's sync codebase before adding |
| Bitwarden SM | shell out to `bws` | official crate is beta + heavy |
| future cache sink | `linux-keyutils` | pure Rust, no lib dep |

Vault note: shuttle already does host-side http(s) fetch + hash pinning
(`src/dep_fetch.rs`); a raw-REST KV v2 read on the existing stack may
beat adding tokio for `vaultrs`. Decide at implementation.
