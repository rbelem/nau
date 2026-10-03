# ADR-0054: GitHub token auth — deferred, design frozen against triggers

## Status

Implemented (opt-in), 2026-10-03. Originally accepted as a deferral
(drafted 2026-10-02 after the rate-limit wave landed, 0afc6e8: retry
with backoff at the curl seam). The operator fired the re-open path on
2026-10-03 and the frozen design below was implemented as specified —
see [Implementation](#implementation). The plumbing is live but inert
unless `GITHUB_TOKEN` is exported: opt-in by construction, unset env =
byte-identical legacy behavior. Of the Decision 2 triggers, the one
still ahead is `api.github.com` usage — the moment nau calls the REST
API, the 5,000/hr quota becomes real and the token stops being a
courtesy and starts being the point; the codeload secondary-limit
trigger (throttling the retry budget cannot absorb) remains the
day-to-day watch item. The research and design below were produced by
the rate-limit lane and reviewed by council in that wave; this ADR
records the decision structurally so the deferral had a re-open path
that is not folklore. Design source of record:
`/tmp/opencode/ratelimit-design.md` §4 (volatile location — superseded
by this ADR once read).

## Context

`nau pod sync` fetches GitHub archive tarballs unauthenticated and hit
429s several times a day. The wave's fix is retry with backoff at the
single curl seam (`crates/nau-chart/src/dep_fetch.rs`), which survives
transient throttling and fails loud past its budget. The obvious next
question — "should the fetches carry a PAT?" — was researched, and the
answer is no for the traffic nau actually sends:

- The archive URL (`github.com/{o}/{r}/archive/...`) 302s to
  **codeload.github.com**, which serves archive bytes as web traffic
  under its own per-IP/fingerprint secondary limits. Codeload has **no
  documented token-raised quota**, and direct authenticated codeload
  access is unsupported (400 for private repos). A PAT would not have
  prevented the observed 429s. Sources: github.com/orgs/community/
  discussions/167943; nhs000.github.io (bazel codeload 429 analysis);
  gist.github.com/nilshamacher89/5f9b2b8f2898c0f50f8b9605004e8c7e.
- REST API limits (60 req/hr unauth → 5,000/hr with a PAT) apply to
  **api.github.com**, which nau does not call today.
- Conditional 304s count against the primary limit only when
  authenticated, on the API — again irrelevant to codeload traffic.

What exists already: the secrets machinery (`crates/nau-pod/src/
secrets.rs`, ADR-0042 `SecretSource` = Bitwarden | Vault |
SecretService | Exec | Env) and the curl credential-safety facts
(`-H @file` keeps tokens out of argv, curl ≥7.55; `-L` strips
`Authorization` on cross-host redirects unless `--location-trusted` —
and github.com → codeload IS cross-host).

## Decision

1. **Token auth is not implemented now.** The only host nau currently
   throttles against ignores tokens. Implementing the plumbing today
   would be capability with no beneficiary — every token invariant
   (redaction, host scoping, sourcing) would be exercised by nothing.

2. **Triggers to implement** (any one re-opens this ADR):
   - nau gains `api.github.com` usage (release/asset lookups are the
     named future features) — the 5,000/hr quota becomes real.
   - Private-repo sources become a requirement.
   - Codeload secondary limits start returning `Retry-After`s the
     retry budget cannot absorb (the lever-3 revisit condition in the
     rate-limit design) — then a token on the API path or fewer floats
     is the answer, never a skipped probe (ADR-0017 Decision 4a).

3. **The design, frozen for that day** (from the reviewed design doc;
   unchanged by this ADR):
   - **Sourcing**: `GITHUB_TOKEN` read at the CLI boundary, passed down
     to the seam as `Option<&str>` — the `SecretSource::Env` /
     provider-cred precedent (ADR-0042 D5: env read at the boundary so
     the core stays env-free). Second choice: the nau-pod Secret
     Service provider. **Rejected: config file** — a token on disk
     inverts ADR-0042 D2's spirit; secrets never live in declarations.
   - **Redaction invariant (ADR-0042 D8 extension)**: the token never
     appears in error strings, logs, or argv. Mechanically:
     `-H @<0600 tmpfile>` (never `-H "Authorization: …"` on the command
     line — ps-visible); the tmp file is deleted in the same cleanup
     block as the header dump; curl stderr stays suppressed (`-sS`).
   - **Host scoping**: attach only for `github.com` / `api.github.com`
     — never to third-party registries (npm/pypi/crates/goproxy:
     sending a GitHub credential to them is a leak). Do **not** use
     `--location-trusted`: default cross-host stripping keeps the token
     off the codeload hop, which ignores it anyway.
   - **Tests**: loopback asserts `Authorization: Bearer …` arrives for a
     github-host URL and is absent for a non-github URL; the header tmp
     file is removed after the run; a 401 error text contains no token.
   - **Kill-switch**: unset the env var — opt-in by construction.
   - **Crate placement rides the seam ruling**: the token attaches
     wherever the shared curl seam lives after the ADR-0053-aligned
     placement decision (see the multi-source rider); resolution stays
     above the seam as `Option<&str>` per ADR-0042's dependency
     direction.

## Implementation

Landed 2026-10-03, to the frozen design, unchanged:

- **Sourcing** — `GITHUB_TOKEN` is read once at the CLI dispatch
  boundary (`src/main.rs`, before command dispatch) and installed
  through `nau_chart::dep_fetch::set_github_token(Option<&str>)`; the
  core stays env-free and the credential crosses the seam as a plain
  value, resolution above it (the ADR-0042 D5 carriage). Carriage is a
  process-global beside `NET_RETRY_BUDGET_MS` (one invocation carries
  one credential, syncs are serial), so threading `Option<&str>`
  through every fetch entry point would buy nothing. Empty string =
  unset.
- **Redaction** — the seam writes one `Authorization: Bearer …` line to
  a fresh 0600 sibling temp file and passes `-H @<file>`; the token
  never appears in argv, stderr, or any error string. The credential
  file is removed in the same cleanup block as the header dump, on
  success and failure.
- **Host scoping** — exact match on `github.com` / `api.github.com`
  (port, userinfo, and case normalized); no subdomain or suffix
  matching, so `codeload.github.com` and lookalikes never see the
  header. No `--location-trusted`: curl's cross-host redirect strip
  keeps the token off the codeload hop.
- **Kill switch** — unset (or empty) `GITHUB_TOKEN`: no Authorization
  header anywhere, byte-identical pre-implementation behavior.
- **Tests** — loopback probes in `crates/nau-chart/src/dep_fetch.rs`:
  header arrival plus credential-file removal on an allowed host,
  absence on a disallowed host even with a credential installed, the
  unset kill switch (no header even with the test-only loopback
  allowlist on), a 401 whose error text carries no token, and a pure
  policy test pinning the exact-host allowlist.

## Alternatives considered

- **Implement now, ready for later.** Rejected: dead capability; the
  redaction and host-scoping invariants would have zero exercising call
  sites, so the first real caller would ship untested invariants
  anyway.
- **Config-file token** (`~/.config/nau/github-token`). Rejected:
  secrets at rest in plain files; contradicts ADR-0042 D2.
- **`--location-trusted` to keep the token on redirects.** Rejected:
  leaks the credential cross-host and buys nothing — codeload ignores
  Authorization regardless.

## Consequences

**Positive**: the 429 story is complete without adding a secrets
surface; the deferral is documented with evidence instead of remembered;
the frozen design makes the future implementation a small, pre-reviewed
diff.

**Negative**: if GitHub tightens codeload throttling beyond what the
retry budget absorbs, the interim levers are budget/cap tuning and
fewer declared floats — both worse than a quota. The triggers above
name when that bridge must be built.

## Revisit triggers

Same as Decision 2's list; each fires a small implementation slice, not
a redesign — the design section is the spec.

## References

ADR-0042 (secret sources, D2/D3/D5/D8 invariants), ADR-0017 4a (probe
observation never skips), ADR-0053 (crate seam rulings — placement of
the shared seam), 0afc6e8 (retry with backoff at the seam),
`/tmp/opencode/ratelimit-design.md` (research citations, §2 and §4),
docs.github.com rate-limit + best-practices pages, curl manpage
(`-H @file`, `--location-trusted`).
