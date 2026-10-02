# ADR-0052: Upstream versions, build requests, and the server release path

## Status

Accepted. Settled in the grill session of 2026-10-01 with the operator
(question-by-question; the summary and sequencing were confirmed verbatim).
Implements ADR-0047 Decision 4 (constraint graduates to recipe-selection
input) for always-latest fetch recipes.

## Context

Always-latest recipes (e.g. `pkgs/o/opencode-bin.lua`) resolve their version
at eval time through `fetch()` of an upstream channel, record the observed
hash in the lockfile, and offer the operator no way to answer "what versions
exist upstream?" or "build 2.0.21, not latest". The distribution side has a
pull-only server (`nau serve`: GET manifests/blobs over a static tree,
`crates/nau-peer/src/serve.rs`), a local-only binary cache keyed by build
closure (ADR-0043 territory, unbuilt remotely), and worker fabric driven by
outbound SSH (`src/worker.rs`). Pods pin versions through `name@constraint`
(`PodPackageSpec`, `crates/nau-pod/src/pod.rs`) and the constraint already
reaches recipe eval as the `constraint` global (`crates/nau-chart/src/
isolate.rs:89-97`). No path exists to ask the server to build a version, and
`nau pod update` sources payloads by local build only.

## Decision

1. **`snap{.versions}` is a packager-implemented method.** A zero-arg
   function field on the snap table returning a Lua array of version
   strings, newest first. An empty array is a valid answer. Listing-only:
   it never feeds build resolution. Because functions cannot cross the
   worker's JSON output boundary, the eval worker gains a versions-mode
   that runs the chunk, calls the function in-process, and returns the
   array alongside the snap's own resolved `version`.

2. **`nau chart versions <file>`** prints the list (aligned table,
   `latest` marked on the recipe-resolved version) and takes `--json`.
   A recipe without a `versions` method is a named skip, not an error.

3. **The pod constraint is the version selector.** A recipe reads the
   `constraint` global: set, it must resolve to exactly that version and
   refuses (error) when the version is absent from its own `versions()`
   listing; nil, it keeps its default resolution (channel latest). No
   build-side `--to` flag; the pod spec is the surface.

4. **`nau serve` grows one POST route, `/build-requests`.** Bearer-token
   gated; tokens are issued manually by the operator on day one. Requests
   land in a file-backed queue directory. A farm-side drain loop
   (`nau build-request run`) farms each request to workers over the
   existing SSH verbs (`__worker-job`), then releases the artifact.

5. **Release lands in rustfs behind Caddy.** The drain signs the
   PackageManifest and uploads manifests plus blobs to rustfs over its S3
   API; Caddy fronts rustfs with TLS and serves the static tree. Clients
   keep the existing HTTPS `Url` pull lane unchanged — no new nau
   transport, and ADR-0043 (closure-keyed remote cache) stays a separate
   future lane.

6. **`servers` is a list.** Nau's system config carries `servers`, a list
   of server fronts, ordered; a pod may override with its own list.
   Resolution: pod override → system list, tried in order → error with a
   provisioning hint.

7. **The platform is deferred, the seam is not.** Accounts, subscriptions,
   quotas, and gated access are a separately planned effort. The manual
   bearer token on `/build-requests` is the integration point; signature
   gating (trust set, revocation, freshness) remains the download trust
   model regardless of what issues the tokens.

8. **Explicitly open: how pods source payloads from servers.** The
   `nau pull` relationship (pull-first update chain, `--request-build`
   fallback) is to be defined in a later session. `nau pod update` keeps
   its local-build behavior until then.

## Security

- `/build-requests` requires a bearer token before it accepts anything;
  unauthenticated POST is a 4xx, never a queue write. Tokens are operator-
  issued secrets, revocable by removal from the farm's token file.
- Build requests carry the target recipe identity and version; the drain
  re-evaluates recipes farm-side and never executes client-supplied build
  text. The release path is the existing fail-closed chain: signed
  manifest, trust-set verify, target gate, freshness/downgrade gate.
- Queue writes are atomic (temp file + rename); one request file per
  build; the drain claims by rename before dispatch.

## Consequences

**Positive.** Operators get an upstream-version surface (`nau chart
versions`) instead of scraping channels by hand. The pod constraint
becomes a real selector for floating recipes, not just a hold gate. The
farm becomes askable: a device without toolchain can request a version and
pull the released snap. rustfs + Caddy reuses the deployment pattern the
infrastructure already runs.

**Negative.** `nau serve` stops being strictly read-only (one POST route,
token-gated). Recipes grow a second eval mode to test. Until the pull
discussion closes, requesting a build does not automatically install into
a pod — the artifact lands in the server tree and a human pulls it. The
manual token file is a stopgap the platform effort must replace.

## References

- ADR-0047 (version coexistence; Decision 4 is the constraint-as-input
  threading this ADR lands for fetch recipes)
- ADR-0043 (remote build cache — deliberately not this lane)
- ADR-0033 (pod store / install workflow; pulls stage, pods install)
- `crates/nau-peer/src/serve.rs`, `crates/nau-ship/src/pull_peer.rs`,
  `src/worker.rs` — the surfaces this ADR extends
