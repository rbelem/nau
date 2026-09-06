# Dependency fetch for interpreted packages: offline-sandbox build, content-hash pin, optional float

## Status

Accepted (2026-09-05). Grounded in a `/grill-with-docs` session and a three-seat council review on dep-fetch safety and pin-vs-float. Extends ADR-0008 (package inputs), ADR-0012 (file-level content-addressed store), and the pod feature (ADR-0015). Naming invariant per ADR-0013 applies.

## Context

Interpreter-based packages need a dependency-fetch capability shuttle does not have. Concrete cases: `zg` (Node CLI with a large `node_modules` tree plus prebuilt native addons: onnxruntime-node, sharp, reflink, @zvec/bindings), `whichllm` (Python CLI with pip deps), `hermes-agent` (Python agent built via uv2nix, multiple releases a day on a date tag). Two structural blockers in shuttle today:

1. **The build sandbox is offline** (`--unshare-net`, ADR-0004) — `npm install` / `pip install` cannot run at build time.
2. **The source model fetches one tarball** (`source.url`, ADR-0008) — there is no npm/pip dependency resolution or lockfile for transitive closures.

Nix/nixpkgs solve this with **fixed-output derivations**: `buildNpmPackage` fetches the npm closure once (network allowed at fetch time) into a content-addressed store path pinned by `npmDepsHash`, then the sandboxed build runs `npm ci --offline` against it. Python (`buildPythonPackage`) does the same with a pip lock. Shuttle has no analog.

Council risk review (unanimous) on running the fetch outside the sandbox: the **sharpest risk is lifecycle/install scripts executing on the host** (`npm` postinstall, `pip` `setup.py` — arbitrary code). Nix avoids this by sandboxing the fetch itself (FOD runs in a derivation, `fetchurl` is a pure download); shuttle has no daemon, so it must make the fetch **side-effect-free** instead.

## Decision

1. **General dependency-fetch model, shipped first for npm and pip.** The mechanism — resolve a dependency closure, fetch it into the store, content-hash-pin it, then install offline inside the sandbox — is ecosystem-agnostic. npm and pip are the first two resolvers; gem/cargo follow the same shape.

2. **Fetch is a pure downloader, never an installer.** The fetch phase runs outside the sandbox with network, but downloads artifacts only: npm via the registry (tarball GETs driven by the resolved lockfile, `--ignore-scripts`; never `npm install` on the host), pip via `pip download` / uv `--no-build` (wheels/sdists only; never `pip install` on the host). **No lifecycle/install script ever executes on the host** — install (including any scripts) happens only inside the offline bubblewrap sandbox during the build (ADR-0004), where it cannot reach the host.

3. **The closure is content-hashed and lockfile-pinned.** After download, the materialized dependency tree is digested deterministically (NAR-style: sorted paths + contents) into a `deps_hash`, recorded in `shuttle.lock` under a per-package `deps` section alongside the existing source sha256 pin. The sandbox build verifies the hash before use and mounts only that one content-addressed store entry read-only — never a shared `~/.npm` / `~/.cache/pip`. First fetch is TOFU (same as `source.sha256` today: print the hash, let the user pin it); strengthen it by cross-checking registry integrity fields (npm `dist.integrity`, pip hash metadata) where available. The fetch may also exclude lock entries before any download — npm via `deps.npm.exclude` (globs over lock keys), uv.lock via the dev-dependency split (the dev-only subgraph is skipped, issue #14) — and the `deps_hash` pin covers the materialized post-filter closure.

4. **Locked by default; `floating = true` is an opt-in per package.** Locked: sync verifies the pinned `deps_hash` and never re-fetches — bit-reproducible. Floating (`floating = true`, for fast-moving packages like hermes-agent): sync re-resolves the latest closure, records the new `deps_hash` plus a `fetched_at` date-tag, and still hash-verifies during that build — float means "re-resolve", not "unverified". The last-known hash is kept so rollback to a prior generation always works. Floating packages are marked: `shuttle pod list` shows `(float)`, `sync` warns naming each floating package whose content changed.

5. **Generations always pin content.** Floating only controls whether the *next* sync changes the content; a built pod generation always holds its pinned content-addressed state, so rollback is unaffected. Floating sacrifices bit-reproducibility and offline rebuild for that one package — the author's explicit choice, never a silent default.

6. **DSL surface.** `source` and `deps` coexist on one package (a hybrid: a source tarball plus npm/pip deps), either alone, or neither. `deps` names the ecosystem resolver and its lockfile, e.g. `deps = { npm = { lock = "package-lock.json" } }` or `deps = { pip = { lock = "requirements.lock" } }`. Native prebuilt addons inside the closure (onnxruntime/sharp/zvec `.node` binaries) get the existing build-time ELF repair (patchelf interpreter/RUNPATH, tickets #10/#12) so their libstdc++ and loader resolve from the store.

7. **Command surface: auto + explicit.** `shuttle pod add` / `shuttle pod sync` auto-fetch a dependency closure when its `deps_hash` is not cached (before the offline build). An explicit `shuttle deps fetch [--latest]` forces a (re-)fetch — the float path and the "always latest" knob.

## Alternatives considered

- **Vendor `node_modules` into the source tarball.** Rejected: works one-off but cannot be pinned/reproduced cleanly, bloats sources, and hides the dependency closure from the lockfile.
- **Allow network inside the build sandbox.** Rejected outright: breaks ADR-0004's hermeticity guarantee and the reproducibility story; builds would depend on the registry state at build time.
- **Per-ecosystem one-off fetchers (npm-only first).** Rejected: the mechanism is ecosystem-agnostic; a general model avoids a second redesign at gem/cargo time.
- **Float via "no lockfile entry" (unchecked).** Rejected by council: float must still hash-verify each fetch and keep the last-known hash, or rollback and the audit trail are lost.
- **npm/pip integrity-only (no closure hash).** Rejected: registry integrity covers individual tarballs; the closure tree hash (layered on top) is what equals Nix's fixed-output guarantee.

## Consequences

**Positive**: interpreter-based packages (Node/Python CLIs and agents) become portable into pods; the build stays fully offline and hermetic; the dependency closure is content-addressed, lockfile-pinned, and rollback-safe; the fetch side is side-effect-free (no host script execution); fast-moving packages get an explicit, marked, still-verifiable float mode.

**Negative**: a new fetch phase runs with network outside the sandbox — the one place shuttle code touches the network besides source/inputs; per-ecosystem resolvers (npm, pip) must be maintained and their lockfile formats tracked; floating packages lose bit-reproducibility and offline rebuild by explicit choice; native prebuilt addons still depend on upstream shipping working prebuilds (the onnxruntime/sharp set), with ELF repair as the mitigation; TOFU on first fetch remains (mitigated by printed hashes and registry integrity cross-checks).
