# Pod services: declarative `services = { … }` emitted through service backends

## Status

Accepted (2026-09-19), revised same day after a two-seat council review.
Records the T13 §5.4 services disposition (council 2026-09-18: services
are out-of-band systemd user units — a carve-out from ADR-0015 Decision
10, whose "no systemd user units" was scoped to *activation*) and
exercises §5.4's re-open trigger in the declarative direction. Grounded
in ADR-0015 (pods, verb set, collision classifier), ADR-0016's shared
grants vocabulary + `backend_options` escape hatch, ADR-0028 (farm-first
activation seams), ADR-0030 (generation-scoped declared literals), the
desktop (issue #7, `src/desktop.rs`) and font (`src/fonts.rs`) emitters
as mechanism precedents, and a process-manager survey
(`.planning/research/process-manager-survey-2026-09-19.md`).

## Context

devbox-global ran the cutover's three user services — `valkey` (with the
valkey-search module), `bifrost`, `wigolo` — under devbox's process-compose.
Pods have no service verb (ADR-0015's verb set), and the council
disposition of 2026-09-18 (`docs/t13-cutover-checklist.md` §5.4) chose
hand-written units to ship in `examples/cutover/`, with `ExecStart`
through the pod's `current` symlink. That disposition carried two known
defects and one latent one:

1. The units are ambient machine state — invisible to
   `shuttle pod sync`, to rollback, and to any other pod; nothing
   re-emits them and the checklist itself notes they must be manually
   restarted after a pod rollback (a flip does not restart running
   daemons).
2. They duplicate configuration the packages already know (binary name,
   module path, flags) — the same duplication the desktop emitter
   eliminated for `.desktop` files.
3. Multi-pod reality was left undefined: units share one systemd user
   namespace, so two pods declaring the same service collide on unit name
   unless namespaced, and systemd supervises but never dedupes — two
   valkeys are two valkeys, and same-port collisions crash-loop.

Two platform constraints shape the design:

- **shuttle targets exist without systemd.** WSL2 defaults to systemd
  off (opt-in via `/etc/wsl.conf`); Devuan, antiX, and Slackware run
  SysV or comparable inits with no user-session manager at all. A
  services surface that only emits systemd units would make pods
  second-class on exactly the machines pods serve (dev containers).
- **macOS is a planned host.** Its user-service manager is launchd
  (LaunchAgents), a different artifact and lifecycle entirely.

The owner's requirement: service configuration done **like in Nix** —
declarative, options-with-defaults, artifacts generated as derived files,
enable state part of the declaration, activation a diff-and-switch.
§5.4's re-open trigger anticipated exactly this: *"a service must become
pod-declared or machine-portable — then the design is packages declaring
`services = { … }` emitted through the launcher/font emitter family,
never a verb."* This ADR exercises that trigger and makes the backend a
detail of the emitter, not of the declaration.

## Decision

1. **Services are declared, never verb-managed.** Packages declare
   services alongside `apps`; pod declarations set per-service options.
   The ADR-0015 verb set is unchanged — there is no `service` verb and
   there never is one (the §5.4 trigger language, now policy).

2. **Package-level declaration with NixOS-style options + defaults.**
   A service is built with a `service()` constructor in
   `pkgs/lib/daemon.lua` — the file exists today exporting `app()` for
   the Snap `apps` half; `service()` is new, and the two daemon
   vocabularies (Snap's `daemon = "simple"` app key and the service
   `daemon` kind below) share one spelling deliberately:

   ```lua
   -- pkgs/v/valkey/init.lua
   local svc = require("pkgs.lib.daemon").service

   return {
     name = "valkey",
     -- … build / apps as today …
     services = {
       valkey = svc {
         command = "bin/valkey-server",
         daemon  = "simple",                      -- simple | notify | forking; oneshot is out of scope for v1
         args    = { "--port", "${port}",
                     "--dir",  "${data_dir}",
                     "--loadmodule", "${extensions}/valkey-search/…so" },
         options = {
           port        = 6379,
           data_dir    = "%h/.local/share/shuttle/valkey/%p",
           enabled     = false,                     -- NixOS `enable` semantics
         },
         after   = { "valkey" },   -- advisory ordering between shuttle services
         environment = { VALKEY_QUIET = "yes" },  -- literals per the ADR-0030 spirit
       },
     },
   }
   ```

   Interpolation: `${name}` resolves the service's own declared options
   plus exactly one built-in — `${extensions}`, the active generation's
   extensions dir resolved through `current` (Decision 6's seam) — and
   nothing else: no ambient env expansion, no other implicit farm paths
   (ADR-0030's literal rule, extended through its recorded revisit
   trigger for an explicit interpolation vocabulary). `%h` and `%p`
   (home, pod name) are **shuttle's own emit-time specifiers**, expanded
   by the emitter into absolute literals on every backend: the spelling
   borrows systemd's, but `%p` is not systemd's unit-prefix `%p` (which
   would expand to the whole unit name, not the pod), and no `%`-token
   ever reaches a backend artifact unexpanded. `daemon` and `after` are
   **advisory shared vocabulary**: every backend must accept them;
   backends that cannot honor them exactly degrade per Decision 5.
   `after` is a best-effort ordering hint, never a readiness contract.

3. **Pod-level option overrides** (configuration.nix ≙ the `pod {}`
   block):

   ```lua
   pod {
     packages = { "valkey", "bifrost", "wigolo" },
     services = {
       valkey = { port = 6380 },      -- defaults fill the rest
       wigolo = { enabled = true },   -- enabling is explicit
     },
   }
   ```

   Layering follows the existing rule: package defaults < loaded pods <
   own declaration; cross-layer override warns naming winner and loser;
   same-precedence duplicate service *names* are a hard error — the
   shared collision classifier (`crate::farm::classify_collision`),
   service-flavored. Service names are constrained to `[a-z0-9-]` (the
   classifier's invocation point), so the per-backend identifier
   mappings in Decision 9 are total.

4. **The manifest is the source of truth; the emitter family gains a
   third member (`src/services.rs`) with swappable backends.** Like
   desktop (#7) and fonts: the manifest records each package's
   `ServiceUnit` — the shared vocabulary of Decision 2 with options
   resolved — and each record's hash covers the rendered artifact AND
   the owning package's manifest digest. The emitter writes backend
   artifacts INSIDE the pod generation (`services/` beside `launchers/`
   and the bin farm) and surfaces them through pod-namespaced user-level
   links. Rollback re-emits the target generation's link set from the
   manifest alone.

5. **Three backends, one shared vocabulary.** Artifact and lifecycle
   mapping (`restart` and `logs` are fixed emitted policy, not
   declaration knobs):

   | Declaration | systemd (Linux) | launchd (macOS) | portable (no manager) |
   |---|---|---|---|
   | artifact | `generations/<n>/services/shuttle-pod-<pod>-<svc>.service` → link in `~/.config/systemd/user/` | `generations/<n>/services/shuttle.pod.<pod>.<svc>.plist` → link in `~/Library/LaunchAgents/` | `generations/<n>/services/supervisor.<fmt>` (config consumed by a packaged supervisor) |
   | `daemon = simple` | `Type=simple` | `KeepAlive` + `RunAtLoad` | supervisor restart policy |
   | `daemon = notify` | `Type=notify` | degraded: `KeepAlive` | degraded: supervisor restart policy |
   | `daemon = forking` | `Type=forking` | **unsupported**: launchd cannot supervise a forking daemon (parent exit means job completion; `KeepAlive` would respawn it — launchd has no `Expect`, that is Upstart vocabulary) — sync-time warning to run foreground or use `backend_options` | supervisor daemon flag if it has one, else degrade with warning |
   | `after` | `After=` against declared shuttle services; `Requires=` is deliberately never emitted (a hard dependency is reachable via `backend_options`); naming a system target warns — user units cannot order against the system manager | **ignored** (launchd has no ordering), sync-time warning | config order (advisory) |
   | `environment` | `Environment=` lines, plus the generation's `env.json` (ADR-0030) and an emitter-injected `LD_LIBRARY_PATH` over the generation's loader-lib dirs (the ADR-0028 seam — farm-exec'd processes get no shell) | `EnvironmentVariables` dict + same injections | supervisor env block + same injections |
   | restart | `Restart=on-failure` | `KeepAlive={SuccessfulExit=false}` | supervisor restart/backoff |
   | logs | journal | `StandardOutPath`/`StandardErrorPath` under the pod data dir | supervisor log files |
   | `enabled` | unit linked with `[Install] WantedBy=default.target`, enabled and started at sync (`disable`+`stop` on withdrawal) — the unit-file link alone does not auto-start | plist bootstrapped (`launchctl bootstrap gui/$UID`) | entry active in the supervisor's running config |

   Backend-specific raw fields follow the ADR-0016 grants pattern: a
   non-portable `backend_options = { systemd = { … }, launchd = { … } }`
   sub-table passes through verbatim; the portable backend has no
   passthrough (its supervisor is declared, not raw-scripted). `daemon`,
   `after`, and passthrough are the ONLY per-backend divergence points.

6. **Program paths bake the farm path in every backend** — the resolved
   absolute `<home>/.local/share/shuttle/pods/<pod>/current/bin/…` as
   `ExecStart`, `ProgramArguments` element, or supervisor command. The
   `current` flip is the activation seam everywhere: artifacts survive
   rollbacks without rewriting, and `--loadmodule` reaches
   `current/extensions/…` the same way (§5.4's original insight, kept).
   Confinement rides the farm path unchanged: a `confined` service's
   entrypoint resolves through `current/bin/<cmd>`, which is the
   `shuttle run` wrapper (ADR-0016) — the emitter is
   confinement-agnostic; grants on services follow ADR-0016 defaults.

7. **`enabled = false` keeps the service dormant in the generation** for
   every backend: the artifact is emitted into the generation but the
   user-level link/registration is withheld — declaring a package never
   starts anything; enabling is an explicit, reversible declaration edit
   (NixOS `enable` semantics).

8. **Activation is the reconcile tail of every generation-changing verb
   — sync, add/remove, and rollback alike — with
   switch-to-configuration semantics.** Each verb's tail diffs
   per-service hashes (Decision 4: rendered artifact + owning package's
   manifest digest) against the live registrations, then: reload the
   manager (`daemon-reload` / launchd re-registration is
   `bootout` + `bootstrap` / supervisor config reload); activate new,
   changed, or newly-enabled services; deactivate withdrawn or disabled
   ones. Deactivation is **stop-then-withdraw** per backend
   (`systemctl --user stop` before link removal; `launchctl bootout`
   before the plist link; supervisor entry removed, then reload) — a
   registration is never pulled from under a running service. Because
   the hash covers the package digest, a binary-only upgrade (version
   bump, unchanged options) also restarts the service. This *resolves*
   §5.4's restart caveat on the flip itself — rollback included, no
   follow-up sync required. On the systemd backend, the tail warns when
   lingering is off for a pod with enabled services
   (`loginctl show-user -p Linger`): without lingering the services stop
   at the user's last logout. Enabling linger is a one-time host step,
   documented and never performed silently. Ad-hoc control remains the
   manager's own CLI (`systemctl --user`, `launchctl`, the supervisor's
   control command); config changes go through the declaration.

9. **Multi-pod duplication: namespaced coexistence, option-driven
   isolation, no auto-dedup.** Service IDs are namespaced per pod in
   every backend (`shuttle-pod-<pod>-<svc>` / label
   `shuttle.pod.<pod>.<svc>` / supervisor process name
   `shuttle-<pod>-<svc>`), so two pods' same-named services coexist
   exactly like their binaries. They must not share endpoints: resolved
   endpoint options (port, socket path, data dir) colliding across pods
   is a hard error at reconcile time, named in full — the check is a
   read-only scan of all pods' active generations, comparison not a
   registry, nothing persisted across pods. True dedup is a deployment
   pattern, not machinery: one provider pod runs the daemon
   (`enabled = true`), other pods declare it disabled and consume the
   endpoint. A cross-pod dedup registry is out of scope; re-open if a
   real requirement appears.

10. **Supervisor policy: use the manager the host has; bring a packaged
    one only where the host has none.** On systemd hosts the user
    manager is the supervisor — full stop (the survey found no process
    manager that improves on it there: process-compose, goreman,
    immortal, mprocs all trade down). On portable-backend hosts (WSL2
    without systemd, SysV) there is no user manager to duplicate, and a
    **packaged supervisor from the pool** runs the pod's services:
    process-compose is the preferred pool package (single static Go
    binary, daemon mode, restart policies, readiness probes — the
    survey's best-in-class); goreman is the minimal fallback. Shuttle
    generates the supervisor's config INSIDE the generation and drives
    it through its documented CLI at reconcile time; shuttle remains the
    source of truth and the diff engine, the supervisor is a dumb
    runtime. A shuttle-builtin supervisor daemon is rejected — it
    reintroduces the long-running daemon ADR-0015 Decision 10 rejected.

11. **Backend detection is fail-closed; sequencing is systemd → portable
    → launchd.** Selection: `SHUTTLE_SERVICE_BACKEND` override (tests,
    explicit choice) → macOS host ⇒ launchd → systemd user manager
    reachable ⇒ systemd → else portable. A declaration whose resolved
    backend cannot honor a requested feature degrades with a named
    reconcile-time warning, never silently. Implementation order:
    systemd first (the cutover hosts), portable second (WSL2-no-systemd
    and SysV users exist today; it is also the test harness for backend
    neutrality), launchd with the macOS port. The emitter lands WITH the
    first service-carrying pool port — a package cannot declare
    `services = { … }` before the surface exists, so ports and emitter
    are one changeset per backend, never sequenced apart. Until the
    emitter lands on a host, that host has no service surface — the
    `examples/cutover/` units remain the Linux/systemd bootstrap.

## Alternatives considered

- **Hand-written out-of-band units (the 2026-09-18 disposition as
  written).** Kept as the cutover bootstrap; superseded once the
  emitter lands. Ambient state, invisible to sync/rollback, manual
  restarts, duplicated knowledge.
- **`shuttle pod service <verb>`** — rejected: violates the ADR-0015
  verb set; an imperative surface would fork the source of truth the
  declaration file owns.
- **systemd-only emitter.** Rejected: makes pods second-class on WSL2
  (systemd off by default) and SysV distros, and bakes systemd vocabulary
  (`Type=`, `After=`) into the DSL — a later macOS port would then face a
  breaking DSL migration instead of a backend.
- **process-compose (or any supervisor) as the universal backend.**
  Rejected on systemd hosts — redundant supervision under the existing
  manager, and its readiness/dependency features map to
  `Type=notify`/`After=`/`ExecStartPost`. Sanctioned only as the
  portable backend's runtime (Decision 10).
- **Machine-level hoisted units with first-declarer-wins.** Rejected for
  now — needs a cross-pod registry and a "which pod's binary serves"
  rule; namespaced coexistence + option isolation covers the real cases.
  Re-open trigger: dedup becomes a requirement rather than a pattern.
- **cron `@reboot` as a service mechanism.** Rejected — no supervision,
  no restart, no logs. Kept only as the *login/boot hook* that starts the
  portable backend's supervisor on SysV hosts (one idempotent,
  shuttle-marked crontab line), where no session manager exists to do it.
- **runit / s6-rc family.** Rejected: excellent supervisors, wrong
  payload shape — multi-binary C toolboxes with directory conventions,
  not single-payload pool packages; and they'd duplicate the host
  manager again.
- **Native Windows services.** Out of scope: the runtime is Linux-only
  (and macOS per the planned port); WSL2 is covered by the portable or
  systemd backend. Re-open if shuttle itself ships on Windows.

## Consequences

**Positive**: services become generation-scoped and rollback-revertible
like every other pod surface, on every host class; Nix-style declarative
config with options/defaults and explicit enablement; the declaration is
stable across platforms — adding macOS or WSL2-no-systemd support is an
emitter backend, not a DSL change; multi-pod coexistence rides
existing ID/collision machinery; §5.4's restart caveat disappears (the
reconcile tail restarts changed services on the flip itself); the
process-manager survey work is preserved as the portable backend's
runtime choice instead of being discarded.

**Negative**: three backends to test, and the portable backend needs its
own start-at-login story per host (a shuttle-marked crontab line on
SysV; on WSL2 a root-owned `/etc/wsl.conf` `[boot]` line that runs the
supervisor as the pod user — the one system-config touch, documented as
such); launchd ignores `after` and cannot supervise `daemon = forking`
at all, so cross-backend behavior is not identical by design
(degradations are warned, never silent); the portable backend adds a
supervisor dependency on non-systemd hosts (pool package, version-pinned
like any other); systemd user services require lingering to survive
logout — a host-level, non-generation-scoped bit the reconcile tail can
only warn about; service secrets have no declared surface yet — until
one lands, credentials reach daemons the way they did under
process-compose (host-managed env), not through the declaration; "stop a
service temporarily" is overruled by the next reconcile unless the
declaration says `enabled = false` — the Nix trade, accepted; the
classifier compares APPLIED state, not live manager state, so ad-hoc
`systemctl --user stop`/`disable` drift is detected only when a hash
next moves — an accepted trade (issue #109 N14), since the converge on
the next sync is cheap while a live manager-state probe would tax every
sync; duplicate
services across pods remain the user's option discipline until a dedup
requirement re-opens the registry question.

## Revisit triggers

- A service must carry secrets (API keys, tokens) → design an env-file
  surface (`EnvironmentFile`-shaped, redacted from the manifest) —
  never raw literals in the declaration.
- Readiness must gate ordering (valkey *healthy*, not merely started,
  before bifrost) → supervisor readiness probes on the portable backend,
  `Type=notify` where daemons support it, or an `ExecStartPost`-shaped
  probe field.
- Dedup becomes a requirement rather than a pattern → the cross-pod
  registry question (Decision 9) re-opens.
- A service must declare `oneshot` semantics → extend the `daemon`
  vocabulary.
- Shuttle ships on Windows → native services backend (Task
  Scheduler-shaped), evaluated then.

## Evidence

- Emitter precedents verified in source: `src/desktop.rs` header
  contract (generation-scoped artifacts, `current`-flip `Exec`, pod-
  namespaced IDs, `farm::classify_collision`), `src/fonts.rs` (the
  mechanism mirrored verbatim), `pkgs/lib/daemon.lua` (the `app()` half
  the `service()` constructor extends).
- Platform claims checked against the survey
  (`.planning/research/process-manager-survey-2026-09-19.md`) and
  primary docs: launchd has no ordering and no `Type=notify` analog;
  `%p` in systemd is the unit prefix; launchd plists do no specifier
  expansion; WSL2 defaults to systemd off; SysV has no user-session
  manager; `KeepAlive={SuccessfulExit=false}` is the `Restart=on-failure`
  analog; launchd re-registration requires `bootout` before `bootstrap`.
- Carve-out legitimacy: ADR-0015 Decision 10's original wording scopes
  "no systemd user units" to activation; this ADR's services are
  generated artifacts activated by the reconcile tail, and systemd
  remains the ad-hoc control surface.
