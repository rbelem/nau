# Process-manager survey for pod services (2026-09-19)

Grounding artifact for ADR-0032 (Decision 10). Research method: live
GitHub API queries (repos listed below, queried 2026-09-19), skarnet.org
and smarden.org primary pages, process-compose official docs. Complements
the orchestrator-level survey conversation; all release dates as
published upstream.

## Question

Can any process manager / service supervisor replace the systemd user
manager for pod services — or serve where no user manager exists (WSL2
with systemd disabled, SysV)? Constraints: single self-contained binary
(pool-package payload), unprivileged user, headless under an
out-of-band launcher, multi-service config with restart policies.

## Verdict

No candidate improves on the systemd user manager where one exists. On
hosts without one, **process-compose** is the best packaged runtime
(portable backend); goreman is the minimal fallback. The full ranking:

| # | Tool | Shape | Headless | Multi-service config | Restart/readiness | Status (2026-09) | Verdict |
|---|---|---|---|---|---|---|---|
| — | process-compose (F1bonacc1) | Go static | ✅ daemon mode | ✅ one YAML | ✅ both | active (docs Feb 2026) | benchmark; portable-backend choice |
| 1 | goreman (mattn) | Go static | ✅ SIGTERM fan-out | ✅ Procfile | ❌ neither | v0.3.19 Jul 2026, active | minimal fallback |
| 2 | immortal (immortal) | Go static | ⚠️ self-daemonizing | ❌ one YAML per service | ✅ backoff restarts | v0.24.7 Jul 2026 | real supervisor, bad ergonomics |
| 3 | hivemind (DarthSim) | Go static | ✅ | ✅ Procfile | ❌ | dormant since 2021 | freeze-in-time only |
| 4 | mprocs (pvolok) | Rust static | ❌ TUI-only | ✅ | ❌ | v0.9.6 Jun 2026, active | interactive companion only |
| 5 | overmind (DarthSim) | Go | ❌ hard tmux runtime dep | ✅ Procfile | ⚠️ | v2.5.1 Mar 2024, slowing | fails self-contained |
| ❌ | s6 / s6-rc (skarnet) | C multi-binary suite | ✅ | dir-based | ✅ | Jan 2026 release wave | wrong payload shape |
| ❌ | runit | C multi-binary | ✅ | dir-based | ✅ | 2.2.0 Sep 2024 | wrong payload shape |
| ❌ | supervisord, honcho, foreman, pm2 | Python/Ruby/Node | — | — | — | various | hard fail: runtime dependency |

Newer entrants, all pre-release/hobby-stage as of 2026-09: dekit
(pvolok, canary only), provisr (loykin, 2 stars), procman (a-chacon, no
release), prox (fgrosse, minimal), APM (processmanager.dev, unvetted),
Oxmgr (unvetted).

## Key facts used by ADR-0032

- process-compose: daemon mode (`-D`), `depends_on` with readiness
  probes, `restart: on-failure/always`, per-process `log_location` —
  designed for exactly the headless slot; still nothing beats it in the
  niche, which is why it is the portable backend's runtime rather than a
  universal one.
- goreman: Procfile, foreground runner, graceful signal fan-out
  (`KillMode=mixed` under a unit); no restart policy, no readiness.
- immortal: per-service YAML under `~/.immortal/dir`, `immortalctl`,
  self-daemonizing — awkward under a single `ExecStart`-shaped launcher.
- mprocs must own the terminal; overmind spawns processes inside tmux
  panes (tmux is a runtime dependency).
- s6 (skaware Jan 2026 wave, new `s6-frontend`) and runit are excellent
  supervisors but multi-binary toolboxes — not single-payload pool
  packages.
- honcho/foreman/supervisord/pm2 require a language runtime at runtime —
  excluded by the pool-package constraint.
- macOS launchd specifics used in ADR-0032 Decision 5: labels namespaced
  by dots, `KeepAlive={SuccessfulExit=false}` ≙ `Restart=on-failure`,
  no dependency ordering, no `Type=notify` analog, no specifier
  expansion in `ProgramArguments`, re-registration requires
  `launchctl bootout` before `bootstrap`; there is no `Expect` key
  (Upstart vocabulary) so forking daemons are unsupervisable.
- systemd specifics used in Decision 5/8: `%p` expands to the unit
  prefix (not a pod name); auto-start needs `[Install]
  WantedBy=default.target` + enablement, not just a unit-file link;
  user services die at last logout without `loginctl enable-linger`;
  user units cannot order against system-manager targets
  (`network.target` is unreachable from `--user`).
