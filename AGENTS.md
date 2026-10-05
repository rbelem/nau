# nau — AGENTS.md

Rust CLI that builds Snap packages from Lua declarations — a programmable
replacement for Snapcraft's YAML. GPL-3.0-only, Linux-only. Formerly named
*shoot*, then *shuttle* (ADR-0013, ADR-0031). Package manager: Cargo, pinned
through devbox (not npm).

## Build, test, lint

Use the pinned 1.97.1 toolchain — devbox and the gate pod both carry it, and
the pod payload follows the devbox pin (the pin is the contract). The pod env
leaks `LD_LIBRARY_PATH` into the shell (breaks devbox's node), and
`COMPILER_PATH`/`LIBRARY_PATH` redirect every gcc driver's subprogram search
into pod store blobs (libbfd load deaths), so strip all three and pin CC/CXX:

```bash
nix shell nixpkgs#gcc -c env -u LD_LIBRARY_PATH -u COMPILER_PATH -u LIBRARY_PATH CC=gcc CXX=g++ devbox run -- build
nix shell nixpkgs#gcc -c env -u LD_LIBRARY_PATH -u COMPILER_PATH -u LIBRARY_PATH CC=gcc CXX=g++ devbox run -- test
bash scripts/gate.sh   # full gate (test + clippy -D + fmt-check, gcc14 pinned)
nau run --pod gate -- cargo clippy -- -D warnings   # lint axis, pod gate
nau run --pod gate -- cargo fmt --check             # fmt axis, pod gate
```

Keep the pod shellenv on PATH (git and the curl shim ride it); the nix gcc
prepend plus `CC=gcc` keeps every compiler invocation off the pod blobs.

Run the corrected full-gate invocation above before committing or pushing.
Clippy warnings are errors. Ratified: the pod gate is the verified substitute
for the clippy/fmt axes (verdicts matched the devbox pin on the daily-host
reruns — see Build & test); the
test axis stays devbox until the gate pod also carries the build-host tools
the suite spawns — see [Build & test](docs/agents/build-and-test.md).

**Heavy compiles are pool-only.** Never spin heavy compile jobs on this
workstation: workspace gates, `--workspace` builds, multi-crate check/test
loops, or any parallel compile lanes. The host carries 15 GB RAM and finite
/home — six parallel cargo lanes OOM'd it into a restart storm, and one gate
run per lane (~35 GB of `target/` each) filled /home to 100%. Submit heavy
jobs to pool workers instead (`nau build-request submit`/`drain` per
nau-farm-ops; `nau run --pod gate` for the clippy/fmt axes). Local cargo is
rationed to ONE foreground scoped job at a time — single crate (`-p`), no
other cargo/devbox process alive — and run `scripts/target-clean.sh` when a
lane's work is done so `target/` doesn't accumulate across lanes.

## Detail docs

- [Build & test](docs/agents/build-and-test.md) — commands, test layout, gates
- [Verb → state map](docs/agents/verb-state-map.md) — what each verb touches; where live state actually lives (systemd, not nau)
- [Git workflow](docs/agents/git-workflow.md) — commits, generated files
- [Planning & docs](docs/agents/planning-and-docs.md) — grill-with-docs, CONTEXT.md, ADRs
- [Project context](docs/agents/project-context.md) — constraints, stack, where things live
- [Domain model](docs/agents/domain.md) · [Issue tracker](docs/agents/issue-tracker.md) · [Triage labels](docs/agents/triage-labels.md)
