# nau — AGENTS.md

Rust CLI that builds Snap packages from Lua declarations — a programmable
replacement for Snapcraft's YAML. GPL-3.0-only, Linux-only. Formerly named
*shoot*, then *shuttle* (ADR-0013, ADR-0031). Package manager: Cargo, pinned
through devbox (not npm).

## Build, test, lint

The pinned toolchain is 1.99.0. `devbox.json` pins rustc, cargo, clippy and
rustfmt at 1.99.0, and `devbox.lock` records the nixpkgs revision they resolve
from. The gate pod still carries 1.97.1 — its rust payload is sideloaded, so
its version moves only when a new payload replaces it — which means the pod
gate and CI compile with different compilers until that happens; #23 tracks
closing that gap. Until it does, CI's clippy and fmt verdicts are the
authority and the pod gate is a 1.97.1 approximation of them, not a
substitute. The pod env leaks `LD_LIBRARY_PATH` into the shell (breaks devbox's node), and
`COMPILER_PATH`/`LIBRARY_PATH` redirect every gcc driver's subprogram search
into pod store blobs (libbfd load deaths), so strip all three and pin CC/CXX:

```bash
nix shell nixpkgs#gcc -c env -u LD_LIBRARY_PATH -u COMPILER_PATH -u LIBRARY_PATH CC=gcc CXX=g++ devbox run -- build
nix shell nixpkgs#gcc -c env -u LD_LIBRARY_PATH -u COMPILER_PATH -u LIBRARY_PATH CC=gcc CXX=g++ devbox run -- test
bash scripts/gate.sh   # full gate (test + clippy -D + fmt-check, gcc14 pinned)
nau run --pod gate -- cargo clippy -- -D warnings   # lint axis, pod gate
nau run --pod gate -- cargo fmt --check             # fmt axis, pod gate
devbox run -- luacheck                              # Lua lint axis
devbox run -- stylua                                # Lua style axis
devbox run -- shellcheck                             # shell script lint axis
```

The three Lua/shell axes cover `pkgs/`, `test-fixtures/`, and every script
under `scripts/`. CI runs the same three devbox scripts, so a local green and
a CI green mean the same thing.

**The token-budget gate.** A staged file may not exceed 5,000 tokens (20,000
bytes). A file already over that limit may not grow by a single byte — the
repo's last 40 commits shrank 39 of the over-budget files they touched and
held the fortieth; none grew. So a change to a big file moves its new code
into a new module and leaves the old file at or below its current size, and
the gate's refusal is the design working. `scripts/split-inline-tests.py
<file.rs>` moves an inline `#[cfg(test)] mod tests` into a sibling module
directory that keeps `super::` access; run `cargo fmt` after applying it.

Keep the pod shellenv on PATH (git and the curl shim ride it); the nix gcc
prepend plus `CC=gcc` keeps every compiler invocation off the pod blobs.

Run the corrected full-gate invocation above before committing or pushing.
Clippy warnings are errors. Ratified: the pod gate is the verified substitute
for the clippy/fmt axes (the verdicts matched on the daily-host reruns, when
both lanes carried the same compiler — see Build & test); the
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

**When no pool worker is provisioned** (`tailscale status` lists no worker
node), a heavy build cannot run here at all. Run the static axes instead:
recipe loading, closure order, and source URL and hash resolution. Then hand
the build to a pool window. A recipe change nobody built is unproven, so
report it that way rather than as done.

## Detail docs

Reach for these by what you are about to change:

- [Build & test](docs/agents/build-and-test.md) — before running a gate or
  adding a test: the commands, the test layout, which axis runs where.
- [Verb → state map](docs/agents/verb-state-map.md) — before changing what a
  verb touches: which state each verb reads and writes, and where that state
  actually lives (systemd, not nau).
- [Domain model](docs/agents/domain.md) — before naming a type, a field, or a
  package concept: the terms this repo already uses.
- [Git workflow](docs/agents/git-workflow.md) — before committing, and before
  adding a generated file: the commit shape and what is generated.
- [Planning & docs](docs/agents/planning-and-docs.md) — before writing a
  design note, an ADR, or a CONTEXT.md update: how planning happens here.
- [Project context](docs/agents/project-context.md) — before touching the
  stack or the constraints: what this project is and what it must not do.
- [Issue tracker](docs/agents/issue-tracker.md) · [Triage labels](docs/agents/triage-labels.md) —
  before filing or triaging an issue: how issues are written and labelled.
