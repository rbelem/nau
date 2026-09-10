# shuttle — AGENTS.md

Rust CLI that builds Snap packages from Lua declarations — a programmable
replacement for Snapcraft's YAML. GPL-3.0-only, Linux-only. Formerly named
*shoot* (ADR-0013). Package manager: Cargo, pinned through devbox (not npm).

## Build, test, lint

Use the pinned devbox toolchain — do not assume the system `cargo` matches:

```bash
devbox run -- build       # cargo build
devbox run -- test        # cargo test (unit + integration)
devbox run -- clippy      # cargo clippy -- -D warnings
devbox run -- fmt-check   # cargo fmt --check
devbox run -- check       # test + clippy + fmt-check
```

Run `devbox run -- check` before committing or pushing. Clippy warnings are errors.

## Detail docs

- [Build & test](docs/agents/build-and-test.md) — commands, test layout, gates
- [Git workflow](docs/agents/git-workflow.md) — commits, generated files
- [Planning & docs](docs/agents/planning-and-docs.md) — grill-with-docs, CONTEXT.md, ADRs
- [Project context](docs/agents/project-context.md) — constraints, stack, where things live
- [Domain model](docs/agents/domain.md) · [Issue tracker](docs/agents/issue-tracker.md) · [Triage labels](docs/agents/triage-labels.md)
