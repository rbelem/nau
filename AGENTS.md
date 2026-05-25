# shoot — AGENTS.md

## Project

Rust CLI tool. GPL v3 (`LICENSE`).

Planning phase — 8-phase roadmap defined, no code yet.

## Quickstart (once `Cargo.toml` exists)

```bash
cargo build           # debug build
cargo build --release # release build
cargo run             # run the binary
cargo test            # all tests
cargo test <name>     # single test / test file
cargo clippy          # lint (warnings are errors)
cargo fmt             # format
```

## Build artifacts

`debug/`, `target/`, `*.rs.bk`, `*.pdb`, `**/mutants.out/` — all gitignored.

## Testing

- Tests live in `src/` alongside code (Rust convention).
- No integration test fixtures or external services needed at this stage.
- `cargo test` is the single command.

## Conventions

- `cargo fmt` before committing.
- Keep `clippy` clean — treat warnings as errors.
- Conventional commits for commit messages.

## Planning

- `PROJECT.md` — project context, core value, constraints, key decisions
- `REQUIREMENTS.md` — 17 v1 requirements with REQ-IDs
- `ROADMAP.md` — 8 vertical MVP phases
- `STATE.md` — project progress and decisions log
- `config.json` — workflow preferences (interactive, fine granularity, inherit model)

<!-- GSD:project-start source:PROJECT.md -->
## Project

**shoot**

A Rust CLI tool that builds Snap packages from Lua declarations. Inspired by Nix's declarative reproducibility and Neovim's Lua-based configurability, `shoot` replaces Snapcraft's YAML with a programmable, composable Lua DSL. Single snaps first — growing toward full Ubuntu Core image assembly.

**Core Value:** Define any Snap package with a simple Lua file — no Snapcraft YAML needed. Packaged, composable, version-controllable.

### Constraints

- **Language**: Rust stable only — no nightly features
- **Platform**: Linux (snaps target Linux; `mksquashfs` is Linux-native)
- **Output**: Standard `.snap` format compatible with `snapd`
- **License**: GPL v3 (inherited from project)
<!-- GSD:project-end -->

<!-- GSD:stack-start source:STACK.md -->
## Technology Stack

Technology stack not yet documented. Will populate after codebase mapping or first phase.
<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->
## Conventions

Conventions not yet established. Will populate as patterns emerge during development.
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->
## Architecture

Architecture not yet mapped. Follow existing patterns found in the codebase.
<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->
## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, `.github/skills/`, or `.codex/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->

<!-- GSD:profile-start -->
## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->

## Agent skills

### Issue tracker

Issues are tracked in GitHub Issues on `rbelem/shoot`. See `docs/agents/issue-tracker.md`.

### Triage labels

The five canonical triage roles use default label names. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.
