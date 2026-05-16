# shoot — AGENTS.md

## Project

Rust CLI tool. GPL v3 (`LICENSE`).

Early stage — single initial commit, no code yet.

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
