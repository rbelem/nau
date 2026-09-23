# Git Workflow

## Commits

- Use [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).
- Format before committing: `env -u LD_LIBRARY_PATH devbox run -- fmt`.
- Pass the full gate before pushing: `env -u LD_LIBRARY_PATH devbox run -- check`.

## Lane worktrees

A cow worktree clones the checkout INCLUDING its uncommitted files, so every
lane starts with the operator's WIP docs riding along. A lane stages only the
files it owns (name them in `git add`), never `git add -A`/`git add .`, and
leaves pre-existing dirty files untouched for the merge to sort out.

## Generated files — do not commit

Cargo defaults, already covered by `.gitignore`:

- `target/`, `debug/`
- `**/*.rs.bk` — rustfmt backups
- `*.pdb` — MSVC debug info
- `**/mutants.out/` — cargo-mutants output

Project build outputs, also ignored:

- `*.snap` — built packages
- `shuttle.lock` — generated input lockfile
- `stage/` — staging directory used during builds
