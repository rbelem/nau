# Git Workflow

## Commits

- Use [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).
- Format before committing: `devbox run -- fmt`.
- Pass the full gate before pushing: `devbox run -- check`.

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
