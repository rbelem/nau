# Git Workflow

## Commits

- Use [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).
- Format before committing: `env -u LD_LIBRARY_PATH devbox run -- fmt`.
- Pass the full gate before pushing: `env -u LD_LIBRARY_PATH devbox run -- check`.

## Commit hook. Token budget

`scripts/hooks/pre-commit` refuses a commit where a staged file exceeds
**5,000 tokens** (1 token = 4 bytes, so 20,000 bytes). It measures the staged
snapshot, so the working tree alone never blocks a commit.

Install it once per clone. `git config core.hooksPath scripts/hooks`, or
`devbox run -- hooks`. The setting is per-clone; the script is versioned.

A file already over budget may shrink or hold and still commit. It may not
grow, and a new file may not arrive over budget. `NAU_TOKEN_BUDGET_STRICT=1`
removes that grandfather clause. `NAU_TOKEN_BUDGET` moves the limit.

Lockfiles, vendored trees, minified bundles, and generated sources are exempt.
To exempt a generated file the hook does not recognize, mark it in
`.gitattributes` with `<pattern> linguist-generated=true` in the same commit.
The failure message carries the split recipe; `git commit --no-verify` skips
the check for one commit.

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
- `nau.lock` — generated input lockfile
- `stage/` — staging directory used during builds
