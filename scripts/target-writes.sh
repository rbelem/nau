#!/usr/bin/env bash
# Only target-clean.sh may invoke cargo clean, and it must go through the
# claim channel. A cleaner that bypasses the claim deletes artifacts
# under a live run — the failure the claim channel exists to prevent
# (issue #14). This check fails the gate instead of waiting for one.
#
# Discovery is by shebang, not by file name, the same boundary
# scripts/shellcheck-all.sh draws: the scripts that run unattended
# (scripts/hooks/pre-commit, scripts/nau-cache-publish) carry no
# extension, so a `*.sh` glob would miss the very cleaner this check
# exists to catch.
#
# Usage: target-writes.sh [scripts-dir]   (default: scripts)
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT="${1:-scripts}"

# A cargo clean in command position, with the prefixes a shell script
# actually uses: an env assignment, `env`, `exec`, `command`. A cleaner
# that hid behind one of them would otherwise pass the gate.
CLEAN_RE='^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*=[^[:space:]]+[[:space:]]+)*(env[[:space:]]+)?(exec[[:space:]]+|command[[:space:]]+)?cargo[[:space:]]+clean([[:space:]]|$)'

cleaners=$(
    while IFS= read -r -d '' file; do
        if head -1 "$file" | grep -qE '^#!.*(sh|bash)' &&
            grep -qE "$CLEAN_RE" "$file"; then
            printf '%s\n' "$file"
        fi
    done < <(find "$ROOT" -type f -print0)
)

bad=$(printf '%s\n' "$cleaners" | grep -v -x -e "$ROOT/target-clean.sh" || true)
if [ -n "$bad" ]; then
    printf 'target-writes: FAIL, cargo clean outside target-clean.sh:\n%s\n' "$bad" >&2
    exit 1
fi

if ! grep -q 'target-claim.sh' "$ROOT/target-clean.sh"; then
    printf 'target-writes: FAIL, target-clean.sh bypasses the claim channel\n' >&2
    exit 1
fi

printf 'target-writes: only target-clean.sh cleans, and it holds the claim.\n'
