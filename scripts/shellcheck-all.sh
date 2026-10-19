#!/usr/bin/env bash
# Lint every shell script under scripts/.
#
# Discovery is by shebang, not by file name. A glob over `scripts/*.sh`
# misses the scripts that matter most: `nau-cache-publish`,
# `nau-worker-ttl-sweep`, and the git hook in scripts/hooks/ carry no
# extension, and the ones in subdirectories sit below the glob. Those are
# the scripts that run unattended, so a name-based glob is the wrong
# boundary.
#
# A file is a shell script when its first line names sh or bash. The
# Python helpers and the systemd unit files fail that test, so they are
# not passed to the linter.
#
# CI runs this through `devbox run -- shellcheck`; the same script runs
# locally, so the gate is identical in both places.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

mapfile -t targets < <(
    find scripts -type f ! -name '*.pyc' -print0 \
        | xargs -0 grep -lI -E '^#!.*(sh|bash)' 2>/dev/null \
        | sort
)

if ((${#targets[@]} == 0)); then
    echo "shellcheck: no shell scripts found under scripts/" >&2
    exit 0
fi

printf 'shellcheck: %d script(s)\n' "${#targets[@]}"
printf '  %s\n' "${targets[@]}"
shellcheck "${targets[@]}"
