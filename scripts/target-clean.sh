#!/usr/bin/env bash
# cargo clean behind the #349 claim channel: refuses while a consumer
# holds target/ (a gate, a dev-loop sync spawning children from
# target/debug), so a disk-reclaim sweep cannot delete artifacts under
# a live run. Takes the claim for the clean's own duration, so a gate
# starting mid-clean refuses with a readable holder instead of racing
# the sweep. --force is the operator's explicit override.
set -eu
CLAIM="$(dirname "$0")/target-claim.sh"
if [[ "${1:-}" == "--force" ]]; then
    shift
    echo "target-clean: --force — skipping the claim check (operator override)"
    exec cargo clean "$@"
fi
exec bash "$CLAIM" with cargo clean "$@"
