#!/usr/bin/env bash
# target/ claim channel (#349). One flock + one advert file:
#
#   target-claim.sh with CMD...   hold target/ for CMD's duration
#   target-claim.sh check         exit 0 when free, 2 + holder when held
#   target-claim.sh holder        print the current holder line
#
# The flock is the truth: a dead holder's lock is released by the
# kernel, so a stale advert never blocks anyone — a successful acquire
# overwrites the advert. The advert line is only the readable name
# ("PID cmd started-at") that refusals print, replacing the
# discover-by-breaking failure mode where a gate relink deleted
# target/debug/nau under a live pod sync (twice, 2026-10-04).
#
# Consumers: gate.sh claims at entry; dev-loop runs that spawn children
# from target/ wrap themselves (`target-claim.sh with nau pod sync ...`);
# deleters (target-clean.sh, disk sweeps) check before deleting.
set -eu

CLAIM_DIR="${NAU_TARGET_DIR:-target}"
CLAIM_FILE="$CLAIM_DIR/.claim"

holder_line() { cat "$CLAIM_FILE" 2>/dev/null || echo "(no advert file)"; }

refuse() {
    echo "target-claim: FAIL — $CLAIM_DIR/ is held:" >&2
    echo "  $(holder_line)" >&2
    echo "  wait for the holder to finish; only remove $CLAIM_FILE if" >&2
    echo "  the holder is provably dead (the lock, not the file, decides)." >&2
    exit 2
}

case "${1:-}" in
with)
    shift
    mkdir -p "$CLAIM_DIR"
    exec 9>>"$CLAIM_FILE"
    flock -n 9 || refuse
    printf '%s %s %s\n' "$$" "$*" "$(date -Is)" >"$CLAIM_FILE"
    trap 'flock -u 9; : > "$CLAIM_FILE"' EXIT
    "$@"
    ;;
check)
    mkdir -p "$CLAIM_DIR"
    exec 9>>"$CLAIM_FILE"
    flock -n 9 || refuse
    exit 0
    ;;
holder)
    holder_line
    ;;
*)
    echo "usage: target-claim.sh with CMD... | check | holder" >&2
    exit 64
    ;;
esac
