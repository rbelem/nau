#!/usr/bin/env bash
# Test suite for scripts/target-claim.sh and scripts/target-writes.sh
# (issue #14). No cargo build, no network: the claim channel is a flock
# plus one advert file, so every case is a shell process and a scratch
# directory.
#
# The bug this suite pins: the claim file lived INSIDE the tree it
# protects (target/.claim), and cargo clean removes target/ outright.
# The release then truncated a file that no longer existed and the
# script exited 1 for a clean that had succeeded. Worse, the removed
# file took the flock's inode with it, so the next holder locked a
# fresh inode and the channel stopped excluding anyone.
#
# The cases:
#   - path: the claim file sits beside the protected tree, not inside it
#   - the release survives the protected tree being removed mid-claim
#   - the claim still excludes a second holder after the tree is gone
#   - check is 0 when free, 2 with the holder line when held
#   - holder prints the advert
#   - the cleaner exits 0 after the clean removes the tree (the repro)
#   - the gate takes its claim path from target-claim.sh, so the gate
#     and the cleaner exclude each other
#   - target-writes.sh fires on a cleaner that bypasses the claim
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
CLAIM=$SCRIPT_DIR/target-claim.sh
CLEAN=$SCRIPT_DIR/target-clean.sh
GATE=$SCRIPT_DIR/gate.sh
WRITES=$SCRIPT_DIR/target-writes.sh

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }

assert_rc() { # desc want-rc got-rc
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want rc $2, got $3)"; fi
}
assert_eq() { # desc want got
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want: [$2] got: [$3])"; fi
}
assert_contains() { # desc needle haystack
    if grep -qF -- "$2" <<<"$3"; then ok "$1"; else bad "$1 (missing: [$2])"; fi
}
assert_not_contains() { # desc needle haystack
    if grep -qF -- "$2" <<<"$3"; then bad "$1 (unexpected: [$2])"; else ok "$1"; fi
}
assert_outside() { # desc tree path
    case "$3" in
        "$2"/*) bad "$1 ($3 is inside $2)" ;;
        *) ok "$1" ;;
    esac
}
assert_file_contains() { # desc file needle
    if grep -qF -- "$3" "$2"; then ok "$1"; else bad "$1 (missing: [$3] in $2)"; fi
}

# Hold the claim on a tree until the advert lands, then release it.
# The holder's own output is closed off the pipe: a command substitution
# reads until every writer closes it, so an inherited stdout would hold
# the substitution open until the holder exits.
hold() { # tree -> pid on stdout
    NAU_TARGET_DIR="$1" bash "$CLAIM" with sleep 10 >/dev/null 2>&1 &
    local pid=$!
    for _ in $(seq 1 50); do
        [ -s "$1.claim" ] && break
        sleep 0.1
    done
    printf '%s\n' "$pid"
}

release() { # pid
    pkill -P "$1" 2>/dev/null || true
    kill "$1" 2>/dev/null || true
    wait "$1" 2>/dev/null || true
}

# ── the claim file sits beside the protected tree ──
tree="$TMP/tree-path"
mkdir -p "$tree"
path=$(NAU_TARGET_DIR="$tree" bash "$CLAIM" path 2>/dev/null) || path=""
assert_eq "path prints the claim file beside the tree" "$tree.claim" "$path"
assert_outside "the claim file is not inside the protected tree" "$tree" "$path"

# ── the release survives the protected tree being removed mid-claim ──
tree="$TMP/tree-removed"
mkdir -p "$tree"
rc=0
out=$(NAU_TARGET_DIR="$tree" bash "$CLAIM" with rm -rf "$tree" 2>&1) || rc=$?
assert_rc "a claim whose command removes the tree exits 0" 0 "$rc"
assert_not_contains "the release prints no missing-file error" "No such file or directory" "$out"

# ── the claim still excludes a second holder after the tree is gone ──
tree="$TMP/tree-under-holder"
mkdir -p "$tree"
holder=$(hold "$tree")
rc=0
NAU_TARGET_DIR="$tree" bash "$CLAIM" check >/dev/null 2>&1 || rc=$?
assert_rc "a second holder is refused while the first holds" 2 "$rc"
rm -rf "$tree"
rc=0
NAU_TARGET_DIR="$tree" bash "$CLAIM" check >/dev/null 2>&1 || rc=$?
assert_rc "the claim still holds after the tree is removed" 2 "$rc"
release "$holder"

# ── check is 0 when the claim is free ──
tree="$TMP/tree-free"
mkdir -p "$tree"
rc=0
NAU_TARGET_DIR="$tree" bash "$CLAIM" check >/dev/null 2>&1 || rc=$?
assert_rc "check is 0 when the claim is free" 0 "$rc"

# ── check is 2 with the holder line when the claim is held ──
tree="$TMP/tree-held"
mkdir -p "$tree"
holder=$(hold "$tree")
rc=0
out=$(NAU_TARGET_DIR="$tree" bash "$CLAIM" check 2>&1) || rc=$?
assert_rc "check is 2 when the claim is held" 2 "$rc"
assert_contains "the refusal names the holder" "sleep 10" "$out"

# ── holder prints the advert ──
out=$(NAU_TARGET_DIR="$tree" bash "$CLAIM" holder 2>&1) || out=""
assert_contains "holder prints the advert" "sleep 10" "$out"
release "$holder"

# ── the repro: the cleaner exits 0 after the clean removes the tree ──
tree="$TMP/tree-clean"
mkdir -p "$tree"
: >"$tree/marker"
rc=0
out=$(cd "$SCRIPT_DIR/.." && CARGO_TARGET_DIR="$tree" NAU_TARGET_DIR="$tree" bash "$CLEAN" 2>&1) || rc=$?
assert_rc "the cleaner exits 0 after the clean removes the tree" 0 "$rc"
assert_not_contains "the cleaner prints no claim error" "No such file or directory" "$out"

# ── the gate and the cleaner share one claim file ──
assert_file_contains "the gate takes the claim path from target-claim.sh" "$GATE" "target-claim.sh path"

# ── target-writes.sh fires on a cleaner that bypasses the claim ──
fixture="$TMP/scripts"
mkdir -p "$fixture"
cp "$CLEAN" "$fixture/target-clean.sh"
printf '#!/usr/bin/env bash\ncargo clean\n' >"$fixture/sneaky-clean.sh"
rc=0
out=$(bash "$WRITES" "$fixture" 2>&1) || rc=$?
assert_rc "the guardrail fails on a cleaner outside target-clean.sh" 1 "$rc"
assert_contains "the guardrail names the offending script" "sneaky-clean.sh" "$out"
rm "$fixture/sneaky-clean.sh"
rc=0
bash "$WRITES" "$fixture" >/dev/null 2>&1 || rc=$?
assert_rc "the guardrail passes when only target-clean.sh cleans" 0 "$rc"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
