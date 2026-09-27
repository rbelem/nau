#!/usr/bin/env bash
# Smoke test for scripts/nau-publish-cache.sh (ticket #275 lane F)
# against a local stub target directory and a hand-built stub mirror
# tree (Decision-10 shape: index.json, manifests/, blobs/). No Nau
# host, no ssh — the local-directory target mode is the same rsync +
# stamp code path.
#
# Proves, locally:
#   - fresh publish: tree lands byte-exact, stamp has exactly one
#     "<UTC-timestamp> <release-id>" line, source tree not mutated
#   - re-publish unchanged: stamp appends (history preserved)
#   - rsync --delete propagates inside blobs/ and manifests/; stale
#     root-level files are left alone (documented deviation)
#   - a new release-id lands as the last stamp line
#   - --dry-run performs zero writes
#   - fail-loud on a missing index.json / bad release-id
#   - commit-point property: a failed publish never appends the stamp
#
# NOT proven here (operator-gated, recorded in #275): the remote-ssh
# path ([user@]host targets) and a live `shuttle pull` from
# https://cache.nau.rclb.dev/ — both unblock when the Nau host exists.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PUB=$SCRIPT_DIR/nau-publish-cache.sh

command -v rsync >/dev/null || { echo "rsync required"; exit 1; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/nau-publish-cache-test.XXXXXX")
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "  ok: $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }
check() { # check <desc> <cmd...>
    local desc=$1
    shift
    if "$@"; then ok "$desc"; else bad "$desc"; fi
}

OUT=$TMP/pub.out
ERR=$TMP/pub.err
RC=0
run_pub() { # run_pub <target> <tree> [args...]
    local target=$1 tree=$2
    shift 2
    RC=0
    "$PUB" --target "$target" "$@" "$tree" >"$OUT" 2>"$ERR" || RC=$?
}

# Stub fixture in the Decision-10 export shape (lane D owns the real
# export; this stub only needs the tree shape the wrapper consumes).
make_tree() { # make_tree <dir>
    local d=$1
    rm -rf "$d"
    mkdir -p "$d/blobs" "$d/manifests"
    printf '{"kind":"nau-index","release":"stub","manifests":["manifests/aaa.json"],"created":"2026-09-27T00:00:00Z"}\n' >"$d/index.json"
    printf '{"closure":"aaa","blob":"1111","size":5}\n' >"$d/manifests/aaa.json"
    printf '{"closure":"bbb","blob":"2222","size":5}\n' >"$d/manifests/bbb.json"
    printf 'blob1' >"$d/blobs/1111111111111111111111111111111111111111111111111111111111111111"
    printf 'blob2' >"$d/blobs/2222222222221111111111111111111111111111111111111111111111111111"
}

stamp_lines() { # stamp_lines <target-root> — number of stamp lines
    wc -l <"$1/freshness.stamp"
}
last_line_id() { # last_line_id <target-root> — release-id of last line
    awk '{print $2}' "$1/freshness.stamp" | tail -n 1
}
last_line_ts() { # last_line_ts <target-root> — timestamp of last line
    awk '{print $1}' "$1/freshness.stamp" | tail -n 1
}
ts_is_utc_iso() { # UTC ISO-8601: 2026-09-27T18:00:00Z
    case $1 in
        [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z) return 0 ;;
        *) return 1 ;;
    esac
}

echo "scenario 1: fresh publish to an empty stub root"
TREE=$TMP/tree
make_tree "$TREE"
ROOT=$TMP/stub-root
mkdir -p "$ROOT"
run_pub "$ROOT" "$TREE" --release-id pool-gen120
check "exit 0" test "$RC" -eq 0
check "index.json byte-exact" cmp -s "$TREE/index.json" "$ROOT/index.json"
check "manifest byte-exact" cmp -s "$TREE/manifests/aaa.json" "$ROOT/manifests/aaa.json"
check "blob byte-exact" cmp -s "$TREE/blobs/1111111111111111111111111111111111111111111111111111111111111111" "$ROOT/blobs/1111111111111111111111111111111111111111111111111111111111111111"
check "stamp exists" test -f "$ROOT/freshness.stamp"
check "stamp world-readable (644, Caddy must read it)" test "$(stat -c %a "$ROOT/freshness.stamp")" = "644"
check "stamp has exactly 1 line" test "$(stamp_lines "$ROOT")" -eq 1
check "stamp last ts is UTC ISO-8601" ts_is_utc_iso "$(last_line_ts "$ROOT")"
check "stamp last line carries the release id" test "$(last_line_id "$ROOT")" = "pool-gen120"
check "source tree not mutated (no stamp in TREE)" test ! -e "$TREE/freshness.stamp"

echo "scenario 2: re-publish unchanged — stamp appends, history kept"
run_pub "$ROOT" "$TREE" --release-id pool-gen120
check "exit 0" test "$RC" -eq 0
check "stamp grew to 2 lines" test "$(stamp_lines "$ROOT")" -eq 2
check "both lines carry the release id" test "$(grep -c ' pool-gen120$' "$ROOT/freshness.stamp")" -eq 2

echo "scenario 3: --delete propagates in content dirs; root extras untouched"
rm "$TREE/blobs/2222222222221111111111111111111111111111111111111111111111111111"
rm "$TREE/manifests/bbb.json"
printf 'stale' >"$ROOT/blobs/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
printf 'junk' >"$ROOT/notes.txt"
run_pub "$ROOT" "$TREE" --release-id pool-gen121
check "exit 0" test "$RC" -eq 0
check "deleted blob gone from target" test ! -e "$ROOT/blobs/2222222222221111111111111111111111111111111111111111111111111111"
check "deleted manifest gone from target" test ! -e "$ROOT/manifests/bbb.json"
check "--delete removed the stale blob" test ! -e "$ROOT/blobs/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
check "root-level extra left alone (documented)" test "$(cat "$ROOT/notes.txt")" = "junk"
check "stamp appended to 3 lines" test "$(stamp_lines "$ROOT")" -eq 3
check "last line is the new release id" test "$(last_line_id "$ROOT")" = "pool-gen121"

echo "scenario 4: --dry-run — plan printed, zero writes"
BEFORE=$(cd "$ROOT" && find . -type f -exec sha256sum {} + | sort)
run_pub "$ROOT" "$TREE" --release-id pool-gen122 --dry-run
check "exit 0" test "$RC" -eq 0
check "plan shows put(dry) for all three phases" \
    test "$(grep -c 'put(dry)' "$OUT")" -eq 3
check "plan shows the stamp(dry) line" grep -q "stamp(dry) .* pool-gen122" "$OUT"
AFTER=$(cd "$ROOT" && find . -type f -exec sha256sum {} + | sort)
check "target untouched by dry-run" test "$BEFORE" = "$AFTER"
check "stamp still 3 lines" test "$(stamp_lines "$ROOT")" -eq 3

echo "scenario 5: missing index.json — fail loud, tree named"
TREE_NOIDX=$TMP/tree-noidx
make_tree "$TREE_NOIDX"
rm "$TREE_NOIDX/index.json"
run_pub "$ROOT" "$TREE_NOIDX" --release-id pool-gen123
check "nonzero exit" test "$RC" -ne 0
check "error names index.json" grep -q "no index.json under $TREE_NOIDX" "$ERR"

echo "scenario 6: bad release-id — rejected before any rsync"
for BAD_ID in 'pool gen' 'x
y' '../evil' ''; do
    run_pub "$ROOT" "$TREE" --release-id "$BAD_ID" || true
    if [ "$RC" -eq 0 ]; then
        bad "release-id '$BAD_ID' accepted"
    else
        ok "release-id rejected: $(printf '%q' "$BAD_ID")"
    fi
done

echo "scenario 7: failed publish never touches the stamp (commit point)"
chmod 555 "$ROOT"
run_pub "$ROOT" "$TREE" --release-id pool-gen124
chmod 755 "$ROOT"
check "nonzero exit on unwritable target" test "$RC" -ne 0
check "rsync error surfaced" grep -q . "$ERR"
check "stamp line count unchanged" test "$(stamp_lines "$ROOT")" -eq 3
check "stamp content unchanged" test "$(last_line_id "$ROOT")" = "pool-gen121"

echo
echo "nau-publish-cache-test: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
