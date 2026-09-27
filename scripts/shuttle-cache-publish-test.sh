#!/usr/bin/env bash
# E2E test for scripts/shuttle-cache-publish (ticket #270) against the
# auth-exempt stub scripts/shuttle-cache-publish-stub.py.
#
# Proves, locally:
#   - walk order: every blob op before any manifest op; per blob
#     HEAD-before-PUT; per manifest GET-before-PUT
#   - skip-if-exists blobs (HEAD 200); 403 treated as a miss (=> PUT)
#   - manifest bytes-compare: identical => skip, different => LOUD
#     conflict naming the key, remote bytes untouched
#   - --dry-run performs zero writes
#   - fail-loud (nonzero exit, object named) on a failed PUT
#   - blob PUTs carry Content-Type application/octet-stream
#   - the secret never appears in stdout/stderr or the request log
#   - SigV4 signature correctness, cross-checked against an independent
#     python reimplementation of the signing chain (byte-exact)
#
# NOT proven here (blocked, recorded in #270): SigV4 acceptance by the
# real rustfs endpoint (policy dialect, UNSIGNED-PAYLOAD, path-style
# vhost) and a real-bucket publish round trip — both unblock when the
# zet checklist steps 0-1 (anonymous-read gate + provision script) land.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PUB=$SCRIPT_DIR/shuttle-cache-publish
STUB=$SCRIPT_DIR/shuttle-cache-publish-stub.py

command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
command -v openssl >/dev/null || { echo "openssl required (SigV4 chain)"; exit 1; }
command -v curl >/dev/null || { echo "curl required"; exit 1; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/shuttle-cache-publish-test.XXXXXX")
STUB_PID=
cleanup() {
    [ -n "$STUB_PID" ] && kill "$STUB_PID" 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT

STORE=$TMP/store
LOG=$TMP/req.jsonl
PORTFILE=$TMP/port

python3 "$STUB" --port 0 --data "$STORE" --log "$LOG" --portfile "$PORTFILE" &
STUB_PID=$!
for _ in $(seq 1 50); do
    [ -s "$PORTFILE" ] && break
    sleep 0.1
done
[ -s "$PORTFILE" ] || { echo "stub did not start"; exit 1; }
PORT=$(cat "$PORTFILE")

export SHUTTLE_CACHE_S3_ACCESS_KEY=stub-access-key
export SHUTTLE_CACHE_S3_SECRET_KEY=stub-secret-do-not-print-9f86d081884c7d65
export SHUTTLE_CACHE_S3_ENDPOINT="http://127.0.0.1:$PORT"
export SHUTTLE_CACHE_S3_BUCKET=shuttle-test-bucket
export SHUTTLE_CACHE_S3_REGION=us-east-1
BUCKET=$SHUTTLE_CACHE_S3_BUCKET
SECRET=$SHUTTLE_CACHE_S3_SECRET_KEY

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "  ok: $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }
check() { # check <desc> <cmd...>
    local desc=$1
    shift
    if "$@"; then ok "$desc"; else bad "$desc"; fi
}
check_no() { # check_no <desc> <cmd...> — passes when the command fails
    local desc=$1
    shift
    if "$@"; then bad "$desc (matched, expected none)"; else ok "$desc"; fi
}

OUT=$TMP/pub.out
ERR=$TMP/pub.err
RC=0
run_pub() {
    RC=0
    "$PUB" "$@" >"$OUT" 2>"$ERR" || RC=$?
    if grep -Fq "$SECRET" "$OUT" "$ERR" "$LOG"; then
        bad "secret leaked into output or request log"
    fi
}

LOG_N=0
logdelta() { tail -n "+$((LOG_N + 1))" "$LOG"; LOG_N=$(wc -l <"$LOG"); }

make_tree() {
    local d=$1
    mkdir -p "$d/blobs" "$d/cache"
    printf 'alpha-blob-payload\n%.0s' {1..64} >"$d/blobs/1111111111111111111111111111111111111111111111111111111111111111"
    printf 'bravo-blob-payload\n%.0s' {1..64} >"$d/blobs/2222222222222222222222222222222222222222222222222222222222222222"
    cat >"$d/cache/cafe111111111111111111111111111111111111111111111111111111111111.json" <<'EOF'
{"kind":"cache-manifest","closure":"cafe1","blob":"1111","size":1281,"signer":"test"}
EOF
    cat >"$d/cache/dead22222222222222222222222222222222222222222222222222222222222.json" <<'EOF'
{"kind":"cache-manifest","closure":"dead2","blob":"2222","size":1281,"signer":"test"}
EOF
}

blob_mtime() { # remote blob mtime -> used to prove skip = no rewrite
    stat -c %Y "$STORE/$BUCKET/blobs/$1"
}

echo "scenario 1: fresh publish — order, PUT, content-type, bytes"
TREE=$TMP/tree1
make_tree "$TREE"
run_pub "$TREE"
check "exit 0" test "$RC" -eq 0
check "summary counts" grep -qF "0 conflicts, 0 failed" "$OUT"
check "4 uploaded, 0 skipped" grep -qF "4 uploaded, 0 skipped" "$OUT"
logdelta >"$TMP/s1.jsonl"
python3 - "$TMP/s1.jsonl" <<'EOF'
import json, sys
ops = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
blob = [(i, o) for i, o in enumerate(ops) if "/blobs/" in o["path"]]
man = [(i, o) for i, o in enumerate(ops) if "/cache/" in o["path"]]
assert blob and man, "expected both blob and manifest ops"
assert blob[-1][0] < man[0][0], "blob ops must all precede manifest ops"
by_path = {}
for o in ops:
    by_path.setdefault(o["path"], []).append(o)
for path, reqs in by_path.items():
    if "/blobs/" in path:
        assert [r["method"] for r in reqs] == ["HEAD", "PUT"], (path, reqs)
        assert (reqs[0]["status"], reqs[1]["status"]) == (404, 200), path
        assert reqs[1]["content_type"] == "application/octet-stream", path
    else:
        assert [r["method"] for r in reqs] == ["GET", "PUT"], (path, reqs)
        assert (reqs[0]["status"], reqs[1]["status"]) == (404, 200), path
        assert reqs[1]["content_type"] == "application/json", path
assert sum(1 for o in ops if o["method"] == "PUT") == 4
EOF
check "order: blobs-then-manifests, HEAD/GET 404, 4 PUTs, content-types" test $? -eq 0
check "blob bytes stored verbatim" cmp -s "$TREE/blobs/1111111111111111111111111111111111111111111111111111111111111111" "$STORE/$BUCKET/blobs/1111111111111111111111111111111111111111111111111111111111111111"
check "manifest bytes stored verbatim" cmp -s "$TREE/cache/dead22222222222222222222222222222222222222222222222222222222222.json" "$STORE/$BUCKET/cache/dead22222222222222222222222222222222222222222222222222222222222.json"

echo "scenario 2: SigV4 signature cross-check (independent python reimplementation)"
python3 - "$TMP/s1.jsonl" "$SHUTTLE_CACHE_S3_ENDPOINT" <<'EOF'
import hashlib, hmac, json, os, sys
from urllib.parse import urlsplit

ops = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
put = next(o for o in ops if o["method"] == "PUT" and o["authorization"])
u = urlsplit(sys.argv[2])
host = u.netloc
secret = os.environ["SHUTTLE_CACHE_S3_SECRET_KEY"]
access = os.environ["SHUTTLE_CACHE_S3_ACCESS_KEY"]
region = os.environ["SHUTTLE_CACHE_S3_REGION"]
amz = put["x_amz_date"]
day = amz.split("T")[0]
signed = "host;x-amz-content-sha256;x-amz-date"
ph = "UNSIGNED-PAYLOAD"
cr = (
    f"PUT\n{put['path']}\n\nhost:{host}\n"
    f"x-amz-content-sha256:{ph}\nx-amz-date:{amz}\n\n{signed}\n{ph}"
)
scope = f"{day}/{region}/s3/aws4_request"
sts = f"AWS4-HMAC-SHA256\n{amz}\n{scope}\n{cr}"

def hm(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()

k = hm(("AWS4" + secret).encode(), day)
k = hm(k, region)
k = hm(k, "s3")
k = hm(k, "aws4_request")
sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
assert put["authorization"] == (
    f"AWS4-HMAC-SHA256 Credential={access}/{scope}, "
    f"SignedHeaders={signed}, Signature={sig}"
), f"signature mismatch:\n{put['authorization']}\nexpected ...{sig}"
EOF
check "sh SigV4 chain matches python reimplementation byte-exact" test $? -eq 0

echo "scenario 3: re-publish unchanged — everything skips, no rewrite"
M1_MTIME_BEFORE=$(blob_mtime 1111111111111111111111111111111111111111111111111111111111111111)
run_pub "$TREE"
check "exit 0" test "$RC" -eq 0
check "0 uploaded, 4 skipped" grep -qF "0 uploaded, 4 skipped, 0 conflicts, 0 failed" "$OUT"
logdelta >"$TMP/s3.jsonl"
check_no "no PUT issued on re-publish" grep -q '"method": "PUT"' "$TMP/s3.jsonl"
M1_MTIME_AFTER=$(blob_mtime 1111111111111111111111111111111111111111111111111111111111111111)
check "existing blob not rewritten on skip" test "$M1_MTIME_BEFORE" = "$M1_MTIME_AFTER"

echo "scenario 4: mutated manifest — LOUD conflict, remote untouched"
CONFLICT_KEY=cafe111111111111111111111111111111111111111111111111111111111111.json
REMOTE_BEFORE=$(cat "$STORE/$BUCKET/cache/$CONFLICT_KEY")
printf '\n{"tampered":true}\n' >>"$TREE/cache/$CONFLICT_KEY"
run_pub "$TREE"
check "nonzero exit on conflict" test "$RC" -ne 0
check "conflict names the key" grep -qF "CONFLICT  cache/$CONFLICT_KEY" "$ERR"
check "remote manifest bytes untouched" test "$REMOTE_BEFORE" = "$(cat "$STORE/$BUCKET/cache/$CONFLICT_KEY")"

echo "scenario 5: --dry-run — plan printed, zero writes"
TREE5=$TMP/tree5
make_tree "$TREE5"
rm -rf "${STORE:?}/$BUCKET"
mkdir -p "$STORE/$BUCKET/blobs" "$STORE/$BUCKET/cache"
cp "$TREE5/blobs/1111111111111111111111111111111111111111111111111111111111111111" \
    "$STORE/$BUCKET/blobs/"
LIST_BEFORE=$(find "$STORE" -type f | sort)
run_pub --dry-run "$TREE5"
check "dry-run exit 0 (no conflicts in this tree)" test "$RC" -eq 0
logdelta >"$TMP/s5.jsonl"
check_no "dry-run issued no PUT" grep -q '"method": "PUT"' "$TMP/s5.jsonl"
check "plan shows skip for the pre-seeded blob" grep -qF "skip      blobs/1111" "$OUT"
check "plan shows put(dry) for the missing blob" grep -qF "put(dry)  blobs/2222" "$OUT"
check "plan shows put(dry) for both manifests" test "$(grep -c 'put(dry)  cache/' "$OUT")" -eq 2
check "store untouched by dry-run" test "$LIST_BEFORE" = "$(find "$STORE" -type f | sort)"

echo "scenario 6: 403 is a miss — HEAD/GET 403 leads to PUT"
TREE403=$TMP/tree403
mkdir -p "$TREE403/blobs" "$TREE403/cache"
printf 'forbidden-blob\n' >"$TREE403/blobs/aaa.403"
printf '{"kind":"cache-manifest","closure":"f403"}\n' >"$TREE403/cache/bbb.403.json"
run_pub "$TREE403"
check "exit 0 (403 treated as miss)" test "$RC" -eq 0
logdelta >"$TMP/s6.jsonl"
python3 - "$TMP/s6.jsonl" <<'EOF'
import json, sys
ops = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
blob_head = next(o for o in ops if o["method"] == "HEAD")
assert blob_head["status"] == 403, blob_head
man_get = next(o for o in ops if o["method"] == "GET")
assert man_get["status"] == 403, man_get
puts = [o for o in ops if o["method"] == "PUT"]
assert len(puts) == 2 and all(o["status"] == 200 for o in puts), puts
EOF
check "HEAD 403 + GET 403 both led to PUT 200" test $? -eq 0

echo "scenario 7: failed PUT — fail loud, object named, nonzero exit"
TREEFP=$TMP/treefp
mkdir -p "$TREEFP/blobs" "$TREEFP/cache"
printf 'doomed\n' >"$TREEFP/blobs/evil.failput"
run_pub "$TREEFP"
check "nonzero exit on failed PUT" test "$RC" -ne 0
check "failure names the object and status" grep -qF "FAIL      blobs/evil.failput (PUT status 500)" "$ERR"
check "summary reports 1 failed" grep -qF "0 uploaded, 0 skipped, 0 conflicts, 1 failed" "$OUT"

echo "scenario 8: endpoint with a path is rejected (no silent wrong-prefix publish)"
SAVED_EP=$SHUTTLE_CACHE_S3_ENDPOINT
export SHUTTLE_CACHE_S3_ENDPOINT="$SAVED_EP/prefix"
run_pub "$TREE"
check "nonzero exit on endpoint with path" test "$RC" -ne 0
check "error names the endpoint constraint" grep -qF "no path or query" "$ERR"
export SHUTTLE_CACHE_S3_ENDPOINT="$SAVED_EP"

echo
echo "shuttle-cache-publish-test: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
