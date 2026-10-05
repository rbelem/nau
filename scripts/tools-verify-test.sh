#!/usr/bin/env bash
# Test suite for scripts/tools-verify.sh (issue #353) against a fixture
# pins.conf + a fake build-tool.sh. No network, no Docker — the container
# rebuild itself is operator-side (the gates live in build-tool.sh and are
# exercised by the tools-artifacts workflow); this suite proves the verify
# table and the delegation wiring:
#
#   - source axis: sha256 vs pins.conf — OK, MISMATCH, MISSING (each of the
#     latter two fails the run; MISSING names the fetch command)
#   - artifact axis via a REAL gen-manifest.sh manifest: byte OK, byte
#     FAIL (both hashes named), version smoke FAIL, un-pinned report-only
#     rows (no fake OKs)
#   - byte-pin mode (--expect-sha256): sha equality only, version not
#     consulted; a never-consulted name is a hard error (typo = pin never
#     checked = fail-open trap)
#   - --rebuild delegation: fetch + one call per tool, exact args, then a
#     green verify; a corrupt fake build fails the verify; --rebuild
#     without --out refuses
#   - the REAL recipes/tools/pins.conf parses and reports 4 MISSING
#     sources on an empty downloads dir (no fetch, exit 1)
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
VERIFY=$SCRIPT_DIR/tools-verify.sh
GEN_MANIFEST=$SCRIPT_DIR/../recipes/tools/gen-manifest.sh

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

FIX=$TMP/fix # stands in for recipes/tools via TOOLS_RECIPE_DIR
DL=$FIX/downloads
OUT=$FIX/out
TRIPLE=x86_64-unknown-linux-musl

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }

assert_eq() { # desc want got
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want: [$2] got: [$3])"; fi
}
assert_contains() { # desc needle haystack
    if grep -qF -- "$2" <<<"$3"; then ok "$1"; else bad "$1 (missing: [$2])"; fi
}
assert_not_contains() { # desc needle haystack
    if grep -qF -- "$2" <<<"$3"; then bad "$1 (unexpected: [$2])"; else ok "$1"; fi
}
assert_rc() { # desc want-rc got-rc
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want rc $2, got $3)"; fi
}

RC_V=0
OUT_V=""
run_verify() { # args... → OUT_V + RC_V (env TOOLS_RECIPE_DIR, FAKE_FIX, FAKE_CORRUPT)
    RC_V=0
    OUT_V=$(TOOLS_RECIPE_DIR=$FIX FAKE_FIX=$FIX FAKE_CORRUPT=${FAKE_CORRUPT:-0} \
        bash "$VERIFY" "$@" 2>&1) || RC_V=$?
}

sha_of() { sha256sum "$1" | awk '{print $1}'; }

# ── fixture: pins.conf with the REAL var names, test values ─────────────────
mkdir -p "$FIX" "$DL" "$OUT"
printf 'fixture-tarball-squashfs\n' >"$DL/squashfs-tools-9.9.9.tar.gz"
printf 'fixture-tarball-bubblewrap\n' >"$DL/bubblewrap-8.8.8.tar.xz"
printf 'fixture-tarball-tar\n' >"$DL/tar-7.7.7.tar.xz"
printf 'fixture-tarball-curl\n' >"$DL/curl-6.6.6.tar.xz"

cat >"$FIX/pins.conf" <<EOF
# fixture pins.conf — same var names the real file carries (test seam)
TOOLS_VERSION=7
ALPINE_IMAGE='alpine:9.9@sha256:0000000000000000000000000000000000000000000000000000000000000000'
SQUASHFS_TOOLS_VERSION='9.9.9'
SQUASHFS_TOOLS_SOURCE_URL='http://fixtures.invalid/rel/squashfs-tools-9.9.9.tar.gz'
SQUASHFS_TOOLS_SHA256='$(sha_of "$DL/squashfs-tools-9.9.9.tar.gz")'
BUBBLEWRAP_VERSION='8.8.8'
BUBBLEWRAP_SOURCE_URL='http://fixtures.invalid/rel/bubblewrap-8.8.8.tar.xz'
BUBBLEWRAP_SHA256='$(sha_of "$DL/bubblewrap-8.8.8.tar.xz")'
TAR_VERSION='7.7.7'
TAR_SOURCE_URL='http://fixtures.invalid/rel/tar-7.7.7.tar.xz'
TAR_SHA256='$(sha_of "$DL/tar-7.7.7.tar.xz")'
CURL_VERSION='6.6.6'
CURL_SOURCE_URL='http://fixtures.invalid/rel/curl-6.6.6.tar.xz'
CURL_SHA256='$(sha_of "$DL/curl-6.6.6.tar.xz")'
MANIFEST_TRIPLE='$TRIPLE'
MANIFEST_MIN_KERNEL='3.2'
EOF

# The REAL gen-manifest.sh beside the fixture pins.conf (it sources its own
# dir) — the manifest under test is produced by the real producer.
cp "$GEN_MANIFEST" "$FIX/gen-manifest.sh"

# mk-binaries.sh: the five version stubs at their pinned versions.
cat >"$FIX/mk-binaries.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
out=$1
mk() { printf '#!/bin/sh\ncat <<V\n%s\nV\n' "$2" >"$out/$1"; chmod +x "$out/$1"; }
mk mksquashfs 'mksquashfs version 9.9.9 (2026-01-01)'
mk unsquashfs 'unsquashfs version 9.9.9 (2026-01-01)'
mk bwrap 'bwrap 8.8.8'
mk tar 'tar (GNU tar) 7.7.7'
mk curl 'curl 6.6.6 (x86_64-pc-linux-musl) libcurl/6.6.6'
EOF
chmod +x "$FIX/mk-binaries.sh"

# Fake build-tool.sh: records every invocation and materializes pin-
# consistent fixtures (the real script's container gates run in the
# tools-artifacts workflow; the contract under test here is the
# DELEGATION plus the post-rebuild verify).
cat >"$FIX/build-tool.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
FIX=${FAKE_FIX:?}
echo "$*" >>"$FIX/calls.log"
case $1 in
    fetch)
        mkdir -p "$2"
        cp "$FIX"/downloads/*.tar.* "$2"/
        ;;
    squashfs-tools | bubblewrap | tar | curl)
        mkdir -p "$2" "$3"
        if [ "${FAKE_CORRUPT:-0}" = 1 ]; then
            printf '#!/bin/sh\necho "corrupt 0.0.0"\n' >"$3/mksquashfs"
            printf '#!/bin/sh\necho "corrupt 0.0.0"\n' >"$3/unsquashfs"
            printf '#!/bin/sh\necho "corrupt 0.0.0"\n' >"$3/bwrap"
            printf '#!/bin/sh\necho "corrupt 0.0.0"\n' >"$3/tar"
            printf '#!/bin/sh\necho "corrupt 0.0.0"\n' >"$3/curl"
        else
            "$FIX/mk-binaries.sh" "$3"
        fi
        chmod +x "$3"/mksquashfs "$3"/unsquashfs "$3"/bwrap "$3"/tar "$3"/curl
        ;;
    *) exit 64 ;;
esac
EOF
chmod +x "$FIX/build-tool.sh"

# ── T1: sources OK, no --out → green, exit 0 ─────────────────────────────────
run_verify --downloads "$DL"
assert_rc "T1 source-OK exits 0" 0 "$RC_V"
assert_eq "T1 four source rows all = pins.conf" 4 "$(grep -c '= pins.conf$' <<<"$OUT_V")"
assert_contains "T1 squashfs sha surfaced" "$(sha_of "$DL/squashfs-tools-9.9.9.tar.gz") = pins.conf" "$OUT_V"
assert_contains "T1 green summary" \
    "tools-verify: OK — all checked rows verified" "$OUT_V"
assert_eq "T1 no artifact rows without --out" 0 "$(grep -c 'artifact' <<<"$OUT_V" || true)"

# ── T2: source byte MISMATCH fails closed, both hashes named ────────────────
printf 'tampered\n' >"$DL/curl-6.6.6.tar.xz"
PIN_CU=$(awk -F"'" '/^CURL_SHA256=/ {print $2}' "$FIX/pins.conf")
run_verify --downloads "$DL"
assert_rc "T2 source-MISMATCH exits 1" 1 "$RC_V"
assert_contains "T2 FAIL row names both hashes" \
    "$(sha_of "$DL/curl-6.6.6.tar.xz") ≠ pins.conf $PIN_CU" "$OUT_V"
printf 'fixture-tarball-curl\n' >"$DL/curl-6.6.6.tar.xz" # restore

# ── T3: source MISSING fails closed, names the fetch ─────────────────────────
mv "$DL/tar-7.7.7.tar.xz" "$TMP/keep-tar"
run_verify --downloads "$DL"
assert_rc "T3 source-MISSING exits 1" 1 "$RC_V"
assert_contains "T3 MISSING row names the tarball" "tar-7.7.7.tar.xz" "$OUT_V"
assert_contains "T3 MISSING hints fetch" "build-tool.sh fetch" "$OUT_V"
mv "$TMP/keep-tar" "$DL/tar-7.7.7.tar.xz"

# ── T4: artifacts vs a REAL gen-manifest.sh manifest → all five byte-OK ─────
"$FIX/mk-binaries.sh" "$OUT"
TRIPLE_OUT=$TMP/triple-out # gen-manifest wants <name>-<triple> names
mkdir -p "$TRIPLE_OUT"
for b in mksquashfs unsquashfs bwrap tar curl; do
    cp "$OUT/$b" "$TRIPLE_OUT/$b-$TRIPLE"
done
"$FIX/gen-manifest.sh" 7 "$TRIPLE_OUT" "$FIX/manifest.toml" 'http://fixtures.invalid/rel' >/dev/null
run_verify --downloads "$DL" --out "$OUT" --manifest "$FIX/manifest.toml"
assert_rc "T4 manifest-verified artifacts exit 0" 0 "$RC_V"
assert_contains "T4 mksquashfs pinned-bytes detail" \
    "sha $(sha_of "$OUT/mksquashfs") = pinned bytes — version 9.9.9 = pins.conf" "$OUT_V"
assert_eq "T4 five pinned-bytes artifact rows" 5 "$(grep -c '= pinned bytes' <<<"$OUT_V")"

# ── T5: artifact byte MISMATCH vs manifest fails, both hashes named ─────────
printf '#!/bin/sh\necho "mksquashfs version 9.9.9 (2026-01-01)"\n' >"$OUT/mksquashfs"
chmod +x "$OUT/mksquashfs" # same version line, different bytes
PINNED_MK=$(awk '/name = "mksquashfs"/ {while ($0 !~ /^sha256/) getline; gsub(/[",]/, "", $3); print $3}' \
    "$FIX/manifest.toml")
run_verify --out "$OUT" --manifest "$FIX/manifest.toml"
assert_rc "T5 byte-MISMATCH exits 1" 1 "$RC_V"
assert_contains "T5 FAIL row names actual + pinned" \
    "sha $(sha_of "$OUT/mksquashfs") ≠ pinned $PINNED_MK" "$OUT_V"

# ── T6: version smoke catches a lying binary when bytes are un-pinned ───────
printf '#!/bin/sh\necho "tar (GNU tar) 1.01"\n' >"$OUT/tar"
chmod +x "$OUT/tar"
run_verify --out "$OUT"
assert_rc "T6 version-smoke FAIL exits 1" 1 "$RC_V"
assert_contains "T6 FAIL row reports smoke" \
    "version smoke: expected *7.7.7*, got: tar (GNU tar) 1.01" "$OUT_V"
assert_contains "T6 un-pinned sha is reported-only" \
    "sha $(sha_of "$OUT/tar") (no byte pin; reported only)" "$OUT_V"

# ── T7: byte-pin mode — sha only, version never consulted ────────────────────
"$FIX/mk-binaries.sh" "$OUT" # reset all five
printf '#!/bin/sh\necho "bwrap 0.0.0"\n' >"$OUT/bwrap" # wrong version on purpose
chmod +x "$OUT/bwrap"
SHA_BWRAP=$(sha_of "$OUT/bwrap")
run_verify --out "$OUT" --expect-sha256 "bwrap=$SHA_BWRAP"
assert_rc "T7 byte-pin OK ignores version" 0 "$RC_V"
assert_contains "T7 pinned-bytes detail" "sha $SHA_BWRAP = pinned bytes" "$OUT_V"
assert_not_contains "T7 no version smoke in byte-pin mode" "version smoke" "$OUT_V"

# T7b: wrong sha under byte-pin mode → FAIL
run_verify --out "$OUT" --expect-sha256 "bwrap=$(printf 'a%.0s' {1..64})"
assert_rc "T7b byte-pin MISMATCH exits 1" 1 "$RC_V"

# T7c: a never-consulted --expect-sha256 name is a hard error (typo trap)
run_verify --out "$OUT" --expect-sha256 "mkgsquashfs=$SHA_BWRAP"
assert_rc "T7c unknown byte-pin name refused" 2 "$RC_V"
assert_contains "T7c error names the typo" \
    "--expect-sha256 mkgsquashfs: no such artifact was checked" "$OUT_V"

# T7d: malformed --expect-sha256 (not 64 hex) refused at the boundary
run_verify --out "$OUT" --expect-sha256 "bwrap=deadbeef"
assert_rc "T7d malformed byte-pin refused" 2 "$RC_V"

# ── T8: --rebuild delegates to build-tool.sh, then verifies green ────────────
rm -f "$FIX/calls.log"
RB_OUT=$TMP/rb-out
RB_DL=$TMP/rb-downloads
run_verify --rebuild --downloads "$RB_DL" --out "$RB_OUT"
assert_rc "T8 rebuild+verify exits 0" 0 "$RC_V"
assert_eq "T8 fake build-tool called 5x (fetch + 4 tools)" \
    5 "$(wc -l <"$FIX/calls.log")"
assert_contains "T8 fetch arg order" "fetch $RB_DL" "$(cat "$FIX/calls.log")"
for tool in squashfs-tools bubblewrap tar curl; do
    assert_contains "T8 $tool arg order" "$tool $RB_DL $RB_OUT" "$(cat "$FIX/calls.log")"
done
assert_contains "T8 post-rebuild verify green" \
    "tools-verify: OK — all checked rows verified" "$OUT_V"

# T8b: a corrupt (gate-evading) build fails the post-rebuild verify; a clean
# rebuild converges back to green.
FAKE_CORRUPT=1 run_verify --rebuild --downloads "$RB_DL" --out "$RB_OUT"
assert_rc "T8b corrupt rebuild fails verify" 1 "$RC_V"
run_verify --rebuild --downloads "$RB_DL" --out "$RB_OUT"
assert_rc "T8b2 clean rebuild greens again" 0 "$RC_V"

# T8c: --rebuild without --out refuses (usage, rc 2)
run_verify --rebuild --downloads "$RB_DL"
assert_rc "T8c rebuild needs --out" 2 "$RC_V"

# ── T9: the REAL pins.conf parses; empty downloads → 4 MISSING, exit 1 ──────
mkdir -p "$TMP/empty-dl"
OUT_V=$(bash "$VERIFY" --downloads "$TMP/empty-dl" 2>&1) || RC_V=$?
assert_rc "T9 real pins.conf, empty downloads exits 1" 1 "${RC_V:-0}"
assert_contains "T9 header carries real tools_version" \
    "pins.conf (tools_version=1)" "$OUT_V"
assert_eq "T9 four MISSING source rows" 4 "$(grep -c '^MISSING' <<<"$OUT_V")"
for f in squashfs-tools-4.7.5.tar.gz bubblewrap-0.11.2.tar.xz tar-1.35.tar.xz curl-8.20.0.tar.xz; do
    assert_contains "T9 real pin row: $f" "$f" "$OUT_V"
done

# ── summary ──────────────────────────────────────────────────────────────────
printf '\n%s\n' "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
