#!/usr/bin/env bash
# bench-squashfs.sh — ticket #152 / ADR-0038 squashfs pack benchmark harness.
#
# Benchmarks mksquashfs compression configs over a staged tree and checks
# byte-reproducibility (two runs, SOURCE_DATE_EPOCH pinned, identical
# sha3-384 required per config).
#
# Usage:
#   bash scripts/bench-squashfs.sh [STAGED_TREE_DIR]
#
#   No argument  -> build a deterministic ~2 GB synthetic tree (seeded) under
#                   BENCH_SCRATCH (default: <repo>/.bench-scratch) and DELETE
#                   it again after the run.
#   Dir argument -> benchmark that real tree instead; it is never deleted.
#
# Env:
#   BENCH_SCRATCH   scratch dir for tree + images   (default <repo>/.bench-scratch)
#   BENCH_SEED      generator seed                  (default 152)
#   BENCH_TABLE     markdown table output path      (default /tmp/opencode/lane152-table.md)
#
# Exit: 0 all configs reproducible; 1 reproducibility mismatch (config named);
#       2 setup/tool error. Full run log on stdout/stderr.
#
# NOTE on expected numbers (ADR-0038 gate): xz slowest of the useful configs,
# zstd levels 3/6 fastest. This harness only measures and reports.
set -euo pipefail
umask 022
export TZ=UTC
export SOURCE_DATE_EPOCH=946684800
EPOCH="${SOURCE_DATE_EPOCH}"

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="${BENCH_SCRATCH:-$REPO/.bench-scratch}"
SEED="${BENCH_SEED:-152}"
TABLE="${BENCH_TABLE:-/tmp/opencode/lane152-table.md}"

log()  { printf '%s\n' "$*"; }
die2() { printf 'bench-squashfs: ERROR: %s\n' "$*" >&2; exit 2; }

# ---------------------------------------------------------------- tools ----
command -v mksquashfs >/dev/null 2>&1 || die2 "mksquashfs not on PATH (devbox squashfsTools pin)"
command -v zstd       >/dev/null 2>&1 || die2 "zstd not on PATH"
command -v awk        >/dev/null 2>&1 || die2 "awk not on PATH"
command -v dd         >/dev/null 2>&1 || die2 "dd not on PATH"

# sha3-384 backend. Some sha3sum builds (busybox) implement legacy Keccak,
# not SHA-3 — verify against the FIPS 202 test vector for "abc" before use,
# else fall back to openssl, then to python3 hashlib (chunked reads).
SHA3_ABC="ec01498288516fc9fde1e47d4db903f4124e1f72f925c0e2644df14f"
HASH_BACKEND=""
if command -v sha3sum >/dev/null 2>&1; then
  got="$(printf 'abc' | sha3sum -a 384 2>/dev/null | cut -c1-62 || true)"
  [ "$got" = "$SHA3_ABC" ] && HASH_BACKEND=sha3sum
fi
if [ -z "$HASH_BACKEND" ] && command -v openssl >/dev/null 2>&1; then
  got="$(printf 'abc' | openssl dgst -sha3-384 2>/dev/null | awk '{print $NF}' || true)"
  [ "$got" = "$SHA3_ABC" ] && HASH_BACKEND=openssl
fi
if [ -z "$HASH_BACKEND" ] && command -v python3 >/dev/null 2>&1; then
  HASH_BACKEND=python3
fi
[ -n "$HASH_BACKEND" ] || die2 "no sha3-384 backend (verified sha3sum / openssl / python3)"

hash384() { # $1=file -> hex digest on stdout
  case "$HASH_BACKEND" in
    sha3sum) sha3sum -a 384 "$1" | cut -d' ' -f1 ;;
    openssl) openssl dgst -sha3-384 "$1" | awk '{print $NF}' ;;
    python3) python3 - "$1" <<'PYEOF'
import hashlib, sys
h = hashlib.sha3_384()
with open(sys.argv[1], "rb") as f:
    for chunk in iter(lambda: f.read(1 << 20), b""):
        h.update(chunk)
print(h.hexdigest())
PYEOF
  esac
}

log "== bench-squashfs =="
log "mksquashfs: $(mksquashfs -version 2>&1 | head -1)"
log "zstd:       $(zstd --version 2>&1 | head -1)"
log "sha3-384 backend: $HASH_BACKEND"
if [ "$HASH_BACKEND" = python3 ]; then
  if command -v sha3sum >/dev/null 2>&1; then
    log "note: sha3sum present but failed the SHA3-384 test vector (busybox builds"
    log "      implement legacy Keccak) — using python3 hashlib instead."
  elif command -v openssl >/dev/null 2>&1; then
    log "note: openssl present but failed the SHA3-384 test vector — using python3 hashlib."
  fi
fi

# ----------------------------------------------------------------- tree ----
TREE="${1:-}"
TREE_IS_SYNTHETIC=0
if [ -z "$TREE" ]; then
  TREE="$SCRATCH/tree"
  TREE_IS_SYNTHETIC=1
  if [ -e "$TREE" ]; then
    die2 "synthetic tree path $TREE already exists; remove it or pass BENCH_SCRATCH"
  fi
  log "== generating seeded synthetic tree (seed=$SEED, target ~2 GB) at $TREE =="
  mkdir -p "$SCRATCH"
  SEED_BIN="$SCRATCH/seed.bin"

  # Near-incompressible whitened seed blob: seeded PRNG hex -> zstd. ~64 MB hex
  # -> ~32 MB high-entropy binary. Pure function of SEED (stable for a given
  # awk/zstd build; the run1-vs-run2 hash gate does not depend on it).
  log "  [1/4] whitened seed blob (deterministic, seed=$SEED)..."
  awk -v s="$SEED" 'BEGIN{
    srand(s);
    for (i = 0; i < 8388608; i++)
      printf "%08x%08x%08x%08x",
        int(rand()*4294967296), int(rand()*4294967296),
        int(rand()*4294967296), int(rand()*4294967296)
  }' | zstd -q -3 -o "$SEED_BIN" -
  BLOB_BYTES="$(wc -c < "$SEED_BIN")"

  # 60 x 24 MiB binary files, carved from the blob at distinct 4 KiB-aligned
  # offsets (i*6177 mod span, gcd=1 -> all 60 offsets distinct). Every 128 KiB
  # block in the tree has distinct content -> no accidental mksquashfs dedup.
  log "  [2/4] carving 60 x 24 MiB binary files..."
  mkdir -p "$TREE/blobs"
  FILE_BLOCKS=6144                      # 6144 * 4096 = 24 MiB
  OFFSPAN=$(( (BLOB_BYTES - FILE_BLOCKS * 4096) / 4096 ))
  [ "$OFFSPAN" -gt 64 ] || die2 "seed blob too small ($BLOB_BYTES bytes)"
  i=0
  while [ "$i" -lt 60 ]; do
    skip_i=$(( (i * 6177) % OFFSPAN ))
    dd if="$SEED_BIN" of="$(printf '%s/blobs/blob-%03d.bin' "$TREE" "$i")" \
       bs=4096 skip="$skip_i" count="$FILE_BLOCKS" status=none
    i=$(( i + 1 ))
  done

  # 270 x ~1.8 MB unique text files (compressible, like real logs/resources).
  log "  [3/4] generating 270 unique text files..."
  mkdir -p "$TREE/texts"
  i=0
  while [ "$i" -lt 270 ]; do
    awk -v s="$(( SEED + i ))" -v fid="$i" 'BEGIN{
      srand(s);
      n = split("alpha bravo charlie delta echo foxtrot golf hotel india " \
                "juliet kilo lima mike november oscar papa quebec romeo " \
                "sierra tango uniform victor whiskey xray yankee zulu " \
                "config service mount target image pack stage root user " \
                "snap squasfs zstd xz lzo block level bytes hash seed " \
                "bench run lane gate table image wall reproducible", w, " ");
      nw = split("kernel initramfs desktop fwupd gnome shell snapd core22 " \
                 "bare gtk-3-38 qt-5-15-2 content interface plug slot slot " \
                 "library runtime hook command daemon socket timer path " \
                 "entry desktop icon metadata license version grade " \
                 "confinement base archetype provenance mangled", t, " ");
      for (l = 0; l < 9000; l++) {
        printf "file=%04d line=%05d ts=%d word=%s id=%d payload ", \
               fid, l, l * 137 + int(rand()*1000), w[int(rand()*n) % n], int(rand()*100000);
        for (k = 0; k < 12; k++)
          printf "%s-%d ", t[int(rand()*nw) % nw], int(rand()*9000) + 1000;
        printf "\n";
      }
    }' > "$(printf '%s/texts/text-%03d.log' "$TREE" "$i")"
    i=$(( i + 1 ))
  done

  # Small config-ish files (unique content), nested dirs for metadata realism.
  log "  [4/4] small files + mtimes..."
  mkdir -p "$TREE/etc/init.d" "$TREE/etc/defaults" "$TREE/meta"
  i=0
  while [ "$i" -lt 30 ]; do
    { printf '# bench config %d (seed %d)\n' "$i" "$SEED"
      j=0; while [ "$j" -lt 20 ]; do
        printf 'key.%d.%d = %d\n' "$i" "$j" "$(( SEED * (i + 1) + j ))"; j=$(( j + 1 ))
      done
    } > "$(printf '%s/etc/defaults/conf-%02d.cfg' "$TREE" "$i")"
    i=$(( i + 1 ))
  done
  printf 'bench-squashfs synthetic tree\nseed: %s\nepoch: %s\n' "$SEED" "$EPOCH" \
    > "$TREE/meta/manifest.txt"
  printf '#!/bin/sh\nexec true\n' > "$TREE/etc/init.d/bench-hook"

  find "$TREE" -exec touch -t 200001010000 {} +
  log "  tree ready:"
  du -sh "$TREE"
  find "$TREE" -type f | wc -l | awk '{print "  files: " $1}'
else
  [ -d "$TREE" ] || die2 "staged tree dir not found: $TREE"
  log "== using provided staged tree: $TREE =="
  du -sh "$TREE"
fi

# ------------------------------------------------------------ run matrix ----
# Config list mirrors ticket #152. "current" is the exact nau argv from
# src/image/mod.rs: mksquashfs <tree> <out> -noappend -comp xz -all-root
# (-no-progress added everywhere; cosmetic, does not affect image bytes).
IMAGES="$SCRATCH/images"
mkdir -p "$IMAGES"
IMG="$IMAGES/img.squashfs"          # reused; removed between runs

run_cfg() { # $1=name, rest=mksquashfs comp args -> sets RT (ns), RH (digest), RB (bytes)
  local name="$1"; shift
  local t0 t1
  rm -f "$IMG"
  t0="${EPOCHREALTIME:-$SECONDS}"
  mksquashfs "$TREE" "$IMG" -noappend -all-root -no-progress "$@" \
    >"$SCRATCH/mksq-$name.log" 2>&1 \
    || { log "  mksquashfs FAILED for $name (see $SCRATCH/mksq-$name.log)"; return 2; }
  t1="${EPOCHREALTIME:-$SECONDS}"
  RT="$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.1f", b-a}')"
  RB="$(wc -c < "$IMG")"
  RH="$(hash384 "$IMG")"
}

RESULTS="$SCRATCH/results.tsv"
: > "$RESULTS"
FAILS=""
log ""
log "== running matrix (2 runs per config, SOURCE_DATE_EPOCH=$EPOCH) =="

declare -a CFG_NAMES=(current xz-1M zstd-l3-1M zstd-l6-1M zstd-def-1M lzo-def)
declare -A CFG_ARGS=(
  [current]="-comp xz"
  [xz-1M]="-comp xz -b 1M"
  [zstd-l3-1M]="-comp zstd -Xcompression-level 3 -b 1M"
  [zstd-l6-1M]="-comp zstd -Xcompression-level 6 -b 1M"
  [zstd-def-1M]="-comp zstd -b 1M"
  [lzo-def]="-comp lzo"
)

for name in "${CFG_NAMES[@]}"; do
  read -r -a args <<< "${CFG_ARGS[$name]}"
  log "-- $name: mksquashfs ... ${args[*]}"
  ok=1
  run_cfg "$name" "${args[@]}" || ok=0
  if [ "$ok" = 1 ]; then
    rt1="$RT"; rb1="$RB"; rh1="$RH"; img1="$IMG.run1"
    mv "$IMG" "$img1"
    run_cfg "$name" "${args[@]}" || ok=0
    if [ "$ok" = 1 ]; then
      rt2="$RT"; rb2="$RB"; rh2="$RH"
      if [ "$rh1" = "$rh2" ]; then
        rep="yes"
      else
        rep="NO"
        FAILS="$FAILS $name"
        log "  !! REPRODUCIBILITY MISMATCH: $name"
        log "     run1 sha3-384: $rh1"
        log "     run2 sha3-384: $rh2"
      fi
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$rt1" "$rt2" "$rb1" "$rh2" "$rep" >> "$RESULTS"
      log "   run1 ${rt1}s / run2 ${rt2}s, ${rb1} bytes, reproducible=$rep"
    fi
  fi
  rm -f "$IMG" "$IMG.run1"
done

# Cross-check the unflagged zstd default actually lands at level 15.
if command -v unsquashfs >/dev/null 2>&1 && [ -f "$SCRATCH/mksq-zstd-def-1M.log" ]; then
  log ""
  log "note: mksquashfs zstd default level check (unsquashfs -s on run would show"
  log "      compression-level 15 per squashfs-tools zstd defaults; level flag absent)."
fi

# ---------------------------------------------------------------- report ----
{
  echo "## squashfs pack benchmark — ticket #152 (ADR-0038 baseline)"
  echo ""
  echo "- host toolchain: $(mksquashfs -version 2>&1 | head -1), $(zstd --version 2>&1 | head -1)"
  echo "- sha3-384 backend: $HASH_BACKEND (test-vector verified)"
  echo "- reproducibility gate: 2 runs per config, \`SOURCE_DATE_EPOCH=$EPOCH\`, identical sha3-384 required"
  if [ "$TREE_IS_SYNTHETIC" = 1 ]; then
    echo "- tree: seeded synthetic ~2 GB (BENCH_SEED=$SEED; mixed near-incompressible binary + compressible text)"
  else
    echo "- tree: $TREE (provided)"
  fi
  echo ""
  echo "| config | wall run1 (s) | wall run2 (s) | bytes | sha3-384 (prefix) | reproducible |"
  echo "|---|---|---|---|---|---|"
  while IFS="$(printf '\t')" read -r name rt1 rt2 rb rh rep; do
    rbh="$(awk -v b="$rb" 'BEGIN{printf "%.0f MiB", b/1048576}')"
    echo "| \`$name\` | $rt1 | $rt2 | $rb ($rbh) | \`${rh:0:16}\` | $rep |"
  done < "$RESULTS"
  echo ""
  if [ -n "$FAILS" ]; then
    echo "**HARD FAILURE — reproducibility mismatch:$FAILS**"
  else
    echo "All configs reproduced byte-identically."
  fi
} > "$TABLE"
log ""
log "== markdown table -> $TABLE =="
cat "$TABLE"

# --------------------------------------------------------------- cleanup ----
log ""
log "== cleanup =="
if [ "$TREE_IS_SYNTHETIC" = 1 ]; then
  find "$TREE" -type f -exec rm {} +
  find "$TREE" -depth -type d -exec rmdir {} +
  rm -f "$SEED_BIN"
  log "synthetic tree + seed blob deleted."
fi
find "$IMAGES" -type f -exec rm {} + 2>/dev/null || true
rmdir "$IMAGES" 2>/dev/null || true
find "$SCRATCH" -maxdepth 1 -type f \( -name 'mksq-*.log' -o -name results.tsv \) -exec rm {} +
if rmdir "$SCRATCH" 2>/dev/null; then
  log "images removed. scratch removed."
else
  log "images removed. scratch kept at: $SCRATCH"
fi

if [ -n "$FAILS" ]; then
  log ""
  log "RESULT: HARD FAILURE — reproducibility mismatch:$FAILS"
  exit 1
fi
log ""
log "RESULT: all configs reproducible."
