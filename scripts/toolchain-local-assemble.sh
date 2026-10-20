#!/usr/bin/env bash
# toolchain-local-assemble.sh — assemble the GCC toolchain in a local pod
# from already-built payloads plus one on-demand gcc build.
#
#   ./scripts/toolchain-local-assemble.sh <pod> [snap-dir]
#
# Seeds the meta's closure payloads into the pod's downloads dir — the
# lane `ensure_pod_dep_payload` (src/pod.rs) reuses: the file must be
# named {name}_{version}_{host-arch}.snap and carry a .sha3-384 sidecar
# (missing digest refuses; a missing content key baselines loudly on
# first use, which is the intended migration behavior). Members with no
# payload at the recipe's version build normally — in practice gcc,
# whose recipe is 15.2.0 while the repo payloads are 14.2.0, so the
# deb fetch-merge runs through the normal build path.
#
# Why: glibc is a source build and the long pole; the repo's built
# payloads already carry it. Seeding is the only reuse path the pod
# install accepts (content-digest verified, content-key baselined).
# This is the placement-A harness of .planning/toolchain-build-plan.md.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
POD="${1:?usage: toolchain-local-assemble.sh <pod> [snap-dir]}"
SNAPS="${2:-$REPO}"
: "${NAU_BIN:=$REPO/target/debug/nau}"
POD_ROOT="${NAU_POD_ROOT:-${XDG_DATA_HOME:-$HOME/.local/share}/nau/pods}"
DOWNLOADS="$POD_ROOT/$POD/downloads"

# The meta's closure: its `requires` (pkgs/t/toolchain-gcc-gnu-x86_64.lua)
# plus the transitive libgcc, m4, make.
MEMBERS=(linux-headers glibc libgcc gcc zlib isl mpc m4 make mpfr gmp)

mkdir -p "$DOWNLOADS"
seeded=0
missing=0
for m in "${MEMBERS[@]}"; do
    v="$(grep -m1 'version = ' "$REPO/pkgs/${m:0:1}/$m.lua" | sed 's/.*"\(.*\)".*/\1/')"
    src="$SNAPS/${m}_${v}_amd64.snap"
    if [ ! -f "$src" ]; then
        echo "  will build: $m $v (no payload at $src)"
        missing=$((missing + 1))
        continue
    fi
    dst="$DOWNLOADS/${m}_${v}_amd64.snap"
    cp -f "$src" "$dst"
    python3 -c 'import hashlib,sys;print(hashlib.file_digest(open(sys.argv[1],"rb"),"sha3_384").hexdigest())' "$dst" >"$dst.sha3-384"
    echo "  seeded: $m $v ($(stat -c %s "$dst") B)"
    # Provenance: a payload without a .content-key sidecar (a pre-#344
    # build) cannot be checked against the current recipes — the pod-side
    # reuse baselines it silently. Warn, so seeding a stale payload (the
    # repo-root glibc predated the ld-script fix, and the failure
    # surfaced at link time) is a visible choice rather than a surprise.
    if [ ! -f "$src.content-key" ]; then
        echo "    WARN: $m payload carries no .content-key sidecar (pre-#344 build) — provenance vs the current recipe is unverifiable; a live pod's downloads carry one"
    fi
    seeded=$((seeded + 1))
done
echo "seeded $seeded payload(s); $missing to build"

cd "$REPO"
# Idempotent re-run: `add` refuses an already-declared package; a declared
# toolchain reconciles through `sync` at its pins instead.
if [ -f "$POD_ROOT/$POD/pod.lua" ] && grep -q '"toolchain"' "$POD_ROOT/$POD/pod.lua"; then
    echo "  'toolchain' already declared in pod $POD — syncing"
    exec env -u LD_LIBRARY_PATH -u LD_PRELOAD "$NAU_BIN" pod --name "$POD" sync
fi
exec env -u LD_LIBRARY_PATH -u LD_PRELOAD "$NAU_BIN" pod --name "$POD" add toolchain
