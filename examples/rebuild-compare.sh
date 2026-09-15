#!/usr/bin/env bash
# examples/rebuild-compare.sh — issue #48: PROVE reproducibility.
#
# Builds the same full-system declaration TWICE into separate output paths,
# from the same pin state (the committed package-index.json) and the same
# warm snap cache, then diffs every artifact the design claims is
# deterministic — byte-for-byte:
#
#   * the whole disk image (sha256 — sparse-aware: hashing reads through)
#   * the GPT table (sfdisk -J minus the volatile node path: disk GUID +
#     every PARTUUID — #48 derives the verity slots from the roothash and
#     pins the rest)
#   * the UKI on the ESP (extracted with mcopy, hashed)
#   * loader.conf on the ESP
#   * the ESP / root slot A / root slot B / verity-hash A+B / state / swap
#     partition extents (hashed — slot B is the spliced rollback twin)
#   * image-manifest.json read back out of each root filesystem (debugfs) —
#     carries the roothash, cmdline, and ESP PARTUUID, so equality here
#     proves the boot-identity chain end to end
#   * the snap pin set in both manifests (revision + sha3-384), plus the
#     build-log line proving the build served the pre-resolved index pins
#     instead of re-resolving (the #69 channel-keyed machinery)
#
# Disk budget: one image lives on disk at a time (~10G). After each build
# the script hashes + extracts the comparison inputs and DELETES the image
# before the next build, so the proof fits a ~25G scratch volume. Hashes
# stand in for the kept bytes — SHA-256 equality is the byte-for-byte claim.
#
# Anything not identical is a finding: the script prints a per-artifact
# comparison table and exits nonzero on ANY mismatch, listing the offenders.
#
# Requirements (see `shuttle doctor`): the devbox toolchain (parted, sfdisk,
# dosfstools >= 4.2, e2fsprogs, mtools, ukify, veritysetup), a warm snap
# cache (~/.cache/shuttle/snaps), and an update signing key
# (~/.config/shuttle/secret-key — `shuttle key keygen`).
#
# Usage:
#   devbox run -- examples/rebuild-compare.sh
#
# Environment overrides:
#   SHUTTLE_BIN       binary to build with (default: target/debug/shuttle)
#   SHUTTLE_LUA       declaration to build (default:
#                     examples/full-system/pc-rootfs-26/shuttle.lua)
#   SHUTTLE_ARCH      target arch (default: amd64)
#   SHUTTLE_WORK      scratch/output root (default:
#                     ~/.cache/shuttle-rebuild-compare)
#   SOURCE_DATE_EPOCH pinned build epoch (default: 1704067200)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SHUTTLE_BIN="${SHUTTLE_BIN:-$REPO_ROOT/target/debug/shuttle}"
SHUTTLE_LUA="${SHUTTLE_LUA:-$REPO_ROOT/examples/full-system/pc-rootfs-26/shuttle.lua}"
SHUTTLE_ARCH="${SHUTTLE_ARCH:-amd64}"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1704067200}"
WORK="${SHUTTLE_WORK:-$HOME/.cache/shuttle-rebuild-compare}"

# The build's scratch tempdirs hold ~14G at peak (disk.img + root.img +
# partition files) — /tmp is often too small, so anchor TMPDIR to WORK.
mkdir -p "$WORK/tmp"
export TMPDIR="$WORK/tmp"

IMG_NAME="ubuntu-core-pc-26_26.04_${SHUTTLE_ARCH}.img"
OUT1="$WORK/build1"
OUT2="$WORK/build2"

fail=0
OFFENDERS=()
TABLE=()

# ── helpers ──────────────────────────────────────────────────────────────

row() { # artifact, verdict, detail
    TABLE+=("$(printf '  %-30s %-3s %s' "$1" "$2" "$3")")
}

mark_fail() { # artifact
    fail=1
    OFFENDERS+=("$1")
}

sha() { sha256sum "$1" | cut -d' ' -f1; }

# sha256 of a byte RANGE of a file — streams; never materializes the extent.
# dd's byte-mode flags avoid the tail|head SIGPIPE trap under pipefail.
range_sha() { # file, skip_bytes, count_bytes
    dd if="$1" bs=4M skip="$2" count="$3" iflag=skip_bytes,count_bytes status=none \
        | sha256sum | cut -d' ' -f1
}

# byte-exact extraction of a file range — dd-free offset math, any offset.
extract_bytes() { # file, skip_bytes, count_bytes, out
    dd if="$1" of="$4" bs=4M skip="$2" count="$3" iflag=skip_bytes,count_bytes status=none
}

# partition field from a table dump, in BYTES: part_field TABLE_JSON IDX FIELD
part_field() {
    python3 - "$1" "$2" "$3" <<'PYEOF'
import json, sys
t = json.load(open(sys.argv[1]))
sector = int(t["partitiontable"].get("sector-size", 512))
p = t["partitiontable"]["partitions"][int(sys.argv[2])]
print(int(p[sys.argv[3]]) * sector)
PYEOF
}

# ── preconditions ────────────────────────────────────────────────────────

[[ -x "$SHUTTLE_BIN" ]] || { echo "error: $SHUTTLE_BIN not built (cargo build first)" >&2; exit 2; }
[[ -f "$SHUTTLE_LUA" ]] || { echo "error: declaration $SHUTTLE_LUA not found" >&2; exit 2; }
for tool in sfdisk debugfs mcopy mdir objcopy python3; do
    command -v "$tool" >/dev/null || { echo "error: $tool not on PATH (run inside devbox)" >&2; exit 2; }
done

echo "rebuild-compare (issue #48)"
echo "  declaration : $SHUTTLE_LUA"
echo "  binary      : $SHUTTLE_BIN"
echo "  arch        : $SHUTTLE_ARCH"
echo "  epoch       : $SOURCE_DATE_EPOCH"
echo "  work        : $WORK"
echo

# The pin state is the committed index — a dirty index would let the two
# builds consume different pin sets and the proof would mean nothing.
if [[ -n "$(git -C "$REPO_ROOT" status --porcelain -- package-index.json)" ]]; then
    echo "error: package-index.json is dirty — the two builds must share the committed pins" >&2
    exit 2
fi

# The builds run from per-build output dirs (their own CWD → own lockfile),
# so the committed index is pinned by path — the same package-index.json
# serves both builds no matter where the script runs from.
export SHUTTLE_INDEX_PATH="${SHUTTLE_INDEX_PATH:-$REPO_ROOT/package-index.json}"

# The #85 boot-assessment staging needs host bless-boot tooling. On FHS
# distros /usr/lib/systemd has it; in a devbox environment it lives in the
# systemd store path next to ukify — derive it when unset.
if [[ -z "${SHUTTLE_BLESS_BOOT_DIR:-}" ]] && command -v ukify >/dev/null; then
    ukify_real="$(readlink -f "$(command -v ukify)")"
    candidate="${ukify_real%/bin/ukify}/lib/systemd"
    if [[ -f "$candidate/systemd-bless-boot" ]]; then
        export SHUTTLE_BLESS_BOOT_DIR="$candidate"
        echo "  bless-boot tooling: $SHUTTLE_BLESS_BOOT_DIR (devbox systemd)"
    fi
fi

rm -f "$WORK"/record1.* "$WORK"/record2.* "$WORK"/build*.log
rm -rf "$OUT1" "$OUT2"

# ── per-build record: hash + extract, then free the image ────────────────

record_build() { # n, out_dir
    local n="$1" out="$2"
    local img="$out/$IMG_NAME"
    [[ -f "$img" ]] || { echo "error: build $n produced no $img" >&2; exit 3; }

    echo "  hashing + extracting $img"
    sha "$img" > "$WORK/record$n.image.sha256"

    # GPT table; the only volatile field is the image path (the per-build
    # output dir, as `device` + each partition's `node`) — normalized away;
    # the disk GUID and every PARTUUID must compare equal.
    sfdisk -J "$img" > "$WORK/record$n.table.raw.json"
    python3 - "$WORK/record$n.table.raw.json" "$WORK/record$n.table.json" <<'PYEOF'
import json, sys
t = json.load(open(sys.argv[1]))
t["partitiontable"].pop("device", None)
for p in t["partitiontable"]["partitions"]:
    p.pop("node", None)
json.dump(t, open(sys.argv[2], "w"), indent=1, sort_keys=True)
PYEOF
    rm -f "$WORK/record$n.table.raw.json"

    # The staged rootfs: the root slot's ext4, materialized once for debugfs.
    # (The root fs carries the CONTENT manifest — step 9a; the boot facts
    # ride the UKI cmdline, extracted below.)
    local root_start root_size esp_start uki_name
    root_start=$(part_field "$WORK/record$n.table.json" 1 start)
    root_size=$(part_field "$WORK/record$n.table.json" 1 size)
    extract_bytes "$img" "$root_start" "$root_size" "$WORK/record$n.root.ext4"
    debugfs -R "cat /image-manifest.json" "$WORK/record$n.root.ext4" 2>/dev/null \
        > "$WORK/record$n.manifest.json"

    # UKI (filename from the ESP listing) + loader config off the ESP, via
    # mtools' @@offset partition read.
    esp_start=$(part_field "$WORK/record$n.table.json" 0 start)
    uki_name=$(mdir -i "$img@@$esp_start" -/ ::/EFI/Linux 2>/dev/null \
        | grep -oE '[A-Za-z0-9._-]+\.efi' | head -1)
    mcopy -i "$img@@$esp_start" "::/EFI/Linux/$uki_name" "$WORK/record$n.uki.efi"
    mcopy -i "$img@@$esp_start" "::/loader/loader.conf" "$WORK/record$n.loader.conf"

    # The boot-identity chain: the UKI's embedded cmdline (root PARTUUID +
    # dm-verity roothash + hash PARTUUID) — extracted from the .cmdline PE
    # section so the compare proves the roothash and derived identities.
    objcopy -O binary --only-section=.cmdline "$WORK/record$n.uki.efi" \
        "$WORK/record$n.cmdline.txt"

    # Partition extents, hashed now (the image is freed below). Labels come
    # from the table's own partition names — the layout order is the
    # declaration's (hash partitions appended, slot B cloned behind slot A).
    : > "$WORK/record$n.extents.txt"
    local idx s sz h label
    for idx in $(python3 -c "import json,sys; t=json.load(open(sys.argv[1])); print(' '.join(str(i) for i, p in enumerate(t['partitiontable']['partitions'])))" "$WORK/record$n.table.json"); do
        label=$(python3 -c "import json,sys; t=json.load(open(sys.argv[1])); print(t['partitiontable']['partitions'][int(sys.argv[2])].get('name','?'))" "$WORK/record$n.table.json" "$idx")
        s=$(part_field "$WORK/record$n.table.json" "$idx" start)
        sz=$(part_field "$WORK/record$n.table.json" "$idx" size)
        h=$(range_sha "$img" "$s" "$sz")
        echo "$label $h" >> "$WORK/record$n.extents.txt"
    done

    # Free the image before the next build — the disk budget is one image.
    rm -rf "$out" "$WORK/record$n.root.ext4"
    echo "  build $n recorded (image freed)"
}

# ── build ×2 (same pins, same cache, different output paths) ─────────────

for n in 1 2; do
    out="$WORK/build$n"
    echo "==> build $n/2 → $out"
    mkdir -p "$out"
    if ! ( cd "$out" && "$SHUTTLE_BIN" image \
            --file "$SHUTTLE_LUA" --arch "$SHUTTLE_ARCH" \
            --output "$out" --lockfile "$WORK/build$n.lock" --json ) \
            >"$WORK/build$n.log" 2>"$WORK/build$n.stderr.log"; then
        echo "error: build $n failed — see $WORK/build$n.stderr.log" >&2
        tail -20 "$WORK/build$n.stderr.log" >&2
        exit 3
    fi
    record_build "$n" "$out"
done

# ── compare the two records ──────────────────────────────────────────────

echo "==> comparing records"
TABLE=("  artifact                        =?  detail")

# 0. Pin-honoring evidence: both builds served the index pins (#69).
pinned=$(grep -c "using pre-resolved pin from index" "$WORK/build1.stderr.log" || true)
restored=$(grep -c "resolving from the store" "$WORK/build1.stderr.log" || true)
if [[ "$restored" -eq 0 && "$pinned" -gt 0 ]]; then
    row "pins honored (no re-resolve)" "✓" "$pinned snaps from index pins, 0 store re-resolves"
else
    row "pins honored (no re-resolve)" "✗" "index-served=$pinned store-resolved=$restored"
    mark_fail "pins honored"
fi

# 1. The whole image, hash-for-hash (byte-for-byte, mediated by SHA-256).
h1=$(cut -d' ' -f1 "$WORK/record1.image.sha256")
h2=$(cut -d' ' -f1 "$WORK/record2.image.sha256")
if [[ "$h1" == "$h2" ]]; then
    row "disk image (whole)" "✓" "sha256 ${h1:0:16}…"
else
    row "disk image (whole)" "✗" "sha256 ${h1:0:16}… ≠ ${h2:0:16}…"
    mark_fail "disk image"
fi

# 2. GPT identity: disk GUID + every PARTUUID (normalized sfdisk -J).
if cmp -s "$WORK/record1.table.json" "$WORK/record2.table.json"; then
    row "GPT table (GUIDs)" "✓" "byte-identical"
else
    row "GPT table (GUIDs)" "✗" "disk GUID or PARTUUID differs"
    mark_fail "GPT table"
fi

# 3. Partition extents — the per-artifact localization layer.
if cmp -s "$WORK/record1.extents.txt" "$WORK/record2.extents.txt"; then
    while read -r label h; do
        row "extent: $label" "✓" "sha256 ${h:0:16}…"
    done < "$WORK/record1.extents.txt"
else
    row "partition extents" "✗" "differences below:"
    mark_fail "partition extents"
    paste -d'|' "$WORK/record1.extents.txt" "$WORK/record2.extents.txt" \
        | while IFS='|' read -r a b; do
            [[ "$a" == "$b" ]] || echo "      $a  ≠  $b"
        done
fi

# 4. The content manifest out of both root filesystems (the rootfs identity:
#    snap set + declared boot shape; boot facts ride the cmdline, checked
#    next).
if cmp -s "$WORK/record1.manifest.json" "$WORK/record2.manifest.json"; then
    row "image-manifest.json (rootfs)" "✓" "byte-identical"
else
    row "image-manifest.json (rootfs)" "✗" "rootfs manifest differs"
    mark_fail "image-manifest.json"
    diff "$WORK/record1.manifest.json" "$WORK/record2.manifest.json" | head -10
fi

# 5. The snap pin set inside both manifests (revision + sha3-384).
pin_ok=1
python3 - "$WORK/record1.manifest.json" "$WORK/record2.manifest.json" <<'PYEOF' || pin_ok=0
import json, sys
s = lambda p: sorted((e["name"], e["revision"], e["sha3-384"]) for e in json.load(open(p))["snaps"])
sys.exit(0 if s(sys.argv[1]) == s(sys.argv[2]) and s(sys.argv[1]) else 1)
PYEOF
if [[ "$pin_ok" -eq 1 ]]; then
    row "snap pin set (rev+sha3-384)" "✓" "$pinned pins identical in both manifests"
else
    row "snap pin set (rev+sha3-384)" "✗" "manifests disagree on the pin set"
    mark_fail "snap pin set"
fi

# 4b. The boot-identity chain: UKI cmdline (root PARTUUID + roothash + hash
# PARTUUID).
if cmp -s "$WORK/record1.cmdline.txt" "$WORK/record2.cmdline.txt"; then
    row "UKI cmdline (roothash+GUIDs)" "✓" "$(tr -d '\0' <"$WORK/record1.cmdline.txt" | cut -c1-60)…"
else
    row "UKI cmdline (roothash+GUIDs)" "✗" "boot identity differs"
    mark_fail "UKI cmdline"
    diff <(tr -d '\0' <"$WORK/record1.cmdline.txt" | tr ' ' '\n') \
         <(tr -d '\0' <"$WORK/record2.cmdline.txt" | tr ' ' '\n') | head -6
fi

# 5. The UKI + loader config off each ESP.
if cmp -s "$WORK/record1.uki.efi" "$WORK/record2.uki.efi"; then
    row "UKI (EFI/Linux)" "✓" "byte-identical ($(wc -c <"$WORK/record1.uki.efi") bytes)"
else
    row "UKI (EFI/Linux)" "✗" "UKI bytes differ"
    mark_fail "UKI"
fi
if cmp -s "$WORK/record1.loader.conf" "$WORK/record2.loader.conf"; then
    row "loader.conf (ESP)" "✓" "byte-identical"
else
    row "loader.conf (ESP)" "✗" "differs"
    mark_fail "loader.conf"
fi

# ── verdict ──────────────────────────────────────────────────────────────

echo
echo "comparison table"
printf '%s\n' "${TABLE[@]}"
echo

if [[ $fail -eq 0 ]]; then
    echo "RESULT: REPRODUCIBLE — every artifact byte-identical across rebuilds."
    rc=0
else
    echo "RESULT: NONDETERMINISM FOUND — mismatched artifacts:"
    for o in "${OFFENDERS[@]}"; do echo "  - $o"; done
    echo "Bisect hint: table = GPT identity, root extent = staged tree + mkfs,"
    echo "hash extents = verity format, UKI/ESP = boot payload, manifest = boot facts."
    rc=1
fi

echo
echo "records kept under $WORK (record1.*, record2.*, build*.log)"
echo "clean them with: rm -f $WORK/record*.* $WORK/build*.log"

exit "$rc"
