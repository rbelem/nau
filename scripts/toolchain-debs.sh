#!/usr/bin/env bash
# toolchain-debs.sh — derive the gcc deb set from a pinned Debian snapshot.
#
#   ./scripts/toolchain-debs.sh [snapshot-timestamp] [suite]
#
# Prints one `key|arch|url|sha256` row per deb. The gcc recipe's `sources`
# table is generated from this output, so a version bump is a timestamp
# change plus a regeneration, not 66 hand-transcribed hashes.
#
# Why the Packages index and not the .deb bytes: the index at a snapshot
# timestamp publishes the sha256 the archive serves, and snapshot URLs are
# immutable. Hashing 66 downloaded debs proves the same thing at ~2 GB of
# bandwidth, and still trusts the download path it is meant to check.
#
# Key scheme, matching the recipe's table: the Debian binary package name,
# plus `_<arch>` when that name ships on every port. Names that already
# encode the triplet (gcc-16-x86-64-linux-gnu) stay bare.
set -euo pipefail

STAMP="${1:-20261001T000000Z}"
SUITE="${2:-sid}"
BASE="https://snapshot.debian.org/archive/debian/$STAMP"
CACHE="${TMPDIR:-/tmp}/nau-toolchain-debs"

# Components, as Debian binary package names. {dt} is the Debian triplet
# spelling, {a} the Debian architecture.
COMPONENTS=(
    "gcc-16-{dt}" "g++-16-{dt}" "cpp-16-{dt}" "binutils-{dt}"
    "gcc-16" "gcc-16-base" "libstdc++-16-dev" "libstdc++6" "libgcc-16-dev"
    "binutils" "binutils-common" "libbinutils" "libsframe3"
    "libctf0" "libctf-nobfd0" "libjansson4" "libgmp10" "libmpfr6"
    "libmpc3" "libisl23" "zlib1g" "libzstd1"
)

arch_triplet() {
    case "$1" in
        amd64) echo x86-64-linux-gnu ;;
        arm64) echo aarch64-linux-gnu ;;
        armhf) echo arm-linux-gnueabihf ;;
        *) echo "toolchain-debs: unknown arch '$1'" >&2; return 1 ;;
    esac
}

mkdir -p "$CACHE"
for arch in amd64 arm64 armhf; do
    idx="$CACHE/Packages-$SUITE-$arch-$STAMP.gz"
    [[ -s "$idx" ]] || curl -fsSL "$BASE/dists/$SUITE/main/binary-$arch/Packages.gz" -o "$idx"
done

for arch in amd64 arm64 armhf; do
    dt="$(arch_triplet "$arch")"
    idx="$CACHE/Packages-$SUITE-$arch-$STAMP.gz"

    # Wanted deb name -> recipe key, one per line, for the awk pass.
    want="$(mktemp)"
    for c in "${COMPONENTS[@]}"; do
        name="${c//\{dt\}/$dt}"
        key="$name"
        [[ "$name" == *-linux-gnu* ]] || key="${name}_$arch"
        printf '%s\t%s\n' "$name" "$key" >>"$want"
    done

    zcat "$idx" | awk -v base="$BASE" -v want="$want" -v arch="$arch" '
        BEGIN {
            while ((getline line < want) > 0) {
                split(line, cols, "\t")
                key[cols[1]] = cols[2]
            }
            close(want)
            RS = ""; FS = "\n"
        }
        {
            p = ""; fn = ""; s = ""
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^Package: /)  p = substr($i, 10)
                if ($i ~ /^Filename: /) fn = substr($i, 11)
                if ($i ~ /^SHA256: /)   s = substr($i, 9)
            }
            if (p == "" || fn == "" || s == "") next
            if (!(p in key)) next
            printf "%s|%s|%s/%s|%s\n", key[p], arch, base, fn, s
        }
    '
    rm -f "$want"
done
