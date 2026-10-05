#!/usr/bin/env bash
# Verify the pinned floor tools against recipes/tools/pins.conf (issue #353).
#
# The gcc14 consts re-pin saga: two toolchains ran mksquashfs/unsquashfs
# bytes that were NOT the pinned bytes, and nobody could tell without hand
# sha256sum + eyeballing. This script replaces that: one per-artifact verdict
# table, fail-closed, with rebuild going through the existing build-tool.sh
# gates (source sha256 vs pins.conf, static-link gate, exec smoke).
#
# Two pin axes, both anchored on pins.conf (the source of record):
#
#   sources   the pinned upstream tarballs, sha256 vs pins.conf. Runs unless
#             --expect-sha256 byte-pin mode is active. MISSING is a failure:
#             bytes that are not there are not verified bytes.
#
#   artifacts built binaries in --out DIR (build-tool.sh's output layout,
#             plain names; release-layout `<name>-<triple>` also accepted).
#             Byte pin comes from --manifest (a tools-manifest.toml generated
#             by gen-manifest.sh from pins.conf + blessed bytes) or from
#             explicit --expect-sha256 NAME=HEX. Without a byte pin the table
#             only REPORTS the sha256 and runs the same version smoke
#             build-tool.sh gates builds with — no fake OKs.
#
# Usage:
#   tools-verify.sh                                         # sources only
#   tools-verify.sh --downloads DIR                         # sources at DIR
#   tools-verify.sh --out DIR --manifest tools-manifest.toml
#   tools-verify.sh --out DIR --expect-sha256 mksquashfs=HEX ...   # byte-pin
#                                                                 # mode
#   tools-verify.sh --rebuild [--out DIR]                   # fetch + gated
#                                                           # rebuild, then
#                                                           # verify
#
# Replication examples (the saga's use case):
#   # floor lane, after a release bless — check a second machine's bytes:
#   tools-verify.sh --out /usr/local/bin --manifest tools-manifest.toml
#   # worker lane (pins live in nau-pool/src/provision/mod.rs, not
#   # pins.conf — byte-pin mode checks exactly the names you hand it):
#   tools-verify.sh --out /usr/local/bin \
#     --expect-sha256 mksquashfs="$MKSQUASHFS_ARTIFACT_SHA256" \
#     --expect-sha256 unsquashfs="$UNSQUASHFS_ARTIFACT_SHA256"
#
# Exit: 0 only when every checked row is OK. FAIL (byte/version mismatch) and
# MISSING both fail the run — fail-closed is the whole point.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# TOOLS_RECIPE_DIR is a test seam: tests point it at a fixture pins.conf.
RECIPE_DIR=${TOOLS_RECIPE_DIR:-"$SCRIPT_DIR/../recipes/tools"}
# shellcheck source-path=SCRIPTDIR
source "$RECIPE_DIR/pins.conf"

DOWNLOADS="${TMPDIR:-/tmp}/nau-tools-verify/downloads"
OUT=""
MANIFEST=""
REBUILD=0
EXPECT_MODE=0
declare -A EXPECT_SHA=()

die() {
    printf 'tools-verify.sh: %s\n' "$*" >&2
    exit 2
}

usage() {
    die "usage: tools-verify.sh [--downloads DIR] [--out DIR] [--manifest FILE] \
[--expect-sha256 NAME=HEX]... [--rebuild]"
}

# ── pins.conf accessors ──────────────────────────────────────────────────────
# The per-tool var PREFIX map mirrors build-tool.sh's tool_vars: both read the
# SAME pins.conf vars, so a pin bump edits pins.conf alone — never a second
# copy of the values.

tool_prefix() {
    case $1 in
        squashfs-tools) printf '%s' SQUASHFS_TOOLS ;;
        bubblewrap) printf '%s' BUBBLEWRAP ;;
        tar) printf '%s' TAR ;;
        curl) printf '%s' CURL ;;
        *) return 1 ;;
    esac
}

# pin_vars <tool> — set P_VERSION/P_URL/P_SHA from pins.conf for one tool.
pin_vars() {
    local p v
    p=$(tool_prefix "$1") || die "unknown tool: $1"
    v="${p}_VERSION" P_VERSION=${!v}
    v="${p}_SOURCE_URL" P_URL=${!v}
    v="${p}_SHA256" P_SHA=${!v}
}

# tool_binaries <tool> — the artifacts the pinned source builds.
tool_binaries() {
    case $1 in
        squashfs-tools) printf '%s\n' mksquashfs unsquashfs ;;
        bubblewrap) printf '%s\n' bwrap ;;
        tar | curl) printf '%s\n' "$1" ;;
    esac
}

# ── tools-manifest.toml accessors ────────────────────────────────────────────
# gen-manifest.sh is the only producer: flat [[tools]] blocks, name first,
# sha256 four lines later. This parser reads that shape and nothing else.

manifest_sha() { # <file> <name> → hex, empty when absent
    awk -v want="$2" '
        /^\[\[tools\]\]/ { blk = 1; name = ""; sha = ""; next }
        blk && /^name = /      { gsub(/[",]/, "", $3); name = $3 }
        blk && /^sha256 = /    { gsub(/[",]/, "", $3); sha = $3 }
        blk && name == want && sha != "" { print sha; exit }
    ' "$1"
}

# ── verdict table ────────────────────────────────────────────────────────────
ROWS_FAIL=0
EXPECT_SEEN="" # every EXPECT_SHA name actually consulted this run

row() { # <verdict> <kind> <artifact> <detail>
    printf '%-8s %-9s %-28s %s\n' "$1" "$2" "$3" "$4"
    case $1 in
        OK) ;;
        *) ROWS_FAIL=$((ROWS_FAIL + 1)) ;;
    esac
}

sha_of() { # <file> → hex
    sha256sum "$1" | awk '{print $1}'
}

verify_source() { # <tool>
    local file actual
    pin_vars "$1"
    file="$DOWNLOADS/$(basename "$P_URL")"
    if [ ! -s "$file" ]; then
        row MISSING source "$(basename "$P_URL")" \
            "expected sha $P_SHA at $file (fetch: build-tool.sh fetch $DOWNLOADS)"
        return
    fi
    actual=$(sha_of "$file")
    if [ "$actual" = "$P_SHA" ]; then
        row OK source "$(basename "$P_URL")" "$actual = pins.conf"
    else
        row FAIL source "$(basename "$P_URL")" \
            "sha $actual ≠ pins.conf $P_SHA — rebuild: tools-verify.sh --rebuild"
    fi
}

version_flag() { # <binary name> — build-tool.sh's smoke flags: the
    # squashfs pair are getopt-old (-version), the rest speak --version.
    case $1 in
        mksquashfs | unsquashfs) printf '%s' -version ;;
        *) printf '%s' --version ;;
    esac
}

verify_artifact() { # <binary name> <pinned version>
    local bin=$1 want=$2 file actual expected="" verdict detail vout
    if [ -s "$OUT/$bin" ]; then
        file="$OUT/$bin"
    elif [ -s "$OUT/$bin-$MANIFEST_TRIPLE" ]; then
        file="$OUT/$bin-$MANIFEST_TRIPLE" # release attachment layout
    else
        row MISSING artifact "$bin" "not found in $OUT"
        return
    fi
    actual=$(sha_of "$file")

    if [ -n "${EXPECT_SHA[$bin]:-}" ]; then
        expected=${EXPECT_SHA[$bin]}
        EXPECT_SEEN+="${EXPECT_SEEN:+ }$bin"
    elif [ -n "$MANIFEST" ]; then
        expected=$(manifest_sha "$MANIFEST" "$bin")
    fi

    detail="sha $actual"
    if [ -n "$expected" ]; then
        if [ "$actual" = "$expected" ]; then
            verdict=OK
            detail+=" = pinned bytes"
        else
            verdict=FAIL
            detail+=" ≠ pinned $expected"
        fi
    else
        verdict=OK # reported, not proven — say so in the detail
        detail+=" (no byte pin; reported only)"
    fi

    # Version smoke: build-tool.sh's own exec gate, skipped in byte-pin mode
    # (an explicit --expect-sha256 names the bytes; their self-reported
    # version is not the checker's business).
    if [ -z "${EXPECT_SHA[$bin]:-}" ]; then
        if [ ! -x "$file" ]; then
            row FAIL artifact "$bin" "$detail — not executable"
            return
        fi
        vout=$("$file" "$(version_flag "$bin")" 2>&1 || true)
        case $vout in
            *"$want"*) detail+=" — version $want = pins.conf" ;;
            *) row FAIL artifact "$bin" \
                "$detail — version smoke: expected *$want*, got: $(printf '%s' "$vout" | head -1)"
                return ;;
        esac
    fi
    row "$verdict" artifact "$bin" "$detail"
}

# ── main ─────────────────────────────────────────────────────────────────────

while [ "$#" -gt 0 ]; do
    case $1 in
        --downloads)
            [ "$#" -ge 2 ] || usage
            DOWNLOADS=$2
            shift 2
            ;;
        --out)
            [ "$#" -ge 2 ] || usage
            OUT=$2
            shift 2
            ;;
        --manifest)
            [ "$#" -ge 2 ] || usage
            MANIFEST=$2
            shift 2
            ;;
        --expect-sha256)
            [ "$#" -ge 2 ] || usage
            case $2 in
                ?*=*)
                    name=${2%%=*}
                    hex=${2#*=}
                    [[ $name != "" && $hex =~ ^[0-9a-fA-F]{64}$ ]] ||
                        die "--expect-sha256 wants NAME=64-hex-chars, got: $2"
                    ;;
                *) die "--expect-sha256 wants NAME=HEX, got: $2" ;;
            esac
            EXPECT_MODE=1
            EXPECT_SHA[$name]=$hex
            shift 2
            ;;
        --rebuild)
            REBUILD=1
            shift
            ;;
        --help | -h)
            sed -n '2,45p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) usage ;;
    esac
done

if [ -n "$MANIFEST" ] && [ ! -s "$MANIFEST" ]; then
    die "no such manifest: $MANIFEST"
fi

if [ "$REBUILD" = 1 ]; then
    [ -n "$OUT" ] || die "--rebuild needs --out DIR (build-tool.sh's output dir)"
    # Delegation, not reimplementation: the gates live in build-tool.sh
    # (source sha256 vs pins.conf, static file+ldd, strip, exec smoke) and
    # fail closed there.
    mkdir -p "$DOWNLOADS" "$OUT"
    "$RECIPE_DIR/build-tool.sh" fetch "$DOWNLOADS"
    for tool in squashfs-tools bubblewrap tar curl; do
        "$RECIPE_DIR/build-tool.sh" "$tool" "$DOWNLOADS" "$OUT"
    done
fi

echo "tools-verify: pins.conf (tools_version=$TOOLS_VERSION) downloads=$DOWNLOADS out=${OUT:--}"

if [ "$EXPECT_MODE" = 0 ]; then
    for tool in squashfs-tools bubblewrap tar curl; do
        verify_source "$tool"
    done
fi

if [ -n "$OUT" ]; then
    for tool in squashfs-tools bubblewrap tar curl; do
        pin_vars "$tool"
        while IFS= read -r bin; do
            verify_artifact "$bin" "$P_VERSION"
        done < <(tool_binaries "$tool")
    done
fi

# A --expect-sha256 name that no artifact row consulted is a silent skip
# waiting to happen (typo'd name = pin never checked) — fail on it.
if [ "${#EXPECT_SHA[@]}" -gt 0 ]; then
    for name in "${!EXPECT_SHA[@]}"; do
        case " $EXPECT_SEEN " in
            *" $name "*) ;;
            *) die "--expect-sha256 $name: no such artifact was checked \
(known: mksquashfs unsquashfs bwrap tar curl)" ;;
        esac
    done
fi

if [ "$ROWS_FAIL" -gt 0 ]; then
    echo "tools-verify: FAIL ($ROWS_FAIL row(s) not OK)"
    exit 1
fi
echo "tools-verify: OK — all checked rows verified"
