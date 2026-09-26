#!/usr/bin/env bash
# Generate tools-manifest.toml from built artifacts + pins.conf (issue #101).
#
# Usage: gen-manifest.sh <tools_version> <artifact-dir> <out-file> <url-prefix>
#
# Artifacts are named "<tool>-<triple>" (e.g. bwrap-x86_64-unknown-linux-musl)
# — the same names the workflow attaches to a release, so <url-prefix>/<name>
# is the release attachment URL. Every artifact's sha256 is computed from the
# bytes on disk here; pins.conf supplies versions, source URLs, licenses and
# per-tool precedence. Output is parsed by the in-tree provisioner and by
# python tomllib in CI.
set -euo pipefail

RECIPE_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source-path=SCRIPTDIR
source "$RECIPE_DIR/pins.conf"

die() {
    printf 'gen-manifest.sh: %s\n' "$*" >&2
    exit 1
}

# Field maps per tool name. Kept as flat case statements so every value is
# greppable next to its pin in pins.conf.
meta_version() {
    case $1 in
        mksquashfs | unsquashfs) printf '%s' "$SQUASHFS_TOOLS_VERSION" ;;
        bwrap) printf '%s' "$BUBBLEWRAP_VERSION" ;;
        tar) printf '%s' "$TAR_VERSION" ;;
        curl) printf '%s' "$CURL_VERSION" ;;
        *) die "unknown tool: $1" ;;
    esac
}

meta_source_url() {
    case $1 in
        mksquashfs | unsquashfs) printf '%s' "$SQUASHFS_TOOLS_SOURCE_URL" ;;
        bwrap) printf '%s' "$BUBBLEWRAP_SOURCE_URL" ;;
        tar) printf '%s' "$TAR_SOURCE_URL" ;;
        curl) printf '%s' "$CURL_SOURCE_URL" ;;
        *) die "unknown tool: $1" ;;
    esac
}

meta_license() {
    case $1 in
        mksquashfs | unsquashfs) printf '%s' 'GPL-2.0-or-later' ;;
        bwrap) printf '%s' 'LGPL-2.1-or-later' ;;
        tar) printf '%s' 'GPL-3.0-or-later' ;;
        curl) printf '%s' 'curl' ;;
        *) die "unknown tool: $1" ;;
    esac
}

meta_precedence() {
    case $1 in
        curl) printf '%s' 'path_first' ;;
        *) printf '%s' 'provisioned_first' ;;
    esac
}

# emit_tool <tool> <artifact-dir> <url-prefix> — append one [[tools]] block.
emit_tool() {
    local name=$1 dir=$2 prefix=$3 file sha
    file="$dir/$name-$MANIFEST_TRIPLE"
    [ -s "$file" ] || die "missing artifact: $file"
    sha=$(sha256sum "$file") || die "sha256 failed: $file"
    sha=${sha%% *}
    cat <<EOF
[[tools]]
name = "$name"
version = "$(meta_version "$name")"
triple = "$MANIFEST_TRIPLE"
url = "$prefix/$name-$MANIFEST_TRIPLE"
sha256 = "$sha"
source_url = "$(meta_source_url "$name")"
license = "$(meta_license "$name")"
precedence = "$(meta_precedence "$name")"
EOF
}

main() {
    [ "$#" -eq 4 ] || die "usage: gen-manifest.sh <tools_version> <artifact-dir> <out-file> <url-prefix>"
    local tools_version=$1 artifact_dir=$2 out=$3 url_prefix=$4
    case $tools_version in
        '' | *[!0-9]*) die "tools_version must be a non-negative integer, got: '$tools_version'" ;;
    esac
    [ -d "$artifact_dir" ] || die "no such artifact dir: $artifact_dir"
    [ -n "$url_prefix" ] || die "url-prefix must not be empty"

    {
        # Header verbatim per #101 / AC-10 — do not reword.
        cat <<EOF
# Root of trust is the git repo, same as the shuttle binary itself.
# sha256 pins bytes, not provenance.
tools_version = $tools_version
min_kernel = "$MANIFEST_MIN_KERNEL"
signature = ""   # reserved: ed25519 over this manifest, gated (see #101)
EOF
        local tool
        for tool in mksquashfs unsquashfs bwrap tar curl; do
            printf '\n'
            emit_tool "$tool" "$artifact_dir" "$url_prefix"
        done
    } >"$out"

    echo "gen-manifest.sh: wrote $out (tools_version=$tools_version)"
}

main "$@"
