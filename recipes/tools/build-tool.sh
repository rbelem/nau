#!/usr/bin/env bash
# Build shuttle's provisioned floor tools as stripped musl-static x86_64
# binaries (issue #101, disposition (c)).
#
# Recipe: pinned-digest Alpine 3.20 container — GitHub runners ship Docker
# (nix pkgsStatic would add a ~1.5 GiB nix bootstrap per job, cf. ci.yml),
# every needed lib ships a -static package in the v3.20 APKINDEX, and the
# artifact bytes are pinned by sha256 in pins.conf regardless.
#
# Usage:
#   build-tool.sh fetch <downloads-dir>               # download + verify ALL pinned tarballs
#   build-tool.sh <tool> <downloads-dir> <out-dir>    # tool: squashfs-tools|bubblewrap|tar|curl
#
# Gates, fail closed: source sha256 vs pins.conf; -static via file+ldd inside
# the container; strip; exec smoke on the runner asserting the pinned version.
set -euo pipefail

RECIPE_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source-path=SCRIPTDIR
source "$RECIPE_DIR/pins.conf"

die() {
    printf 'build-tool.sh: %s\n' "$*" >&2
    exit 1
}

usage() {
    die "usage: build-tool.sh <fetch|squashfs-tools|bubblewrap|tar|curl> <downloads-dir> [out-dir]"
}

# _fetch <dir> <url> <want-sha256> — download once, then always verify.
_fetch() {
    local dir=$1 url=$2 want=$3 file
    file="$dir/$(basename "$url")"
    if [ -s "$file" ]; then
        echo "fetch: present $file"
    else
        echo "fetch: $url"
        curl -fsSL --retry 3 --retry-all-errors -o "$file" "$url"
    fi
    echo "$want  $file" | sha256sum -c - >/dev/null || die "sha256 mismatch: $file"
}

fetch_all() {
    local dir=$1
    mkdir -p "$dir"
    _fetch "$dir" "$SQUASHFS_TOOLS_SOURCE_URL" "$SQUASHFS_TOOLS_SHA256"
    _fetch "$dir" "$BUBBLEWRAP_SOURCE_URL" "$BUBBLEWRAP_SHA256"
    _fetch "$dir" "$TAR_SOURCE_URL" "$TAR_SHA256"
    _fetch "$dir" "$CURL_SOURCE_URL" "$CURL_SHA256"
}

# tool_vars <tool> — set V_VERSION/V_URL/V_SHA from pins.conf for one tool.
tool_vars() {
    case $1 in
        squashfs-tools)
            V_VERSION=$SQUASHFS_TOOLS_VERSION
            V_URL=$SQUASHFS_TOOLS_SOURCE_URL
            V_SHA=$SQUASHFS_TOOLS_SHA256
            ;;
        bubblewrap)
            V_VERSION=$BUBBLEWRAP_VERSION
            V_URL=$BUBBLEWRAP_SOURCE_URL
            V_SHA=$BUBBLEWRAP_SHA256
            ;;
        tar)
            V_VERSION=$TAR_VERSION
            V_URL=$TAR_SOURCE_URL
            V_SHA=$TAR_SHA256
            ;;
        curl)
            V_VERSION=$CURL_VERSION
            V_URL=$CURL_SOURCE_URL
            V_SHA=$CURL_SHA256
            ;;
        *) return 1 ;;
    esac
}

# run_recipe <tool> <downloads-dir> <out-dir> — build inside the pinned
# Alpine image. The heredoc is single-quoted: nothing interpolates on the
# host; the container recipe is the single source of build truth.
run_recipe() {
    local tool=$1 src=$2 out=$3
    src=$(cd "$src" && pwd)
    out=$(cd "$out" && pwd)
    docker run --rm -i \
        -v "$src":/src:ro \
        -v "$out":/out \
        "$ALPINE_IMAGE" sh -s -- "$tool" "$V_VERSION" <<'CONTAINER'
set -eu
tool=$1
ver=$2
BUILD=/build
rm -rf "$BUILD"
mkdir -p "$BUILD"

# Static gate: `file` must say statically linked AND ldd must refuse the
# binary. Either check failing aborts the build — a dynamic binary must
# never reach /out.
gate_static() {
    file "$1" | grep -q 'statically linked' || {
        echo "FAIL(file): $1 is not statically linked" >&2
        exit 1
    }
    if ldd "$1" >/dev/null 2>&1; then
        echo "FAIL(ldd): $1 is dynamically linked" >&2
        exit 1
    fi
}

case $tool in
    squashfs-tools)
        apk add --no-cache build-base linux-headers \
            zlib-dev zlib-static xz-dev xz-static zstd-dev zstd-static
        tar -xzf "/src/squashfs-tools-$ver.tar.gz" -C "$BUILD"
        make -C "$BUILD/squashfs-tools-$ver/squashfs-tools" -j"$(nproc)" \
            LDFLAGS=-static XZ_SUPPORT=1 ZSTD_SUPPORT=1 mksquashfs unsquashfs
        cd "$BUILD/squashfs-tools-$ver/squashfs-tools"
        strip --strip-unneeded mksquashfs unsquashfs
        cp mksquashfs unsquashfs /out/
        gate_static /out/mksquashfs
        gate_static /out/unsquashfs
        ;;
    bubblewrap)
        apk add --no-cache build-base linux-headers meson tar xz
        tar -xJf "/src/bubblewrap-$ver.tar.xz" -C "$BUILD"
        # NOTE (#101 AC-2): upstream ships no static builds — this musl build
        # is the community-precedent path. Static bytes are proven HERE; the
        # release gate is the functional sandbox probe (real `bwrap --ro-bind
        # / / /bin/true` exec), owned by the doctor lane. All optional deps
        # disabled → links against libc only, which is what makes -static work.
        LDFLAGS=-static meson setup "$BUILD/b" "$BUILD/bubblewrap-$ver" \
            -Dbuildtype=release -Dman=disabled -Dtests=false \
            -Dselinux=disabled -Dbash_completion=disabled \
            -Dzsh_completion=disabled
        meson compile -C "$BUILD/b"
        strip --strip-unneeded "$BUILD/b/bwrap"
        cp "$BUILD/b/bwrap" /out/
        gate_static /out/bwrap
        ;;
    tar)
        apk add --no-cache build-base linux-headers tar xz
        tar -xJf "/src/tar-$ver.tar.xz" -C "$BUILD"
        cd "$BUILD/tar-$ver"
        # FORCE_UNSAFE_CONFIGURE=1: GNU configure refuses to run as root
        # otherwise, and the container build runs as root.
        FORCE_UNSAFE_CONFIGURE=1 ./configure --prefix=/usr --disable-nls \
            LDFLAGS=-static
        make -j"$(nproc)" tar
        strip --strip-unneeded src/tar
        cp src/tar /out/
        gate_static /out/tar
        ;;
    curl)
        apk add --no-cache build-base linux-headers pkgconf tar xz \
            openssl-dev openssl-libs-static zlib-dev zlib-static \
            zstd-dev zstd-static
        tar -xJf "/src/curl-$ver.tar.xz" -C "$BUILD"
        cd "$BUILD/curl-$ver"
        # Provisioned curl is PATH-FALLBACK ONLY (manifest precedence
        # "path_first"): host curl wins where corporate NSS/LDAP CA dirs
        # matter — musl-static ignores nsswitch.conf and ships no NSS. The
        # ca-certificates bundle path is baked with --with-ca-fallback so an
        # OpenSSL default-cert-dir install still resolves without the bundle.
        # HTTP/2 (nghttp2), brotli, idn2, libpsl, ssh2, ldap trimmed: the
        # floor only owes HTTP(S)/1.1 fetches; fewer static deps, fewer
        # surprise symbol holes.
        LDFLAGS=-static ./configure --prefix=/usr \
            --disable-shared --enable-static \
            --with-openssl \
            --with-ca-bundle=/etc/ssl/certs/ca-certificates.crt \
            --with-ca-fallback \
            --with-zstd --without-brotli --without-nghttp2 --without-libidn2 \
            --without-libpsl --without-libssh2 --disable-ldap --disable-ldaps
        make -j"$(nproc)" curl
        strip --strip-unneeded src/curl
        cp src/curl /out/
        gate_static /out/curl
        ;;
    *)
        echo "FAIL: unknown tool $tool" >&2
        exit 1
        ;;
esac
echo "container recipe: $tool built OK"
CONTAINER
}

# assert_version <binary> <want-substring> — exec smoke ON THE RUNNER
# (x86_64 host runs the musl binary directly); a binary that will not exec
# or does not self-report the pinned version fails the build.
assert_version() {
    local bin=$1 want=$2 out
    [ -x "$bin" ] || die "not executable: $bin"
    out=$("$bin" --version 2>&1 || true)
    case $out in
        *"$want"*) echo "smoke: $bin -> $(printf '%s' "$out" | head -1)" ;;
        *) die "version smoke failed for $bin: expected *$want*, got: $out" ;;
    esac
}

# mksquashfs/unsquashfs use -version (getopt-old style), not --version.
assert_version_dash() {
    local bin=$1 want=$2 out
    [ -x "$bin" ] || die "not executable: $bin"
    out=$("$bin" -version 2>&1 || true)
    case $out in
        *"$want"*) echo "smoke: $bin -> $(printf '%s' "$out" | head -1)" ;;
        *) die "version smoke failed for $bin: expected *$want*, got: $out" ;;
    esac
}

smoke_versions() {
    local tool=$1 out=$2
    case $tool in
        squashfs-tools)
            assert_version_dash "$out/mksquashfs" "$SQUASHFS_TOOLS_VERSION"
            assert_version_dash "$out/unsquashfs" "$SQUASHFS_TOOLS_VERSION"
            ;;
        bubblewrap) assert_version "$out/bwrap" "$BUBBLEWRAP_VERSION" ;;
        tar) assert_version "$out/tar" "$TAR_VERSION" ;;
        curl) assert_version "$out/curl" "$CURL_VERSION" ;;
    esac
}

main() {
    [ "$#" -ge 2 ] || usage
    local mode=$1 dir=$2 out=${3:-}
    case $mode in
        fetch)
            fetch_all "$dir"
            ;;
        squashfs-tools | bubblewrap | tar | curl)
            [ -n "$out" ] || usage
            tool_vars "$mode" || usage
            mkdir -p "$dir" "$out"
            _fetch "$dir" "$V_URL" "$V_SHA"
            run_recipe "$mode" "$dir" "$out"
            smoke_versions "$mode" "$out"
            echo "build-tool.sh: $mode done -> $out"
            ;;
        *) usage ;;
    esac
}

main "$@"
