#!/usr/bin/env bash
# Rebuild the pinned prebuilt mksquashfs/unsquashfs artifacts (#300).
#
# The BINARY hashes are versioned constants in src/provision/mod.rs
# (MKSQUASHFS_ARTIFACT_SHA256 / UNSQUASHFS_ARTIFACT_SHA256): running this
# script is a DELIBERATE re-pin act — the rebuilt artifact ships together
# with one commit that moves those consts, and no worker ever installs
# bytes the compiled-in consts do not name. The SOURCE pin (tarball URL +
# sha, version + release date) is read back OUT of mod.rs so the
# toolchain pin stays single-sourced.
#
# Emits <dist>/mksquashfs, <dist>/unsquashfs, <dist>/SHA256SUMS (default
# /tmp/opencode/farm-lane/dist). Serve that dir at the publish front's
# /bin/ (runbook §1.6) — the same lane as the worker binary — and point
# provisioning at it via NAU_MKSQUASHFS_ARTIFACT_URL.
#
# The binaries are made self-contained the worker-binary way (runbook
# §1.6): patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2
# --remove-rpath — unpatched, a nix-built binary dies on Ubuntu with
# "required file not found". The soname deps (libzstd/liblzma/liblz4/z)
# resolve from the distro runtime libs every Ubuntu LTS carries.
#
# Invocation on a NixOS build host (no apt headers; the flag vars wire
# the nix store paths into the Makefile's EXTRA_CFLAGS / EXTRA_LDFLAGS
# knobs — env NIX_CFLAGS_COMPILE is NOT honored by the cc-wrapper at run
# time, pkg-config filters its store paths away, and nixpkgs splits the
# .so across per-package outputs: headers ride .dev, the sonames ride
# zstd.out / xz.out / lz4.lib / zlib.out). The nix binaries are put on
# PATH, not run under `nix shell -c`: the pod curl shim loses DNS inside
# it, and SSL_CERT_FILE feeds its OpenSSL the system CA bundle.
#   GCCD=$(nix eval --raw nixpkgs#gcc.out; echo)
#   PED=$(nix eval --raw nixpkgs#patchelf.out; echo)
#   INCS=$(for p in zstd xz lz4 zlib; do nix eval --raw nixpkgs#$p.dev; echo; done)
#   LIBS=$(nix eval --raw nixpkgs#zstd.out; echo
#          nix eval --raw nixpkgs#xz.out; echo
#          nix eval --raw nixpkgs#lz4.lib; echo
#          nix eval --raw nixpkgs#zlib.out)
#   export SQUASHFS_ARTIFACT_CFLAGS="$(printf -- '-I%s/include\n' $INCS | paste -sd' ')"
#   export SQUASHFS_ARTIFACT_LDFLAGS="$(printf -- '-L%s/lib\n' $LIBS | paste -sd' ')"
#   export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
#   env -u LD_LIBRARY_PATH -u COMPILER_PATH -u LIBRARY_PATH \
#     PATH="$GCCD/bin:$PED/bin:$PATH" CC=gcc \
#     bash scripts/build-mksquashfs-artifact.sh
# On an apt host with libzstd-dev/liblzma-dev/liblz4-dev/zlib1g-dev the
# plain script suffices: the headers sit on the default search paths.
set -euo pipefail

REPO=$(git rev-parse --show-toplevel)
MOD="$REPO/src/provision/mod.rs"
DIST="${1:-/tmp/opencode/farm-lane/dist}"

# Read a `pub const NAME: &str = "...";` value out of mod.rs (same line
# or wrapped onto the next) — the pin's single source. An empty
# extraction fails the run.
pin() {
    grep -A1 "^pub const $1: &str" "$MOD" | grep -o '"[^"]*"' | head -n1 | tr -d '"'
}
VERSION=$(pin SQUASHFS_TOOLS_VERSION)
RELEASE_DATE=$(pin SQUASHFS_TOOLS_RELEASE_DATE)
TARBALL_URL=$(pin SQUASHFS_TOOLS_TARBALL_URL)
TARBALL_SHA=$(pin SQUASHFS_TOOLS_SHA256)
: "${VERSION:?SQUASHFS_TOOLS_VERSION not found in $MOD}"
: "${RELEASE_DATE:?SQUASHFS_TOOLS_RELEASE_DATE not found in $MOD}"
: "${TARBALL_URL:?SQUASHFS_TOOLS_TARBALL_URL not found in $MOD}"
: "${TARBALL_SHA:?SQUASHFS_TOOLS_SHA256 not found in $MOD}"

WORK=$(mktemp -d)
TARBALL="squashfs-tools-$VERSION.tar.gz"

# The source gate first: exact tarball bytes before a single byte builds.
curl -fsSL "$TARBALL_URL" -o "$WORK/$TARBALL"
echo "$TARBALL_SHA  $TARBALL" | (cd "$WORK" && sha256sum -c -)
tar -C "$WORK" -xzf "$WORK/$TARBALL"
SRC="$WORK/squashfs-tools-$VERSION/squashfs-tools"

# Same explicit compression set the worker template pinned before #300:
# xz/zstd/lz4 on, lzo off (no liblzo2 on the worker image), gzip default.
# The version/date force keeps the codeload tarball from baking its
# commit hash into the version string the admission gate reads. Header
# and library discovery ride the Makefile's EXTRA_CFLAGS/EXTRA_LDFLAGS
# knobs (empty defaults; see the nix invocation in the header) — the
# script itself stays toolchain-agnostic.
make -C "$SRC" -j"$(nproc)" \
    XZ_SUPPORT=1 ZSTD_SUPPORT=1 LZ4_SUPPORT=1 LZO_SUPPORT=0 \
    RELEASE_VERSION="$VERSION" RELEASE_DATE="$RELEASE_DATE" \
    EXTRA_CFLAGS="${SQUASHFS_ARTIFACT_CFLAGS:-}" \
    EXTRA_LDFLAGS="${SQUASHFS_ARTIFACT_LDFLAGS:-}" \
    mksquashfs unsquashfs

# The artifact must report the EXACT pin (version AND date) before it
# ships — the same string the worker admission gate reads. Checked BEFORE
# the patchelf leg: afterwards the interpreter is Ubuntu's, which a nix
# build host does not carry.
"$SRC/mksquashfs" -version | grep -q "version $VERSION ($RELEASE_DATE)"

for b in mksquashfs unsquashfs; do
    patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 --remove-rpath "$SRC/$b"
done

mkdir -p "$DIST"
cp -a "$SRC/mksquashfs" "$SRC/unsquashfs" "$DIST/"
(cd "$DIST" && sha256sum mksquashfs unsquashfs > SHA256SUMS)

echo "artifact dist: $DIST"
cat "$DIST/SHA256SUMS"
echo "paste into src/provision/mod.rs as MKSQUASHFS_ARTIFACT_SHA256 / UNSQUASHFS_ARTIFACT_SHA256"
