#!/usr/bin/env bash
# #80 sysupdate end-to-end proof — one-time preparation.
#
# 1. stage the host systemd-sysupdate tooling (the base rootfs ships none)
#    into local/nix/, patchelf'd to guest paths;
# 2. build the three images (gen1 device, gen2 payload, gen2-bless payload);
# 3. publish each payload build through the LANDED RELEASE PRODUCER
#    (`shuttle image --release`, #274): the slot-A artifacts land under
#    their `@u`-PARTUUID names with the SIGNED SHA256SUMS +
#    SHA256SUMS.gpg beside them — the same sums signature the device's
#    `Verify=yes` checks at update time. The release self-check (verify
#    over the published set, #293) runs in-process during the publish.
#
# The real device-side verification — systemd-sysupdate running the gpg
# subprocess against import-pubring.pgp, and the http-fetch stand-in
# below swapped back for the real systemd-pull — folds into the deferred
# QEMU axis (#80 live update run).
#
# Everything lands in $WORK (default ~/.cache/shuttle-80). Individual steps
# are idempotent: remove $WORK/payload-gen2 to redo a payload release.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
export PATH="$REPO_ROOT/target/debug:$PATH"
WORK="${SHUTTLE_80_WORK:-$HOME/.cache/shuttle-80}"
# Pin the epoch once: `--release` refuses without it (ADR-0044 D8), and
# the pin is what keeps the payload releases deterministic.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1704067200}"
NIX_SYSTEMD="/nix/store/sm8d6jpilwdy3bw3yq2lv8rr8jld26pb-systemd-261.2"
NIX_SHARED="$NIX_SYSTEMD/lib/systemd/libsystemd-shared-261.so"
NIX_BIN="$NIX_SYSTEMD/bin/systemd-sysupdate"
NIX_GLIBC="/nix/store/n51dhmdbik1kfrsm62j5knavmigwrl1a-glibc-2.42-84"
NIX_ULIB="/nix/store/17xmg38m60inc59az3frp540ccrwn2r8-util-linux-minimal-2.42.2-lib"

OUT="$WORK/images"
mkdir -p "$OUT" "$WORK" "$HERE/local/nix"

log() { printf '\n=== %s ===\n' "$*"; }

# ── 0. the update signing key (ADR-0024 §4: builds never mint one) ──────
if [[ ! -f "$WORK/key-home/.config/shuttle/secret-key" ]]; then
    log "minting the proof signing key (shuttle key keygen)"
    HOME="$WORK/key-home" shuttle key keygen
else
    log "signing key present"
fi

# ── 1. guest tooling ─────────────────────────────────────────────────────
if [[ -f "$HERE/local/nix/systemd-sysupdate" && -f "$HERE/local/nix/libc.so.6" ]]; then
    log "guest sysupdate tooling already staged"
else
    log "staging the guest sysupdate tooling (self-contained nix closure)"
    # The nix-built libsystemd-shared-261.so requires GLIBC_ABI_GNU2_TLS
    # (gnu2-tls descriptors, glibc >= 2.36) which the core22 guest glibc
    # 2.35 does not provide — so the binary cannot run against the guest
    # loader/libc. Instead ship the closure VERBATIM at its absolute
    # /nix/store paths: PT_INTERP, libc and the shared lib all resolve
    # inside the staged tree and nothing from the guest is used. The four
    # dest paths in gen1.lua must match these hash directories.
    cp "$NIX_BIN" "$HERE/local/nix/systemd-sysupdate"
    # The download worker sysupdate spawns for every url-file transfer.
    cp "$NIX_SYSTEMD/lib/systemd/systemd-pull" "$HERE/local/nix/systemd-pull"
    # The real systemd-pull needs its libcurl dlopen closure; for the
    # proof, a 130-line Rust fetcher (plain HTTP GET to stdout, GLIBC_2.34
    # ceiling) is anchored to the guest loader instead, dropping ~25 nix
    # libraries from the staging.
    ( cd "$REPO_ROOT" && CARGO_BUILD_JOBS=3 cargo build --release \
        --manifest-path "$HERE/tools/Cargo.toml" )
    # Host-side smoke test of the exact argument shape sysupdate passes.
    "$HERE/local/nix/systemd-pull" --help >/dev/null 2>&1 || true
    cp "$HERE/tools/target/release/http-fetch" "$HERE/local/nix/systemd-pull"
    patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 \
             "$HERE/local/nix/systemd-pull"
    cp "$NIX_SHARED" "$HERE/local/nix/libsystemd-shared-261.so"
    cp "$NIX_GLIBC/lib/libc.so.6" "$HERE/local/nix/libc.so.6"
    cp "$NIX_GLIBC/lib/ld-linux-x86-64.so.2" "$HERE/local/nix/ld-linux-x86-64.so.2"
    # glibc compat stubs the dlopened libs reference (libfdisk needs
    # libpthread.so.0; without it the dlopen fails with a bare ENOENT and
    # sysupdate exits 1 silently).
    for lib in libpthread.so.0 libdl.so.2 librt.so.1; do
        cp "$NIX_GLIBC/lib/$lib" "$HERE/local/nix/$lib"
    done
    # systemd dlopens util-linux's libblkid (ESP/filesystem probing) and
    # libfdisk (partition enumeration); without them sysupdate fails with
    # a bare EOPNOTSUPP / silent exit. Stage the whole util-linux lib set
    # at the /nix/store path libsystemd-shared's RUNPATH already searches.
    for lib in libblkid.so.1 libfdisk.so.1 libmount.so.1 libsmartcols.so.1 libuuid.so.1; do
        cp "$NIX_ULIB/lib/$lib" "$HERE/local/nix/$lib"
    done
fi

# ── 2+3. builds + payload publication (the landed release producer) ─────
build_one() { # $1 = lua, $2 = outdir, $3 = image file name
    if [[ -f "$OUT/$2/$3" ]]; then
        log "image $2 already built"
        return
    fi
    log "building $1"
    # Run from the repo root so the default package-index.json is found;
    # the lua's own dir is where --file points and where files[] sources
    # resolve (relative to the lua, not the cwd).
    ( cd "$REPO_ROOT" && HOME="$WORK/key-home" shuttle image \
        --file "$HERE/$1" --arch amd64 --output "$OUT/$2" )
}

# Payload builds go through `shuttle image --release` (#274): the producer
# publishes the slot-A artifacts under the exact `@u`-PARTUUID names the
# emitted transfers fetch, with SHA256SUMS + its detached signature
# (SHA256SUMS.gpg) beside them. The @u names are derived from the same
# roothash the build pinned on its slots, so name↔partition agreement is
# the producer's own invariant — the QEMU update run is where the device
# proves it end-to-end.
build_release() { # $1 = lua, $2 = payload dest dir
    if [[ -f "$2/SHA256SUMS.gpg" ]]; then
        log "payload release $2 already published"
        return
    fi
    log "building + publishing $1 (release producer: signed SHA256SUMS)"
    ( cd "$REPO_ROOT" && HOME="$WORK/key-home" shuttle image \
        --file "$HERE/$1" --arch amd64 --release "$2" )
    for artifact in SHA256SUMS SHA256SUMS.gpg; do
        [[ -s "$2/$artifact" ]] || {
            echo "FATAL: release published no $artifact in $2" >&2
            exit 1
        }
    done
    ls -la "$2"
}

build_release gen2.lua       "$WORK/payload-gen2"
build_release gen2-bless.lua "$WORK/payload-gen2b"

# The device image last: it is the biggest transient and the payload
# releases above only need the gen2 images.
build_one gen1.lua        gen1  shuttle-80_1.0_amd64.img

# #86 strand CONTROL device (recovery masked via systemd.mask=): built
# from the same tree, so it only differs from gen1 by the kernel cmdline.
build_one gen1-strand.lua gen1-strand  shuttle-80_1.0_amd64.img

log "preparation complete"
echo "images:   $OUT  (gen1 devices)"
echo "payload:  $WORK/payload-gen2  (signed sums; serve, then boot the gen-1 device)"
echo "#86:      serve with tools/strand-server.py to strand; see README"
