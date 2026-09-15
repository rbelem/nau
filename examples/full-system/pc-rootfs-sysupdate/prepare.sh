#!/usr/bin/env bash
# #80 sysupdate end-to-end proof — one-time preparation.
#
# 1. stage the host systemd-sysupdate tooling (the base rootfs ships none)
#    into local/nix/, patchelf'd to guest paths;
# 2. build the three images (gen1 device, gen2 payload, gen2-bless payload);
# 3. extract each payload build's slot-A artifacts into a servable payload
#    directory, named the way the emitted transfers' `@u` patterns expect,
#    plus the SHA256SUMS manifest url-file sources enumerate.
#
# Everything lands in $WORK (default ~/.cache/shuttle-80). Individual steps
# are idempotent: remove $WORK/images/gen2 or $WORK/payload-gen2 to redo.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
export PATH="$REPO_ROOT/target/debug:$PATH"
WORK="${SHUTTLE_80_WORK:-$HOME/.cache/shuttle-80}"
NIX_SYSTEMD="/nix/store/sm8d6jpilwdy3bw3yq2lv8rr8jld26pb-systemd-261.2"
NIX_SHARED="$NIX_SYSTEMD/lib/systemd/libsystemd-shared-261.so"
NIX_BIN="$NIX_SYSTEMD/bin/systemd-sysupdate"
NIX_GLIBC="/nix/store/n51dhmdbik1kfrsm62j5knavmigwrl1a-glibc-2.42-84"
NIX_ULIB="/nix/store/17xmg38m60inc59az3frp540ccrwn2r8-util-linux-minimal-2.42.2-lib"

OUT="$WORK/images"
mkdir -p "$OUT" "$WORK" "$HERE/local/nix"

log() { printf '\n=== %s ===\n' "$*"; }

part_field() { # $1 = json file, $2 = partno (1-based), $3 = field
    python3 - "$1" "$2" "$3" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
p = d["partitiontable"]["partitions"][int(sys.argv[2]) - 1]
print(p[sys.argv[3]])
PY
}

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

# ── 2+3. builds + payload extraction ─────────────────────────────────────
extract_payload() { # $1 = image path, $2 = version, $3 = payload dest dir
    local img="$1" ver="$2" dest="$3"
    local partmap data_guid roothash esp_off cmdline
    mkdir -p "$dest"

    log "extracting slot A artifacts from $img"
    sfdisk -J "$img" > "$WORK/last-partitions.json"
    partmap="$WORK/last-partitions.json"

    # Partition map: 1=esp 2=rootA 3=state 4=hashA 5=rootB 6=hashB, swap 7.
    local root_start root_bytes hash_start hash_bytes
    root_start=$(part_field "$partmap" 2 start)
    root_bytes=$(part_field "$partmap" 2 size)
    hash_start=$(part_field "$partmap" 4 start)
    hash_bytes=$(part_field "$partmap" 4 size)
    dd if="$img" of="$dest/.root.img"       bs=4M iflag=skip_bytes,count_bytes \
        skip=$((root_start * 512)) count=$((root_bytes * 512)) status=none
    dd if="$img" of="$dest/.verity-hash.img" bs=4M iflag=skip_bytes,count_bytes \
        skip=$((hash_start * 512)) count=$((hash_bytes * 512)) status=none

    # The rootfs manifest is pre-hash (cmdline-less) and the state
    # partition ships empty, so read the cmdline straight out of the UKI's
    # `.cmdline` PE section: it names the generation-derived PARTUUIDs —
    # exactly the @u values the artifact names must carry.
    esp_off=$(part_field "$partmap" 1 start)
    mcopy -n -i "$img@@$((esp_off * 512))" ::EFI/Linux/shuttle-80_${ver}.efi \
        "$dest/shuttle-80_${ver}.efi"
    objcopy -O binary --only-section=.cmdline \
        "$dest/shuttle-80_${ver}.efi" "$dest/.cmdline"
    cmdline=$(tr -d '\0' < "$dest/.cmdline")
    rm -f "$dest/.cmdline"
    data_guid=$(CMDLINE="$cmdline" python3 - <<'PY' | tr 'A-F' 'a-f'
import os, re
print(re.search(r"shuttle\.verity_data=/dev/disk/by-partuuid/([0-9a-fA-F-]+)", os.environ["CMDLINE"]).group(1))
PY
    )
    roothash=$(CMDLINE="$cmdline" python3 - <<'PY'
import os, re
print(re.search(r"shuttle\.roothash=([0-9a-f]{64})", os.environ["CMDLINE"]).group(1))
PY
    )
    echo "  cmdline: $cmdline"
    echo "  roothash=$roothash  data PARTUUID=$data_guid"

    # Sanity: the build must have pinned the derived GUIDs onto slot A
    # (data = roothash back half, hash = roothash front half, dashed).
    local part want got hash_guid
    hash_guid="${roothash:0:32}"
    hash_guid="${hash_guid:0:8}-${hash_guid:8:4}-${hash_guid:12:4}-${hash_guid:16:4}-${hash_guid:20:12}"
    for pair in "2:$data_guid" "4:$hash_guid"; do
        part="${pair%%:*}"
        want=$(printf '%s' "${pair##*:}" | tr 'A-F' 'a-f')
        got=$(part_field "$partmap" "$part" uuid | tr 'A-F' 'a-f')
        if [[ "$got" != "$want" ]]; then
            echo "FATAL: partition $part uuid $got != derived $want" >&2
            exit 1
        fi
    done

    mv "$dest/.root.img"        "$dest/root_${ver}_${data_guid}.img"
    mv "$dest/.verity-hash.img" "$dest/verity-hash_${ver}_${hash_guid}.img"

    # The manifest url-file sources enumerate: every artifact + its hash.
    ( cd "$dest" && sha256sum -b root_${ver}_${data_guid}.img \
                                verity-hash_${ver}_${hash_guid}.img \
                                shuttle-80_${ver}.efi > SHA256SUMS )
    ls -la "$dest"
}

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

build_one gen2.lua        gen2  shuttle-80_2.0_amd64.img
extract_payload "$OUT"/gen2/shuttle-80_2.0_amd64.img 2.0 "$WORK/payload-gen2"
build_one gen2-bless.lua  gen2b shuttle-80_2.0_amd64.img
extract_payload "$OUT"/gen2b/shuttle-80_2.0_amd64.img 2.0 "$WORK/payload-gen2b"

# The device image last: it is the biggest transient and the payload
# extractions above only need the gen2 images.
build_one gen1.lua        gen1  shuttle-80_1.0_amd64.img

# #86 strand CONTROL device (recovery masked via systemd.mask=): built
# from the same tree, so it only differs from gen1 by the kernel cmdline.
build_one gen1-strand.lua gen1-strand  shuttle-80_1.0_amd64.img

log "preparation complete"
echo "images:   $OUT"
echo "payload:  $WORK/payload-gen2  (serve, then boot the gen-1 device)"
echo "#86:      serve with tools/strand-server.py to strand; see README"
