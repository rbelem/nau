#!/usr/bin/env bash
# Reproduce the guest's sysupdate environment on the host with bwrap:
# /nix is a fresh tmpfs containing ONLY the staged closure (like the
# guest rootfs), so any missing-library symptom reproduces here.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NIX_SRC="$(cd "$HERE/../local/nix" && pwd)"
SM8="/nix/store/sm8d6jpilwdy3bw3yq2lv8rr8jld26pb-systemd-261.2"
N51="/nix/store/n51dhmdbik1kfrsm62j5knavmigwrl1a-glibc-2.42-84"
ULIB="/nix/store/17xmg38m60inc59az3frp540ccrwn2r8-util-linux-minimal-2.42.2-lib"

bwrap \
  --ro-bind /tmp /tmp \
  --ro-bind /usr /usr \
  --ro-bind /lib /lib \
  --ro-bind /lib64 /lib64 \
  --ro-bind /bin /bin \
  --dev-bind /dev /dev \
  --proc /proc \
  --ro-bind /sys /sys \
  --tmpfs /nix \
  --ro-bind "$NIX_SRC/libsystemd-shared-261.so" "$SM8/lib/systemd/libsystemd-shared-261.so" \
  --ro-bind "$NIX_SRC/libc.so.6" "$N51/lib/libc.so.6" \
  --ro-bind "$NIX_SRC/ld-linux-x86-64.so.2" "$N51/lib/ld-linux-x86-64.so.2" \
  --ro-bind "$NIX_SRC/libblkid.so.1" "$ULIB/lib/libblkid.so.1" \
  --ro-bind "$NIX_SRC/libfdisk.so.1" "$ULIB/lib/libfdisk.so.1" \
  --ro-bind "$NIX_SRC/libmount.so.1" "$ULIB/lib/libmount.so.1" \
  --ro-bind "$NIX_SRC/libsmartcols.so.1" "$ULIB/lib/libsmartcols.so.1" \
  --ro-bind "$NIX_SRC/libuuid.so.1" "$ULIB/lib/libuuid.so.1" \
  --ro-bind "$HOME/.cache/shuttle-80/curl-libs-test/libcurl.so.4" "/nix/store/x4xicianwlchh2cadblv4pfz8syvl97b-curl-8.21.0/lib/libcurl.so.4" \
  --ro-bind "$HOME/.cache/shuttle-80/usrlib-systemd/curl-libs" "/nix/store/x4xicianwlchh2cadblv4pfz8syvl97b-curl-8.21.0/../curl-test-libs" \
  --ro-bind "$HOME/.cache/shuttle-80/curl-libs-test" /opt/curl-libs \
  --ro-bind /tmp/pull /opt/systemd-pull-under-test \
  --ro-bind "$NIX_SRC/systemd-sysupdate" /opt/systemd-sysupdate \
  "$@"
