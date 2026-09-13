#!/bin/sh
# #80 in-guest sysupdate diagnostic v3 — bisect the silent exit.
exec 2>&1
export SYSTEMD_LOG_TARGET=console
export SYSTEMD_LOG_LEVEL=debug

echo "=== defs present? ==="
ls -la /usr/lib/sysupdate.d/

echo "=== empty defs dir ==="
mkdir -p /run/empty-defs
/usr/bin/systemd-sysupdate --definitions=/run/empty-defs --verify=no --offline list
echo "empty rc=$?"

echo "=== --offline list (default defs) ==="
/usr/bin/systemd-sysupdate --verify=no --offline list
echo "offline rc=$?"

echo "=== bare list ==="
/usr/bin/systemd-sysupdate list
echo "bare rc=$?"

echo "=== update ==="
export LIBFDISK_DEBUG=all
export LIBBLKID_DEBUG=lowlevel
export LIBMOUNT_DEBUG=all
/usr/bin/systemd-sysupdate --verify=no update
echo "update rc=$?"

echo "=== direct pull binary, no args ==="
/usr/lib/systemd/systemd-pull
echo "pull-noargs rc=$?"

echo "=== direct pull binary, real fetch ==="
/usr/lib/systemd/systemd-pull raw --direct --verify no http://10.0.2.2:8123/SHA256SUMS -
echo "pull-fetch rc=$?"

echo "=== dmesg tail ==="
dmesg | tail -8
