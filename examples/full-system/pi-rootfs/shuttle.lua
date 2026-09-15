-- Ubuntu Core 22.04 rootfs image for Raspberry Pi (arm64)
--
-- STATUS (issue #87, the Pi boot chain): `bootloader.type = "piboot"` is
-- the implemented Raspberry Pi backend (ADR-0025 amendment). The build
-- stages, onto the single vfat firmware partition:
--   - the gadget's boot-assets/ VERBATIM (start.elf family, fixup*.dat,
--     bootcode.bin, per-board DTBs, overlays/, psplash);
--   - the pi-kernel payload verbatim under the names the gadget's own
--     config.txt references: kernel.img (a gzip-wrapped ARM64 Image the
--     Pi firmware decompresses itself) and initrd.img;
--   - the kernel snap's board DTBs (dtbs/broadcom, dtbs/overlays);
--   - cmdline.txt REWRITTEN with the declared kernel params + the
--     root=PARTUUID binding (the Pi equivalent of the UKI-embedded cmdline);
--   - config.txt from the gadget with the `initramfs` line dropped (the
--     stock snap-bootstrap initramfs mounts a writable ubuntu-data and
--     cannot honor this image's cmdline).
--
-- Named scope limits (ADR-0025 amendment, #87): NO dm-verity (raspi
-- builds DM_VERITY=m and shuttle has no arm64 native initramfs yet — the
-- root is a plain ext4 partition, audited built-in), and NO boot
-- assessment (try-boot/revert is a systemd-boot protocol; disk.ab and
-- update_source are REFUSED for piboot rather than shipped inert).
--
-- Boot proof status (#88): the FULL chain (VideoCore firmware -> kernel)
-- needs real Pi hardware — QEMU does not emulate start.elf/config.txt.
-- The deepest emulator reach is a `-M virt` TCG probe of the STAGED
-- payload kernel against THIS image (kernel-only, not the product boot
-- path): the raspi kernel carries the -M virt platform built-in
-- (PCI_HOST_GENERIC + NVME + EXT4_FS + PL011 console are '=y'), so it
-- mounts this image's real root from a QEMU NVMe with no initramfs and
-- reaches userspace. Probe (adjusts only what the emulated hardware
-- lacks — no VideoCore, so no firmware handoff and no SD/MMC root):
--   zcat <pi-kernel snap>/kernel.img > /tmp/Image   # the gzip unwrap the
--                                                   # firmware performs
--   qemu-system-aarch64 -M virt -cpu cortex-a53 -smp 2 -m 2G \
--     -kernel /tmp/Image \
--     -append "net.ifnames=0 systemd.unified_cgroup_hierarchy=1 rootwait \
--       rw root=PARTUUID=<p2-uuid> console=ttyAMA0,115200" \
--     -drive file=ubuntu-core-pi_22.04_arm64.img,if=none,id=d,format=raw \
--     -device nvme,drive=d,serial=probe -display none -monitor none \
--     -serial file:pi-tcg-probe.serial.log
-- The product boot path itself (cmdline.txt root=PARTUUID= on the SD's
-- MMC partition) is verified only on hardware — recipe in ADR-0025.
--
-- Build:
--   shuttle image --file examples/full-system/pi-rootfs/shuttle.lua --arch arm64
--
-- Requires:
--   package-index.json with resolved snaps (shuttle index resolve)
--   parted, sfdisk, mtools, mkfs.vfat, mkfs.ext4, dd, unsquashfs on PATH

return {
    rootfs = image {
        name = "ubuntu-core-pi",
        version = "22.04",

        base = index("core22"),

        kernel = merge(pin("pi-kernel"), {
            params = {
                "quiet",
                "splash",
                "console=serial0,115200",
                "console=tty1",
                "net.ifnames=0",
                "systemd.unified_cgroup_hierarchy=1",
                "dwc_otg.lpm_enable=0",
                "rootwait",
            },
            modules = {
                "dwc2",
                "vc4",
                "bcm2835_dma",
            },
        }),

        gadget = index("pi-gadget"),

        snaps = {
            index("snapd"),
            index("network-manager"),
        },

        bootloader = {
            type = "piboot",
            timeout = 3,
        },

        disk = {
            label = "gpt",
            partitions = {
                {
                    name = "esp",
                    size = "512M",
                    fs = "vfat",
                    mount = "/boot",
                },
                {
                    name = "root",
                    -- #87, measured: the real arm64 rootfs (core22 + 4,446
                    -- pi-kernel module files + snapd + NM + the embedded
                    -- shuttle binary) exceeds 1 GB — the "0" grow-to-fill
                    -- default is 1 GB, and a too-small root fails closed at
                    -- populate. Declare a real size.
                    size = "4G",
                    fs = "ext4",
                    mount = "/",
                    options = {
                        "noatime",
                        "discard",
                    },
                },
            },
            swap = {
                size = "1G",
            },
        },

        sysctl = {
            "vm.swappiness=100",
            "kernel.kptr_restrict=2",
            "kernel.dmesg_restrict=1",
        },
    },
}
