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
