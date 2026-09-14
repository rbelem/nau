-- Ubuntu Core 22.04 rootfs image for Raspberry Pi (arm64)
--
-- SANITY STATUS (issue #74, measured against the real store snaps): the
-- pi-kernel payload is a shape no shuttle boot chain can consume —
-- `kernel.img` is a gzip-compressed ARM64 Image and the Pi firmware boots
-- the gadget's boot-assets (config.txt, cmdline.txt, DTBs), not
-- systemd-boot. A build fails closed at payload location with the named
-- reason; the rootfs side (core22 base + pi-kernel module tree staging)
-- is proven by the squashfs-only evidence run in the issue. Implementing
-- the Pi boot chain is #87, the ADR-0025 follow-up.
--
-- Compose a bootable disk image with:
--   - core22 base rootfs
--   - pi-kernel with boot params
--   - pi-gadget boot config (u-boot)
--   - snapd + network-manager
--   - GPT disk: ESP (vfat) + root (ext4) + swap
--   - u-boot bootloader (from gadget snap)
--
-- Build:
--   shuttle image --file examples/full-system/pi-rootfs/shuttle.lua --arch arm64
--
-- Requires:
--   package-index.json with resolved snaps (shuttle index resolve)
--   parted, losetup, mkfs.vfat, mkfs.ext4, dd on PATH

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
            type = "systemd-boot",
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
                    size = "0",
                    fs = "ext4",
                    mount = "/",
                    options = {
                        "noatime",
                        "discard",
                    },
                },
            },
            swap = {
                size = "4G",
            },
        },

        sysctl = {
            "vm.swappiness=100",
            "kernel.kptr_restrict=2",
            "kernel.dmesg_restrict=1",
        },
    },
}
