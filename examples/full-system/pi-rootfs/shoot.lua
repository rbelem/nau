-- Ubuntu Core 22.04 rootfs image for Raspberry Pi (arm64)
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
--   shoot image --file examples/full-system/pi-rootfs/shoot.lua --arch arm64
--
-- Requires:
--   package-index.json with resolved snaps (shoot index resolve)
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
