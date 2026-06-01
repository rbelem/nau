-- Ubuntu Core base rootfs with full disk image layout
--
-- Build with: shoot image --file examples/rootfs/shoot.lua
-- Produces a full GPT disk image with ESP + btrfs root + swap.
--
-- Before running, ensure:
--   package-index.json exists (shoot index resolve)
--   sudo or losetup/mount permissions for disk image creation

return {
    rootfs = image {
        name = "ubuntu-core-rootfs",
        version = "22.04",

        -- Base filesystem from core22 snap
        base = index("core22"),

        -- Kernel snap with boot parameters
        kernel = merge(pin("pc-kernel"), {
            params = {
                "quiet",
                "splash",
                "console=tty1",
                "net.ifnames=0",
                "systemd.unified_cgroup_hierarchy=1",
            },
            modules = {
                "nvme",
                "thunderbolt",
                "usb_storage",
            },
        }),

        -- Gadget for x86_64 PC hardware
        gadget = index("pc-gadget"),

        -- Extra snaps
        snaps = {
            index("snapd"),
        },

        -- Bootloader config
        bootloader = {
            type = "systemd-boot",
            timeout = 3,
        },

        -- Full disk partition layout (creates a bootable .img)
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
                    size = "0",  -- remaining disk space
                    fs = "btrfs",
                    mount = "/",
                    options = {
                        "subvol=rootfs",
                        "compress=zstd",
                        "noatime",
                        "ssd",
                        "discard=async",
                    },
                },
            },
            swap = {
                size = "8G",
            },
        },

        -- Kernel sysctl tuning
        sysctl = {
            "vm.swappiness=100",
            "kernel.kptr_restrict=2",
            "kernel.dmesg_restrict=1",
        },
    },
}
