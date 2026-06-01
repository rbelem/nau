-- Ubuntu Core 22.04 rootfs image for x86_64 PC hardware
--
-- Compose a bootable disk image with:
--   - core22 base rootfs
--   - pc-kernel with boot params
--   - pc-gadget boot config
--   - snapd + network-manager + lxd
--   - GPT disk: ESP (vfat) + root (btrfs) + swap
--   - systemd-boot bootloader
--
-- Build:
--   shoot image --file examples/pc-rootfs/shoot.lua --arch amd64
--
-- Requires:
--   package-index.json with resolved snaps (shoot index resolve)
--   parted, losetup, mkfs.vfat, mkfs.btrfs, dd on PATH
--   sudo or permissions for loop device + mount

return {
    rootfs = image {
        name = "ubuntu-core-pc",
        version = "22.04",

        base = index("core22"),

        kernel = merge(pin("pc-kernel"), {
            params = {
                "quiet",
                "splash",
                "console=tty1",
                "net.ifnames=0",
                "systemd.unified_cgroup_hierarchy=1",
                "module.sig_enforce=1",
                "lockdown=confidentiality",
            },
            modules = {
                "nvme",
                "thunderbolt",
                "usb_storage",
                "intel_lpss_pci",
            },
        }),

        gadget = index("pc-gadget"),

        snaps = {
            index("snapd"),
            index("network-manager"),
            index("lxd"),
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
                    fs = "btrfs",
                    mount = "/",
                    options = {
                        "subvol=@",
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

        sysctl = {
            "vm.swappiness=100",
            "kernel.kptr_restrict=2",
            "kernel.dmesg_restrict=1",
            "net.ipv4.conf.all.rp_filter=1",
            "net.ipv4.tcp_syncookies=1",
        },
    },
}
