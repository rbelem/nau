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
--   shuttle image --file examples/full-system/pc-rootfs/shuttle.lua --arch amd64
--
-- Requires:
--   package-index.json with resolved snaps (shuttle index resolve)
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
                -- tty1 is the local console; ttyS0 mirrors the boot to the
                -- serial port so `shuttle test` (QEMU `-serial`) can observe
                -- userspace. Without a serial console the harness sees an
                -- empty log even on a successful boot.
                "console=tty1",
                "console=ttyS0",
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
                    -- A grow-to-fill "0" root takes the space left after the
                    -- ESP and swap. That alone is only ~1G here, which the
                    -- populated core22 rootfs plus LXD overflows (`mkfs.ext4
                    -- -d` fails with "Could not allocate block"), so the root
                    -- asks for 3G explicitly and the disk grows to fit.
                    size = "3G",
                    -- ext4, not btrfs: the unprivileged file-based build
                    -- populates with `mkfs.ext4 -d` and has no loop-device
                    -- backend, so a btrfs root fails closed at populate time.
                    fs = "ext4",
                    mount = "/",
                    options = {
                        "noatime",
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
