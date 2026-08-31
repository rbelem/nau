-- system-base: minimal bootable rootfs for QEMU/KVM
--
-- Defines the absolute minimum set of packages needed to boot a
-- Linux system under QEMU/KVM and reach a shell prompt.
--
-- Build:
--   1. Build each dependency:  shuttle build --file pkgs/<path>/shuttle.lua
--   2. Assemble the image:     shuttle image --file pkgs/s/system-base/shuttle.lua
--
-- Boot with QEMU:
--   qemu-system-x86_64 -m 2G -smp 2 -enable-kvm       \
--     -drive file=system-base_1.0.0_amd64.img,if=virtio \
--     -serial mon:stdio
--
-- The 13 essential packages + 2 meta-packages:
--   pc-kernel  → Linux kernel + virtio modules
--   pc-gadget  → EFI bootloader configuration
--   systemd    → init, udev, journald, service manager
--   glibc      → C runtime (everything links here)
--   bash       → shell
--   coreutils  → ls, cp, mv, cat, rm, echo, printf...
--   shadow     → login, useradd, passwd, su
--   linux-pam  → PAM authentication modules
--   kmod       → modprobe, lsmod, depmod
--   util-linux → mount, reboot, dmesg, lsblk, fdisk
--   procps     → ps, kill, top, uptime, w
--   toolchain  → default compiler (resolves via alias to gcc-gnu)
--   build-deps → make, autotools, pkg-config

return {
    ["system-base"] = image {
        name = "system-base",
        version = "1.0.0",

        -- Kernel optimized for virtualized environments
        kernel = merge(pin("pc-kernel"), {
            params = {
                "quiet",
                "console=ttyS0,115200",
                "earlyprintk=ttyS0",
                "printk.devkmsg=on",
                "panic=-1",
                "net.ifnames=0",
                "biosdevname=0",
            },
            modules = {
                "virtio",
                "virtio_balloon",
                "virtio_console",
                "virtio_input",
                "virtio_net",
                "virtio_rng",
            },
        }),

        -- Bootloader (EFI + systemd-boot)
        gadget = index("pc-gadget"),

        bootloader = {
            type = "systemd-boot",
            timeout = 1,
        },

        -- Base: systemd provides the init system, udev, and journald
        -- that everything else builds on.
        base = pin("systemd"),

        -- Extra system packages (all snapped, available at runtime)
        snaps = {
            pin("glibc"),
            pin("bash"),
            pin("coreutils"),
            pin("shadow"),
            pin("linux-pam"),
            pin("kmod"),
            pin("util-linux"),
            pin("procps"),
            -- Toolchain (resolved via alias → toolchain-gcc-gnu-x86_64)
            pin("toolchain"),
            -- Build tools (make, autotools, pkg-config)
            pin("build-deps"),
        },

        -- Disk layout suitable for QEMU virtio
        disk = {
            label = "gpt",
            partitions = {
                {
                    name = "esp",
                    size = "256M",
                    fs = "vfat",
                    mount = "/boot",
                },
                {
                    name = "root",
                    size = "0",
                    fs = "ext4",
                    mount = "/",
                    options = { "noatime" },
                },
            },
        },

        -- System tuning
        sysctl = {
            "vm.swappiness=10",
            "kernel.kptr_restrict=2",
        },
    },
}
