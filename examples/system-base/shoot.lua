-- Minimal rootfs for QEMU/KVM, using the 11 essential packages
-- defined in pkgs/s/system-base/.
--
-- Build:   shoot image --file examples/system-base/shoot.lua --arch amd64
-- Boot:    qemu-system-x86_64 -m 2G -smp 2 -enable-kvm       \
--            -drive file=system-base_1.0.0_amd64.img,if=virtio \
--            -serial mon:stdio
--
-- Login:   root (no password — first boot sets up via serial console)

return {
    ["system-base"] = image {
        name = "system-base",
        version = "1.0.0",

        -- Kernel with virtio modules for QEMU
        kernel = merge(pin("pc-kernel"), {
            params = {
                "quiet",
                "console=ttyS0,115200",
                "panic=-1",
                "net.ifnames=0",
            },
            modules = {
                "virtio", "virtio_balloon", "virtio_console",
                "virtio_net", "virtio_rng",
            },
        }),

        -- Bootloader (UEFI + systemd-boot)
        gadget = index("pc-gadget"),
        bootloader = { type = "systemd-boot", timeout = 1 },

        -- systemd provides init + udev + journald
        base = pin("systemd"),

        snaps = {
            pin("glibc"),     -- C runtime (everything links here)
            pin("bash"),       -- shell
            pin("coreutils"),  -- ls, cp, mv, cat, echo, printf...
            pin("shadow"),     -- login, useradd, passwd, su
            pin("linux-pam"),  -- PAM authentication
            pin("kmod"),       -- modprobe, lsmod, depmod
            pin("util-linux"), -- mount, reboot, dmesg, fdisk
            pin("procps"),     -- ps, kill, top, uptime, w
        },

        -- Minimal GPT disk: ESP (vfat) + root (ext4)
        disk = {
            label = "gpt",
            partitions = {
                { name = "esp", size = "256M", fs = "vfat", mount = "/boot" },
                { name = "root", size = "0", fs = "ext4", mount = "/",
                  options = { "noatime" } },
            },
        },

        sysctl = { "vm.swappiness=10", "kernel.kptr_restrict=2" },
    },
}
