-- Minimal rootfs image for QEMU/KVM (issue #74 sanity chain)
--
-- The original draft of this example declared every member as a local
-- shuttle-built package (`base = pin("systemd")`, `pin("glibc")`,
-- `pin("bash")`, …). Image builds resolve EVERY reference through the Snap
-- Store, and none of those names exist in series 16 (verified against the
-- store API, 2026-09-13) — the example could not build at all. It now
-- composes the same minimal QEMU intent from real store snaps, exactly
-- like the pc-rootfs example but smaller.
--
-- Compose a bootable disk image with:
--   - core22 base rootfs
--   - pc-kernel with serial-console boot params (the #70 payload:
--     a prebuilt kernel.efi UKI, split and re-assembled by shuttle)
--   - pc-gadget
--   - snapd
--   - GPT disk: ESP (vfat) + root (ext4)
--   - systemd-boot bootloader
--
-- Build:
--   shuttle image --file examples/full-system/system-base/shuttle.lua --arch amd64
--
-- Boot:
--   qemu-system-x86_64 -m 2G -smp 2 -enable-kvm        \
--     -drive file=system-base_1.0.0_amd64.img,if=virtio \
--     -serial mon:stdio

return {
    ["system-base"] = image {
        name = "system-base",
        version = "1.0.0",

        base = index("core22"),

        -- Kernel with virtio support for QEMU. Module names verified
        -- against the REAL pc-kernel 22/stable modules.dep (rev 3654,
        -- 5.15.0-186-generic, issue #74): virtio, virtio_pci,
        -- virtio_balloon and virtio_console are BUILT INTO that kernel
        -- (no .ko in modules.dep), so declaring them as modules would
        -- document a falsehood; virtio_blk, virtio_net and virtio_rng
        -- ship as modules and are the ones the initramfs would need.
        kernel = merge(pin("pc-kernel"), {
            params = {
                "quiet",
                "console=ttyS0,115200",
                "panic=-1",
                "net.ifnames=0",
            },
            modules = {
                "virtio_blk", "virtio_net", "virtio_rng",
            },
        }),

        gadget = index("pc-gadget"),

        snaps = {
            index("snapd"),
        },

        -- Bootloader (UEFI + systemd-boot)
        bootloader = { type = "systemd-boot", timeout = 1 },

        -- Minimal GPT disk: ESP (vfat) + root (ext4)
        disk = {
            label = "gpt",
            partitions = {
                { name = "esp", size = "256M", fs = "vfat", mount = "/boot" },
                { name = "root", size = "2G", fs = "ext4", mount = "/",
                  options = { "noatime" } },
            },
        },

        sysctl = { "vm.swappiness=10", "kernel.kptr_restrict=2" },
    },
}
