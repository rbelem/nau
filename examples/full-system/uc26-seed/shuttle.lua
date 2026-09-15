-- Ubuntu Core 26 gadget-proper boot image for x86_64 PC hardware (#28)
--
-- The #32 chain: a UC-layout disk whose first boot is the snapd-driven
-- seed — GRUB (the pc gadget's own shim + grub + snapd's first-boot
-- config on ubuntu-seed), snap-bootstrap install mode, modeenv/boot
-- variables managed by snapd on ubuntu-boot — instead of the minimal
-- systemd-boot UKI ESP the other examples boot. The rootfs is NOT
-- painted: the base rootfs comes from the core26 snap via the seed
-- unpack, which is the point of the proof.
--
-- Layout mirrors the pc gadget's gadget.yaml (rev 227, 26/stable):
--   BIOS Boot   1M   (gap partition — present for gadget validation)
--   ubuntu-seed 2G   vfat, role system-seed — ALSO the ESP (gadget content
--                     + seed + recovery systems); GPT esp flag set here
--   ubuntu-boot 750M ext4, role system-boot — modeenv + run boot assets
--   ubuntu-save 32M  ext4, role system-save
--   ubuntu-data 2G   ext4, role system-data — snap-bootstrap seeds it
--
-- Build:
--   shuttle image --file examples/full-system/uc26-seed/shuttle.lua \
--       --arch amd64 --output ~/.cache/shuttle-uc26
--
-- Boot proof (#28 bar: snapd userspace, serial archived):
--   shuttle test ~/.cache/shuttle-uc26/ubuntu-core-uc26-seed_26.04_amd64.img \
--       --runs 2 --require "snapd_recovery_mode=install" \
--       --require "Reached target Basic System"
--
-- First boot: grub defaults snapd_recovery_mode=install (no seed grubenv
-- mode), loopback-mounts the recovery system's kernel.efi, and chainloads
-- it with snapd_recovery_mode=install snapd_recovery_system=<label>; the
-- initrd's snap-bootstrap loads the signed model + seed, seeds
-- ubuntu-data, writes modeenv, reboots. Second boot: run mode, snapd
-- userspace. kernel params land in the per-system grubenv
-- (snapd_extra_cmdline_args) so ttyS0 carries both phases.

return {
    rootfs = image {
        name = "ubuntu-core-uc26-seed",
        version = "26.04",

        base = index("core26"),

        -- Store names; ADR-0019 derives 26/stable from the core26 base:
        -- pc-kernel 3699 (7.0 kernel, virtio + dm-verity initrd) and the
        -- pc gadget 227 per the package-index pins (issue #69 base-aware
        -- resolution). The params land in the recovery system's grubenv
        -- (snapd_extra_cmdline_args): snapd propagates them to the run
        -- system at install, so ttyS0 carries BOTH boot phases' serial
        -- evidence (#28).
        kernel = merge(pin("pc-kernel"), {
            params = {
                "console=tty1",
                "console=ttyS0",
            },
        }),
        gadget = index("pc-gadget"),

        -- snapd is essential on UC20+; network-manager for the seeded
        -- system's network (console-conf asks for it).
        snaps = {
            index("snapd"),
            index("network-manager"),
        },

        disk = {
            label = "gpt",
            partitions = {
                {
                    -- Gadget validation wants the pc gadget's structures
                    -- present; the build leaves this one unformatted
                    -- (role = "gap": exists, never mounted or populated).
                    name = "BIOS Boot",
                    size = "1M",
                    fs = "ext4",
                    role = "gap",
                },
                {
                    -- The seed IS the ESP for the pc gadget (ESP type GUID
                    -- set by the build): gadget EFI assets + seed + the
                    -- recovery system.
                    name = "ubuntu-seed",
                    size = "2G",
                    fs = "vfat",
                    role = "system-seed",
                },
                {
                    name = "ubuntu-boot",
                    size = "750M",
                    fs = "ext4",
                    role = "system-boot",
                },
                {
                    name = "ubuntu-save",
                    size = "32M",
                    fs = "ext4",
                    role = "system-save",
                },
                {
                    name = "ubuntu-data",
                    -- snap-bootstrap grows the data writable over the
                    -- remaining device at install; the declared size is
                    -- the day-one footprint.
                    size = "2G",
                    fs = "ext4",
                    role = "system-data",
                },
            },
        },

        -- No bootloader block: the pc gadget ships the chain (shim + grub
        -- + snapd's managed configs). `bootloader.type = "grub"` stays a
        -- declaration error (#71) — nothing here is shuttle-managed.
    },
}
