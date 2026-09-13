-- Generation 2, BLESS VARIANT of the #80 sysupdate proof. Identical to
-- gen2.lua except the health gate passes (`/bin/true`): on its first boot
-- the counted UKI (+3-0, renamed +2-1 by the loader) reaches
-- boot-complete.target, systemd-bless-boot marks it good, and the counter
-- suffix is shed — the full Automatic Boot Assessment ceremony exercised
-- through a REAL update, on the UC22 chain where the bless-boot generator
-- ships (issue #85 tracks the core26 gap).
--
-- Served from the same payload URL as gen2 (same version 2.0) into a
-- FRESH copy of the gen-1 device: sysupdate sees 1.0 -> 2.0 exactly once,
-- the counted boot is asserted with `--expect-counter-seq 3-0`, and the
-- next boot's archived ESP listing shows the shed
-- `shuttle-80_2.0.efi` — blessing proven via the ESP.
--
-- Build: shuttle image --file gen2-bless.lua --arch amd64 --output "$OUT/gen2b"

return {
    rootfs = image {
        name = "shuttle-80",
        version = "2.0",

        base = index("core22"),

        kernel = merge(pin("pc-kernel"), {
            params = {
                "console=tty1",
                "console=ttyS0",
                "net.ifnames=0",
                "systemd.unified_cgroup_hierarchy=1",
                "systemd.wants=shuttle-80-proof.service",
                "systemd.wants=shuttle-80-poweroff.service",
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
        },

        bootloader = {
            type = "systemd-boot",
            timeout = 3,
        },

        disk = {
            label = "gpt",
            ab = true,
            partitions = {
                {
                    name = "esp",
                    size = "512M",
                    fs = "vfat",
                    mount = "/boot",
                },
                {
                    name = "root",
                    size = "3G",
                    fs = "ext4",
                    mount = "/",
                },
                {
                    -- The persistent state surface (ADR-0023): the update
                    -- gate fails closed without it (the store must survive
                    -- A/B flips).
                    name = "state",
                    size = "1G",
                    fs = "ext4",
                    mount = "/var/lib",
                    role = "state",
                },
            },
            swap = {
                size = "512M",
            },
        },

        update_source = "http://10.0.2.2:8123/",

        -- BLESS VARIANT: the gate passes, boot-complete.target is reached,
        -- the generation is marked good, the counter suffix is shed.
        boot_health_exec = "/bin/true",

        files = {
            { source = "proof/gen2/shuttle-80-proof.service", dest = "/etc/systemd/system/shuttle-80-proof.service" },
            { source = "proof/poweroff.service",              dest = "/etc/systemd/system/shuttle-80-poweroff.service" },
            { source = "proof/gen2/generation",               dest = "/etc/generation" },
        },
    },
}
