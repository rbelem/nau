-- Generation 2 of the #80 sysupdate proof — the UPDATE PAYLOAD (core22
-- chain). This file is BOTH a payload build and a bootable image: the
-- artifacts `prepare.sh` extracts from its slot A (root.img, verity-hash
-- partition, UKI) are exactly what the payload server publishes, and the
-- slot A of THIS image carries the same generation-derived PARTUUIDs the
-- emitted transfers pin via `@u` — one UKI boots both.
--
-- Genuinely different from gen1 (issue #80's bar): a different version
-- (2.0), a different proof unit payload, a different /etc/generation —
-- so the ext4 root, its dm-verity roothash, and both derived partition
-- GUIDs all differ. Observable in the boot: the proof unit's
-- Description says generation 2, and the ESP gains
-- shuttle-80_2.0+3-0.efi with the tries suffix sysupdate wrote.
--
-- This variant FAILS the health gate (`/bin/false`): the counted UKI is
-- never blessed, so the counters freeze in place and `shuttle test
-- --runs 2 --expect-counter-seq 3-0,2-1` can machine-assert the loader's
-- +3-0 -> +2-1 bump. The bless/clear ceremony is gen2-bless.lua's job.
--
-- Build: shuttle image --file gen2.lua --arch amd64 --output "$OUT/gen2"

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
                -- The payload boots do NOT re-run the update (the guest
                -- has no sysupdate binary; gen1's wants list is
                -- deliberately not inherited here) — only the proof and
                -- poweroff oneshots.
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

        -- The payload's transfers point at the same server (both slots of
        -- every generation carry the transfer files), but nothing on a
        -- gen-2 boot pulls the update unit, so no fetch happens.
        update_source = "http://10.0.2.2:8123/",

        -- COUNTING OBSERVATION VARIANT: fail the gate so boot-complete
        -- is never reached, systemd-bless-boot never marks the generation
        -- good, and the counted filename keeps its +N-M suffix for the
        -- `--expect-counter-seq 3-0,2-1` assertion.
        boot_health_exec = "/bin/false",

        files = {
            { source = "proof/gen2/shuttle-80-proof.service", dest = "/etc/systemd/system/shuttle-80-proof.service" },
            { source = "proof/poweroff.service",              dest = "/etc/systemd/system/shuttle-80-poweroff.service" },
            { source = "proof/gen2/generation",               dest = "/etc/generation" },
        },
    },
}
