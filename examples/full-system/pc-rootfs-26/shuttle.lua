-- Ubuntu Core 26 rootfs image for x86_64 PC hardware (#28 chain)
--
-- The core26 sibling of examples/full-system/pc-rootfs: same ADR-0019
-- base-aware snap chain, same proven boot shape, plus the ADR-0023/0024
-- update machinery:
--   - core26 base rootfs (kernel/gadget resolve from the 26/stable track)
--   - pc-kernel 26/stable + pc gadget (store names; see issue #68)
--   - snapd + network-manager + lxd
--   - GPT disk: ESP (vfat) + A/B roots (ext4, dm-verity) + state + swap
--   - systemd-boot bootloader
--   - disk.ab + update_source → sysupdate transfer files, the try-boot
--     counters, and boot-complete.target gated by the #78 health override
--   - role = "state" partition → the persistent state surface (ADR-0023)
--
-- Build:
--   shuttle image --file examples/full-system/pc-rootfs-26/shuttle.lua \
--       --arch amd64 --output ~/.cache/shuttle-core26
--
-- Boot proof (#63 harness, #28 bar):
--   shuttle test ~/.cache/shuttle-core26/ubuntu-core-pc-26_26.04_amd64.img \
--       --runs 1 --require "Reached target multi-user.target"
--
-- (The factory UKI is installed counterless, so boot-complete.target is not
-- pulled into the first transaction — the factory boot completes through
-- default.target; see the #84 completion-gate notes in src/boot_test.rs.)
--
-- Requires:
--   package-index.json with resolved pins (shuttle index resolve \
--       --base core22 --base core26)
--   a signing key for update_source (shuttle key keygen)
--   parted, losetup, mkfs.vfat, mkfs.ext4, dd on PATH

return {
    rootfs = image {
        name = "ubuntu-core-pc-26",
        version = "26.04",

        base = index("core26"),

        -- The store snap is 'pc-kernel' on BOTH chains; ADR-0019 derives
        -- 26/stable from the core26 base (the 22/stable and 26/stable
        -- channel maps carry different, incompatible payloads — issue #69
        -- is why resolve bakes per-channel pins instead of one).
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
            -- A/B slots (ADR-0011 step (d)): the root is cloned into a
            -- second slot and sysupdate flips between them. Without
            -- update_source the transfer files are skipped (a local-source
            -- transfer would carry no verification).
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
                    -- ext4: the unprivileged file-based build populates with
                    -- `mkfs.ext4 -d` (see the core22 sibling for the full
                    -- rationale). A/B clones this partition into slot B.
                    size = "3G",
                    fs = "ext4",
                    mount = "/",
                    options = {
                        "noatime",
                    },
                },
                {
                    -- The persistent state surface (ADR-0023): mounts at
                    -- /var/lib, survives A/B flips, never verity-hashed.
                    -- Sized once — partition layouts are hard to change
                    -- after deploy.
                    name = "state",
                    size = "1G",
                    fs = "ext4",
                    mount = "/var/lib",
                    role = "state",
                },
            },
            -- Trimmed vs the core22 sibling: an A/B disk already carries
            -- two roots, and the QEMU proof values a small image.
            swap = {
                size = "2G",
            },
        },

        -- ADR-0011 step (d): base URL of the sysupdate payload source.
        -- Declaring it emits the transfer files + trigger units and the
        -- boot-complete.target machinery; it requires a signing key at
        -- build time (the build never mints one).
        update_source = "https://updates.example.com/shuttle/ubuntu-core-pc-26/",

        -- #78 health override: the generated boot-health gate defaults to
        -- `shuttle runtime activate`, which needs the shuttle binary inside
        -- the guest. An example image ships no such binary, so the gate is
        -- satisfied with a trivially-successful exec; a real deployment
        -- replaces this with its own health check (or ships shuttle and
        -- drops the override).
        boot_health_exec = "/bin/true",

        sysctl = {
            "vm.swappiness=100",
            "kernel.kptr_restrict=2",
            "kernel.dmesg_restrict=1",
            "net.ipv4.conf.all.rp_filter=1",
            "net.ipv4.tcp_syncookies=1",
        },
    },
}
