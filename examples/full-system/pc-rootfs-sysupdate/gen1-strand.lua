-- #86 strand CONTROL device: gen1 with the #86 recovery oneshot masked
-- out (systemd.mask=), reproducing the pre-#86 behavior. The strand is
-- created here (throttled payload server + a mid-transfer death) and the
-- re-run update is observed WITHOUT recovery; gen1.lua (recovery active)
-- is the paired treatment device.
--
-- The factory device: an A/B disk whose slot B ships DPS-`_empty`-labeled,
-- the sysupdate transfer files pointed at a payload server on the QEMU
-- host (SLIRP alias 10.0.2.2), and the emitted `systemd-sysupdate.service`
-- pulled into the FIRST boot transaction via the `systemd.wants=` kernel
-- parameter — so the device takes a real url-file update on boot #1.
--
-- The `files` entries stage the systemd-sysupdate tooling the base rootfs
-- does not ship (see prepare.sh: the host's systemd 261 binary plus its
-- nix ld.so/libc/libsystemd-shared closure, staged verbatim at their
-- absolute /nix/store paths — the library needs glibc >= 2.36 for
-- GLIBC_ABI_GNU2_TLS, so it cannot run against the guest's 2.35 libc)
-- plus the per-generation proof oneshots:
--   - shuttle-80-proof.service  echoes its generation into the boot
--     transaction (serial-observable payload identity), and
--   - shuttle-80-poweroff.service ends the boot cleanly once the evidence
--     (update finished, completion targets reached) is on the console.
--
-- Build (from this directory, after prepare.sh):
--   shuttle image --file gen1-strand.lua --arch amd64 --output "$OUT/gen1-strand"
--
-- Boot proof (README "#86"): strand boot = throttled payload server +
-- a mid-transfer death; re-run boot = unthrottled server, recovery
-- masked — the native post-strand behavior this ticket fixes.

return {
    rootfs = image {
        name = "shuttle-80",
        version = "1.0",

        base = index("core22"),

        kernel = merge(pin("pc-kernel"), {
            params = {
                -- tty1 is the local console; ttyS0 mirrors the boot to the
                -- serial port so `shuttle test` can observe userspace.
                "console=tty1",
                "console=ttyS0",
                "net.ifnames=0",
                "systemd.unified_cgroup_hierarchy=1",
                -- #80 proof triggers, pulled into the default.target
                -- transaction: the emitted sysupdate unit runs the real
                -- url-file A/B install on the first boot.
                "systemd.wants=systemd-sysupdate.service",
                -- #86 control: mask the recovery oneshot so this device
                -- behaves exactly like a pre-#86 image (no reclaim).
                "systemd.mask=shuttle-slot-recovery.service",
                "systemd.wants=shuttle-80-debug-list.service",
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
            -- A/B slots: slot A boots the factory generation; slot B ships
            -- labeled `_empty` so the first update has a writable slot.
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

        -- ADR-0011 step (d): the payload server the guest fetches from.
        -- 10.0.2.2 is QEMU SLIRP's alias for the host's loopback, where
        -- serve-payload.py publishes the generation-2 artifacts.
        update_source = "http://10.0.2.2:8123/",

        -- The try-boot health gate under test is the CEREMONY itself
        -- (counters, boot-complete.target, bless), not the shipped
        -- /usr/bin/shuttle probe — pin the trivially-true gate so a
        -- generation change is the only variable (#78's escape hatch).
        boot_health_exec = "/bin/true",

        files = {
            -- systemd-sysupdate tooling the base rootfs lacks (prepare.sh
            -- copies these from the host's systemd 261). The library needs
            -- GLIBC_ABI_GNU2_TLS (glibc >= 2.36), so the nix closure ships
            -- VERBATIM at its absolute /nix/store paths — the binary's
            -- PT_INTERP and RUNPATH resolve inside the staged tree, using
            -- nothing from the guest. On a different build host, regenerate
            -- local/nix/ AND these dest paths via prepare.sh.
            { source = "local/nix/systemd-sysupdate",        dest = "/usr/bin/systemd-sysupdate" },
            { source = "local/nix/libsystemd-shared-261.so", dest = "/nix/store/sm8d6jpilwdy3bw3yq2lv8rr8jld26pb-systemd-261.2/lib/systemd/libsystemd-shared-261.so" },
            -- The url-file download worker: http-fetch (tools/), a
            -- minimal stand-in for systemd-pull (see prepare.sh).
            { source = "local/nix/systemd-pull",             dest = "/usr/lib/systemd/systemd-pull" },
            -- systemd-sysupdate spawns the worker from ITS OWN compiled
            -- libdir (the nix store path baked into this build), so the
            -- same bytes must also appear there.
            { source = "local/nix/systemd-pull",             dest = "/nix/store/sm8d6jpilwdy3bw3yq2lv8rr8jld26pb-systemd-261.2/lib/systemd/systemd-pull" },
            -- libcurl + its dependency closure, for systemd-pull's
            -- runtime dlopen. RUNPATHs are rewritten to the flat
            -- /usr/lib/systemd/curl-libs directory (prepare.sh).
            { source = "local/nix/libc.so.6",                dest = "/nix/store/n51dhmdbik1kfrsm62j5knavmigwrl1a-glibc-2.42-84/lib/libc.so.6" },
            { source = "local/nix/ld-linux-x86-64.so.2",     dest = "/nix/store/n51dhmdbik1kfrsm62j5knavmigwrl1a-glibc-2.42-84/lib/ld-linux-x86-64.so.2" },
            -- systemd-pull's PT_INTERP uses the lib64 spelling.
            { source = "local/nix/ld-linux-x86-64.so.2",     dest = "/nix/store/n51dhmdbik1kfrsm62j5knavmigwrl1a-glibc-2.42-84/lib64/ld-linux-x86-64.so.2" },
            { source = "local/nix/libpthread.so.0",          dest = "/nix/store/n51dhmdbik1kfrsm62j5knavmigwrl1a-glibc-2.42-84/lib/libpthread.so.0" },
            { source = "local/nix/libdl.so.2",               dest = "/nix/store/n51dhmdbik1kfrsm62j5knavmigwrl1a-glibc-2.42-84/lib/libdl.so.2" },
            { source = "local/nix/librt.so.1",               dest = "/nix/store/n51dhmdbik1kfrsm62j5knavmigwrl1a-glibc-2.42-84/lib/librt.so.1" },
            { source = "local/nix/libblkid.so.1",            dest = "/nix/store/17xmg38m60inc59az3frp540ccrwn2r8-util-linux-minimal-2.42.2-lib/lib/libblkid.so.1" },
            { source = "local/nix/libfdisk.so.1",            dest = "/nix/store/17xmg38m60inc59az3frp540ccrwn2r8-util-linux-minimal-2.42.2-lib/lib/libfdisk.so.1" },
            { source = "local/nix/libmount.so.1",            dest = "/nix/store/17xmg38m60inc59az3frp540ccrwn2r8-util-linux-minimal-2.42.2-lib/lib/libmount.so.1" },
            { source = "local/nix/libsmartcols.so.1",        dest = "/nix/store/17xmg38m60inc59az3frp540ccrwn2r8-util-linux-minimal-2.42.2-lib/lib/libsmartcols.so.1" },
            { source = "local/nix/libuuid.so.1",             dest = "/nix/store/17xmg38m60inc59az3frp540ccrwn2r8-util-linux-minimal-2.42.2-lib/lib/libuuid.so.1" },
            -- #86 proof-only: a GUEST-RUNNABLE /usr/bin/shuttle. The
            -- build-host embed (#81) needs glibc >= 2.38; the core22
            -- guest ships 2.35, so `runtime activate` and `runtime
            -- recover-slots` could not exec at all (measured: "GLIBC_2.39
            -- not found", in both #80's and #86's serial logs). This copy
            -- is the same build with RUNPATH into the nix glibc/gcc dirs
            -- — of which this file list already stages the loader and
            -- libc for the sysupdate tooling — plus libstdc++, libgcc_s
            -- and libm staged at their absolute store paths. Product
            -- images keep the #81 embed; this is harness plumbing,
            -- exactly like the sysupdate tooling above.
            { source = "local/nix/shuttle-guest",            dest = "/usr/bin/shuttle" },
            { source = "local/nix/libstdcpp.so.6",           dest = "/nix/store/chqq8mpmpyfi9kgsngya71akv5xicn03-gcc-15.2.0-lib/lib/libstdc++.so.6" },
            { source = "local/nix/libgcc_s.so.1",            dest = "/nix/store/chqq8mpmpyfi9kgsngya71akv5xicn03-gcc-15.2.0-lib/lib/libgcc_s.so.1" },
            { source = "local/nix/libm.so.6",                dest = "/nix/store/n51dhmdbik1kfrsm62j5knavmigwrl1a-glibc-2.42-84/lib/libm.so.6" },
            -- Per-generation payload proof + clean end of boot.
            { source = "proof/gen1/shuttle-80-proof.service", dest = "/etc/systemd/system/shuttle-80-proof.service" },
            { source = "proof/poweroff.service",              dest = "/etc/systemd/system/shuttle-80-poweroff.service" },
            -- Diagnostic: mirror the journal to the serial console so a
            -- failed update unit shows its actual error output.
            { source = "proof/journald/80-forward.conf",      dest = "/etc/systemd/journald.conf.d/80-forward.conf" },
            { source = "proof/sysupdate-dropin/10-console.conf", dest = "/etc/systemd/system/systemd-sysupdate.service.d/10-console.conf" },
            { source = "proof/sysupdate-dropin/debug-list.service", dest = "/etc/systemd/system/shuttle-80-debug-list.service" },
            { source = "proof/sysupdate-dropin/diag.sh", dest = "/usr/libexec/shuttle-80/diag.sh" },
            -- Host-side post-mortem: debugfs this out of each slot to prove
            -- the two slots carry different generations.
            { source = "proof/gen1/generation",               dest = "/etc/generation" },
        },
    },
}
