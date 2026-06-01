-- store-snap: Pulling from the Snap Store
--
-- Demonstrates using `pin()` to reference snaps from the Snap Store.
-- The snap is downloaded, verified by sha3-384, and bundled into
-- an image. No source compilation needed — snaps come pre-built.
--
-- Usage:
--   shoot image --file examples/full-system/store-snap/shoot.lua
--   → produces store-snap_1.0.0_amd64.img
--
--   shoot image --file examples/full-system/store-snap/shoot.lua --channel latest/edge
--   → use edge channel instead of stable

return {
    ["store-snap"] = image {
        name = "store-snap",
        version = "1.0.0",
        summary = "Demonstrates pulling pre-built snaps from Snap Store",
        description = [[
            This image uses only store-pinned snaps — no source
            compilation required. The base (core22), kernel (pc-kernel),
            and gadget (pc-gadget) snaps are all downloaded directly
            from the Snap Store.

            Use `pin()` with optional revision and sha3_384 for
            reproducible builds. Without pins, the latest revision
            in the channel is used.

            Interesting snap names to try:
              - lxd: system container manager
              - snapd: snap daemon
              - hello: GNU hello world (store version)
        ]],

        -- Base: core22 from Snap Store (unpinned — latest stable)
        base = pin("core22"),

        -- Kernel: pc-kernel from Snap Store
        kernel = merge(pin("pc-kernel"), {
            params = { "quiet", "console=ttyS0", "panic=-1" },
        }),

        -- Gadget: pc-gadget for UEFI boot
        gadget = pin("pc-gadget"),
        bootloader = { type = "systemd-boot", timeout = 2 },

        -- Extra snaps from the store
        snaps = {
            pin("lxd"),
        },

        -- GPT disk layout
        disk = {
            label = "gpt",
            partitions = {
                { name = "esp", size = "256M", fs = "vfat", mount = "/boot" },
                { name = "root", size = "0", fs = "ext4", mount = "/",
                  options = { "noatime" } },
            },
        },
    },
}
