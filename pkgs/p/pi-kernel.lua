-- pi-kernel: Raspberry Pi kernel snap
--
-- Linux kernel and modules for ARM64 Raspberry Pi devices.
-- Companion to pi-gadget for Raspberry Pi Ubuntu Core images.
--
-- Register in package index:
--   shoot index add pi-kernel --summary "Raspberry Pi kernel snap"
--
-- Usage:
--   image {
--       name = "pi-system",
--       version = "1.0.0",
--       base = index("core22"),
--       kernel = index("pi-kernel"),
--       gadget = index("pi-gadget"),
--   }

return {
    default = snap {
        name = "pi-kernel",
        version = "22.04",
        summary = "Raspberry Pi kernel snap",
        description = [[
            Linux kernel and drivers for Raspberry Pi single-board
            computers (Pi 3, Pi 4, Pi 5). Provides kernel modules,
            firmware, and Device Tree blobs for Raspberry Pi hardware.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "arm64", "armhf" },
    },
}
