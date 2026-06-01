-- pi-gadget: gadget snap for Raspberry Pi hardware
--
-- Provides bootloader config (u-boot), model assertion,
-- and hardware configuration for Raspberry Pi Ubuntu Core devices.
--
-- Register in package index:
--   shoot index add pi-gadget --summary "Raspberry Pi gadget snap"
--
-- Usage:
--   image {
--       name = "pi-system",
--       version = "1.0.0",
--       base = index("core22"),
--       kernel = index("pi-kernel"),
--       gadget = index("pi-gadget"),
--       snaps = { index("snapd") },
--   }

return {
    default = snap {
        name = "pi-gadget",
        version = "22.04",
        summary = "Gadget snap for Raspberry Pi hardware",
        description = [[
            The pi-gadget snap provides boot configuration for Raspberry Pi
            Ubuntu Core images: u-boot bootloader config, gadget YAML,
            and model assertions for Pi 3, Pi 4, and Pi 5 hardware.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "arm64", "armhf" },
    },
}
