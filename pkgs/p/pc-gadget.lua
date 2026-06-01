-- pc-gadget: gadget snap for generic PC hardware
--
-- Provides bootloader config (grub), model assertion, and
-- hardware-specific configuration for x86_64 Ubuntu Core devices.
--
-- Register in package index:
--   shoot index add pc-gadget --summary "PC gadget snap"
--
-- Usage:
--   image {
--       name = "my-system",
--       version = "1.0.0",
--       base = index("core22"),
--       kernel = index("pc-kernel"),
--       gadget = index("pc-gadget"),
--   }

return {
    default = snap {
        name = "pc-gadget",
        version = "22.04",
        summary = "Gadget snap for generic PC hardware",
        description = [[
            The pc-gadget snap provides boot configuration for x86_64
            Ubuntu Core images: GRUB bootloader config, gadget YAML,
            and model assertions for device identity.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        requires = { "glibc" },
    },
}
