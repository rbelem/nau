-- pc-gadget: gadget snap for generic PC hardware
--
-- Provides bootloader config (grub), model assertion, and
-- hardware-specific configuration for x86_64 Ubuntu Core devices.
--
-- Register in package index:
--   shuttle index add pc-gadget --store-name pc --summary "PC gadget snap"
--
-- The --store-name is required (issue #68): the store has no snap named
-- 'pc-gadget' — the generic-PC gadget snap is named 'pc'. Without the
-- alias, resolution queries the store for a snap that does not exist and
-- every image build with gadget = index("pc-gadget") fails.
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
