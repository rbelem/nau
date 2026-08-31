-- pc-kernel: generic PC kernel snap
--
-- Linux kernel and modules for x86_64 Ubuntu Core devices.
-- Extracted into the image rootfs during image assembly (kernel
-- modules/firmware merged into /lib/modules and /lib/firmware).
--
-- Register in package index:
--   shuttle index add pc-kernel --summary "Generic PC kernel snap"
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
        name = "pc-kernel",
        version = "22.04",
        summary = "Generic PC kernel snap",
        description = [[
            Linux kernel and drivers for x86_64 Ubuntu Core systems.
            Provides kernel modules, firmware, and boot assets needed
            to boot an Ubuntu Core image on PC hardware.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        requires = { "glibc" },
    },
}
