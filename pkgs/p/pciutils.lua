-- pciutils: PCI bus utilities
--
-- Source: https://mirrors.edge.kernel.org/pub/software/utils/pciutils/
-- Provides lspci, setpci, and the PCI device database.
--
-- Built via the make plugin: pciutils is non-autoconf, and PREFIX must be
-- given at build time too (it bakes runtime paths into the binaries) — the
-- `variables` map applies PREFIX=/usr to both commands, fixing the
-- usr/local leakage observed in dogfood round 1.

return {
    default = snap {
        name = "pciutils",
        version = "3.13",
        summary = "PCI bus utilities",
        description = [[
            pciutils contains utilities for inspecting and manipulating
            configuration of PCI devices. Includes lspci for listing PCI
            devices, setpci for configuring PCI registers, and update-pciids
            for updating the PCI device ID database. Also provides the
            libpci shared library.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://mirrors.edge.kernel.org/pub/software/utils/pciutils/pciutils-3.13.0.tar.xz",
        },
        parts = {
            pciutils = {
                plugin = "make",
                options = { variables = { PREFIX = "/usr" } },
            },
        },
    },
}
