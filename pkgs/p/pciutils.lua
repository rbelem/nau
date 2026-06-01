-- pciutils: PCI bus utilities
--
-- Source: https://mirrors.edge.kernel.org/pub/software/utils/pciutils/
-- Provides lspci, setpci, and the PCI device database.

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
        source = {
            url = "https://mirrors.edge.kernel.org/pub/software/utils/pciutils/pciutils-3.13.0.tar.xz",
        },
        build = "make PREFIX=/usr DESTDIR=$STAGE install",
    },
}
