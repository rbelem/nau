-- nvme-cli: NVMe management command-line interface
--
-- Source: https://github.com/linux-nvme/nvme-cli
-- Provides the nvme tool for managing NVMe storage devices.

return {
    default = snap {
        name = "nvme-cli",
        version = "2.11",
        summary = "NVMe management command-line interface",
        description = [[
            nvme-cli provides a command-line interface for managing NVMe
            (Non-Volatile Memory Express) storage devices. Supports
            device identification, health monitoring, firmware management,
            namespace management, and performance testing. Essential for
            managing modern NVMe SSDs and enterprise storage.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        source = {
            url = "https://github.com/linux-nvme/nvme-cli/archive/refs/tags/v2.11.tar.gz",
        },
        build = "meson setup build --prefix=/usr && ninja -C build && DESTDIR=$STAGE ninja -C build install",
    },
}
