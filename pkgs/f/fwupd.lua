-- fwupd: Firmware update daemon
--
-- Source: https://github.com/fwupd/fwupd
-- Provides tools for updating device firmware on Linux.

return {
    default = snap {
        name = "fwupd",
        version = "2.0",
        summary = "Firmware update daemon",
        description = [[
            fwupd is a daemon that allows session software to update
            device firmware. It supports UEFI firmware updates, USB
            device firmware, Thunderbolt controllers, and many other
            device types. Provides fwupdmgr for managing firmware
            updates and fwupdtool for low-level operations.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://github.com/fwupd/fwupd/archive/refs/tags/2.0.6.tar.gz",
        },
        build = "meson setup build --prefix=/usr -Ddocs=disabled && ninja -C build && DESTDIR=$STAGE ninja -C build install",
    },
}
