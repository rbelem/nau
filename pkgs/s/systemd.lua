-- systemd: system and service manager for Linux
--
-- Source: https://github.com/systemd/systemd
-- Provides the systemd init system, service manager, and related utilities.

return {
    default = snap {
        name = "systemd",
        version = "260.2",
        summary = "System and service manager for Linux",
        description = [[
            systemd is a suite of basic building blocks for a Linux system.
            It provides a system and service manager that runs as PID 1 and
            starts the rest of the system. Includes journald, logind, networkd,
            resolved, and other core system daemons.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc", "libcap" },
        source = {
            url = "https://github.com/systemd/systemd/archive/v260.2.tar.gz",
        },
        build = "meson setup build --prefix=/usr -Dmode=release && ninja -C build && DESTDIR=$STAGE ninja -C build install",
    },
}
