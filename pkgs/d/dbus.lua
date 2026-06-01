-- dbus: D-Bus message bus daemon and utilities
--
-- Source: https://gitlab.freedesktop.org/dbus/dbus
-- Provides the D-Bus inter-process communication system.

return {
    default = snap {
        name = "dbus",
        version = "1.16",
        summary = "D-Bus message bus daemon and utilities",
        description = [[
            D-Bus is a message bus system, a simple way for applications to
            talk to one another. In addition to interprocess communication,
            D-Bus helps coordinate process lifecycle and provides a uniform
            mechanism for launching services.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://gitlab.freedesktop.org/dbus/dbus/-/archive/v1.16.2/dbus-v1.16.2.tar.gz",
        },
        build = "./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var && make && make install DESTDIR=$STAGE",
    },
}
