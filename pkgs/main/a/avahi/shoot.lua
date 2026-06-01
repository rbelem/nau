-- avahi: mDNS/DNS-SD service discovery daemon
--
-- Source: https://www.avahi.org/
-- Provides zero-configuration service discovery on local networks.
-- Apple Bonjour / Zeroconf compatible.

return {
    default = snap {
        name = "avahi",
        version = "0.8",
        summary = "mDNS/DNS-SD service discovery daemon",
        description = [[
            Avahi is a system which facilitates service discovery on a local
            network via mDNS/DNS-SD. It allows programs to publish and
            discover services and hosts running on a local network with no
            specific configuration. Compatible with Apple Bonjour.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        source = {
            url = "https://github.com/lathiat/avahi/archive/refs/tags/v0.8.tar.gz",
        },
        build = "autoreconf -fi && ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --disable-gtk --disable-qt5 && make && make install DESTDIR=$STAGE",
    },
}
