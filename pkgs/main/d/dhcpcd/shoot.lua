-- dhcpcd: DHCP client daemon
--
-- Source: https://roy.marples.name/projects/dhcpcd/
-- Provides automatic IPv4 and IPv6 network configuration via DHCP.
-- Lightweight alternative to dhclient/NetworkManager for minimal systems.

return {
    default = snap {
        name = "dhcpcd",
        version = "10.1",
        summary = "DHCP client daemon",
        description = [[
            dhcpcd is a DHCP and DHCPv6 client. It is also an IPv4LL
            (IPV4 Link-Local Addressing) and IPv6RA (IPv6 Router Advertisement)
            client. Runs as a standalone daemon for automatic network
            configuration on wired and wireless interfaces.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        source = {
            url = "https://github.com/NetworkConfiguration/dhcpcd/releases/download/v10.1.0/dhcpcd-10.1.0.tar.xz",
        },
        build = "./configure --prefix=/usr --sysconfdir=/etc --rundir=/run --dbdir=/var/lib/dhcpcd && make && make install DESTDIR=$STAGE",
    },
}
