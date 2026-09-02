-- dhcpcd: DHCP client daemon
--
-- Source: https://roy.marples.name/projects/dhcpcd/
-- Provides automatic IPv4 and IPv6 network configuration via DHCP.
-- Lightweight alternative to dhclient/NetworkManager for minimal systems.
--
-- Built via the autotools plugin in-source (dhcpcd ships a non-autoconf
-- configure script that writes its Makefile into the source dir, which
-- breaks the plugin's default VPATH layout — dogfood round 1 friction).

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
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://github.com/NetworkConfiguration/dhcpcd/releases/download/v10.1.0/dhcpcd-10.1.0.tar.xz",
        },
        parts = {
            dhcpcd = {
                plugin = "autotools",
                options = {
                    in_source = true,
                    args = { "--sysconfdir=/etc", "--rundir=/run", "--dbdir=/var/lib/dhcpcd" },
                },
            },
        },
    },
}
