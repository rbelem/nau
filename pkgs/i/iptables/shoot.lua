-- iptables: IPv4/IPv6 packet filtering and NAT
--
-- Source: https://netfilter.org/projects/iptables/
-- Provides the iptables and nftables packet filtering framework.

return {
    default = snap {
        name = "iptables",
        version = "1.8",
        summary = "IPv4/IPv6 packet filtering and NAT",
        description = [[
            iptables is the userspace command-line program used to
            configure the Linux kernel firewall. It supports packet
            filtering, NAT (Network Address Translation), and packet
            mangling. Also includes nftables compatibility via
            iptables-nft and ip6tables.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        source = {
            url = "https://netfilter.org/projects/iptables/files/iptables-1.8.11.tar.xz",
        },
        build = "./configure --prefix=/usr --sysconfdir=/etc && make && make install DESTDIR=$STAGE",
    },
}
