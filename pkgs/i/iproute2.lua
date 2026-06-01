-- iproute2: IP routing and network device configuration tools
--
-- Source: https://mirrors.edge.kernel.org/pub/linux/utils/net/iproute2/
-- Provides ip, ss, tc, and other advanced networking utilities.

return {
    default = snap {
        name = "iproute2",
        version = "7.0.0",
        summary = "IP routing and network device configuration tools",
        description = [[
            iproute2 is a collection of userspace utilities for
            controlling TCP/IP networking and traffic control in Linux.
            It replaces the older net-tools package. Provides the ip
            command for network configuration, ss for socket statistics,
            tc for traffic control, and other networking utilities.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://mirrors.edge.kernel.org/pub/linux/utils/net/iproute2/iproute2-7.0.0.tar.xz",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
