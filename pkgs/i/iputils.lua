-- iputils: Network utilities (ping, traceroute, etc.)
--
-- Source: https://github.com/iputils/iputils
-- Provides ping, tracepath, and other network diagnostic tools.

return {
    default = snap {
        name = "iputils",
        version = "2025",
        summary = "Network monitoring tools including ping and tracepath",
        description = [[
            iputils provides a set of small useful utilities for Linux
            networking. Includes ping for testing network connectivity,
            tracepath for tracing the route to a network host, clockdiff
            for measuring clock differences between hosts, and arping for
            sending ARP requests to neighbors on the local network.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://github.com/iputils/iputils/archive/refs/tags/20250605.tar.gz",
        },
        build = "meson setup build --prefix=/usr && ninja -C build && DESTDIR=$STAGE ninja -C build install",
    },
}
