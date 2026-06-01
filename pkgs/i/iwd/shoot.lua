-- iwd: iNet Wireless Daemon
--
-- Source: https://mirrors.edge.kernel.org/pub/linux/network/wireless/
-- Provides a lightweight Wi-Fi management daemon.

return {
    default = snap {
        name = "iwd",
        version = "3.4",
        summary = "iNet Wireless Daemon",
        description = [[
            iwd (iNet Wireless Daemon) is a wireless daemon for Linux
            that aims to replace wpa_supplicant. It provides a minimal
            and secure Wi-Fi management solution with support for WPA/WPA2/WPA3
            personal and enterprise modes, EAP methods, and station/AP/P2P
            modes.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        source = {
            url = "https://mirrors.edge.kernel.org/pub/linux/network/wireless/iwd-3.4.tar.xz",
        },
        build = "./configure --prefix=/usr --sysconfdir=/etc && make && make install DESTDIR=$STAGE",
    },
}
