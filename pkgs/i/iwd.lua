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
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://mirrors.edge.kernel.org/pub/linux/network/wireless/iwd-3.4.tar.xz",
        },
        -- Build via the autotools plugin (expands to exactly the original
        -- `./configure --prefix=/usr --sysconfdir=/etc && make && make
        -- install DESTDIR=$STAGE`, VPATH-style).
        parts = {
            daemon = {
                plugin = "autotools",
                options = { args = { "--sysconfdir=/etc" } },
            },
        },
        -- iwd is a long-running daemon managed by snapd.
        apps = {
            iwd = app {
                command = "usr/libexec/iwd",
                daemon = "simple",
                plugs = { "network-control" },
            },
        },
        -- iwd manages network interfaces directly (netlink + rfkill).
        plugs = {
            ["network-control"] = "network-control",
        },
        -- iwd persists network profiles under /var/lib/iwd, which a strict
        -- snap cannot write; bind it to snap data.
        layout = {
            ["/var/lib/iwd"] = { bind = "$SNAP_DATA/var/lib/iwd" },
        },
        -- Seed the state directory on install/config change.
        hooks = {
            configure = "pkgs/i/iwd-hooks/configure",
        },
    },
}
