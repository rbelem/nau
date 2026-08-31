-- network-manager: network management daemon
--
-- NetworkManager provides automatic network configuration for
-- Ethernet, Wi-Fi, and mobile broadband on Ubuntu Core devices.
-- Essential for systems that need dynamic network setup.
--
-- Register in package index:
--   shuttle index add network-manager --summary "Network management daemon"
--
-- Usage:
--   image {
--       name = "my-system",
--       version = "1.0.0",
--       base = index("core22"),
--       kernel = index("pc-kernel"),
--       gadget = index("pc-gadget"),
--       snaps = { index("network-manager") },
--   }

return {
    default = snap {
        name = "network-manager",
        version = "1.48",
        summary = "Network management daemon",
        description = [[
            NetworkManager is a system network service that manages
            network devices and connections. It supports Ethernet, Wi-Fi,
            mobile broadband, PPPoE, and VPN connections with automatic
            configuration via DHCP and policy-based routing.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
    },
}
