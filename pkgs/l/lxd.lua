-- lxd: system container manager
--
-- LXD provides system containers for running full Linux distributions
-- inside Ubuntu Core. Useful for development, testing, and workloads
-- that need a full OS environment.
--
-- Register in package index:
--   shoot index add lxd --summary "System container manager"
--
-- Usage:
--   image {
--       name = "my-system",
--       version = "1.0.0",
--       base = index("core22"),
--       kernel = index("pc-kernel"),
--       gadget = index("pc-gadget"),
--       snaps = { index("lxd") },
--   }

return {
    default = snap {
        name = "lxd",
        version = "5.21",
        summary = "System container manager",
        description = [[
            LXD is a next-generation system container manager.
            It offers a user experience similar to virtual machines
            but using Linux containers instead. Run Ubuntu, Fedora,
            Alpine, and other distributions inside your Ubuntu Core system.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
    },
}
