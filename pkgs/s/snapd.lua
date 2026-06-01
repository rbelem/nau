-- snapd: snap daemon
--
-- The snapd service manages snap installation, updates, and confinement
-- on Ubuntu Core systems. Included in image assembly to provide the
-- snap runtime environment.
--
-- Register in package index:
--   shoot index add snapd --summary "Snap daemon"
--
-- Usage:
--   image {
--       name = "my-system",
--       version = "1.0.0",
--       base = index("core22"),
--       kernel = index("pc-kernel"),
--       gadget = index("pc-gadget"),
--       snaps = { index("snapd") },
--   }

return {
    default = snap {
        name = "snapd",
        version = "2.63",
        summary = "Snap daemon",
        description = [[
            The snapd daemon manages snaps on Ubuntu Core systems.
            Handles installation, updates, security confinement, and
            service management for all snaps on the system.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
    },
}
