-- core22: runtime environment based on Ubuntu 22.04 LTS
--
-- The base snap provides the root filesystem for snaps using core22.
-- Downloaded from the Snap Store, consumed by image() DSL.
--
-- Register in package index:
--   shoot index add core22 --summary "Runtime based on Ubuntu 22.04"
--
-- Usage in an image declaration:
--   image {
--       name = "my-system",
--       version = "1.0.0",
--       base = index("core22"),
--       ...
--   }

return {
    default = snap {
        name = "core22",
        version = "22.04",
        summary = "Runtime environment based on Ubuntu 22.04 LTS",
        description = [[
            Core22 provides a minimal Ubuntu 22.04 LTS root filesystem
            for snaps targeting the core22 base. Includes glibc, libstdc++,
            and essential runtime libraries.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf", "ppc64el", "s390x" },
        type = "source",
        requires = { "glibc" },
    },
}
