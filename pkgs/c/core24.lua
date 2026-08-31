-- core24: runtime environment based on Ubuntu 24.04 LTS
--
-- The base snap provides the root filesystem for snaps using core24.
-- Downloads from Snap Store, consumed by image() DSL.
--
-- Register in package index:
--   shuttle index add core24 --summary "Runtime based on Ubuntu 24.04"
--
-- Usage in an image declaration:
--   image {
--       name = "my-system",
--       version = "24.04",
--       base = index("core24"),
--       ...
--   }

return {
    default = snap {
        name = "core24",
        version = "24.04",
        summary = "Runtime environment based on Ubuntu 24.04 LTS",
        description = [[
            Core24 provides a minimal Ubuntu 24.04 LTS root filesystem
            for snaps targeting the core24 base. Includes glibc, libstdc++,
            and essential runtime libraries.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf", "ppc64el", "s390x" },
        type = "source",
        requires = { "glibc" },
    },
}
