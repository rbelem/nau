-- starship: the minimal, blazing-fast, infinitely customizable prompt
-- for any shell, written in Rust.
--
-- Ported from the devbox global profile as a prebuilt release binary:
-- the upstream x86_64 musl tarball is fetched, sha256-pinned, and the
-- starship binary (flat at the tarball root, no Rust toolchain needed
-- in the build sandbox) is staged directly into usr/bin.

return {
    default = snap {
        name = "starship",
        version = "1.26.0",
        summary = "Fast, customizable prompt for any shell",
        description = [[
            starship is a minimal, blazing-fast, infinitely
            customizable cross-shell prompt. It displays contextual
            information (git status, language versions, kubernetes
            context, battery, and more) whenever it is relevant, fast
            enough to be unnoticeable.
        ]],
        license = "ISC",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/starship/starship/releases/download/v1.26.0/starship-x86_64-unknown-linux-musl.tar.gz",
            sha256 = "b7c232b0e8249d8e55a40beb79c5c43a7d370f3f9408bd215deb0170daeaadf3",
        },

        build = table.concat({
            "install -Dm755 starship $STAGE/usr/bin/starship",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            starship = app {
                command = "usr/bin/starship",
            },
        },
    },
}
