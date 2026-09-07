-- ghq: manage remote repository clones (GitHub, GitLab, etc.) under
-- a predictable directory layout like go get.
--
-- Ported from the devbox global profile as a prebuilt release binary
-- (upstream moved from Songmu/ghq to x-motemen/ghq): the linux amd64
-- zip asset is fetched, sha256-pinned, and extracted with python3's
-- zipfile module (no unzip tool in the build sandbox); the ghq binary
-- (Go, static) is staged into usr/bin.

return {
    default = snap {
        name = "ghq",
        version = "1.10.1",
        summary = "Remote repository management made easy",
        description = [[
            ghq manages remote repository clones under a directory
            hierarchy like <host>/<owner>/<repo>, providing ghq get,
            ghq list, and ghq root. Designed to pair well with pecco /
            fzf for fast repository switching.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/x-motemen/ghq/releases/download/v1.10.1/ghq_linux_amd64.zip",
            sha256 = "32e380aa8ac76fdd58758cc06174d9ee5db7270bd0cbcc18138b5d36def91b6b",
        },

        build = table.concat({
            "python3 -m zipfile -e ghq_linux_amd64.zip .",
            "install -Dm755 ghq_linux_amd64/ghq $STAGE/usr/bin/ghq",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            ghq = app {
                command = "usr/bin/ghq",
            },
        },
    },
}
