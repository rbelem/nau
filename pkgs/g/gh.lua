-- gh: GitHub CLI, take GitHub to the command line.
--
-- Ported from the devbox global profile as a prebuilt release binary:
-- the upstream linux amd64 tarball is fetched, sha256-pinned, and the
-- gh binary (from bin/ inside the extracted tree, no Go toolchain
-- needed in the build sandbox) is staged directly into usr/bin.

return {
    default = snap {
        name = "gh",
        version = "2.97.0",
        summary = "GitHub CLI — take GitHub to the command line",
        description = [[
            gh is GitHub on the command line: manage pull requests,
            issues, releases, workflows, repositories, gists, and more
            without leaving the terminal. It authenticates with your
            GitHub account and bridges seamlessly into git itself.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/cli/cli/releases/download/v2.97.0/gh_2.97.0_linux_amd64.tar.gz",
            sha256 = "a2c9b8497e1f85b1ad0dfcb78b5a622e098801b8e461e459e88e1ee12f018112",
        },

        build = table.concat({
            "install -Dm755 bin/gh $STAGE/usr/bin/gh",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            gh = app {
                command = "usr/bin/gh",
            },
        },
    },
}
