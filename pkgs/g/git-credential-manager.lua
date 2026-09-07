-- git-credential-manager: cross-platform Git credential helper
-- (GitHub/GitLab/Bitbucket/Azure DevOps, OAuth + PAT).
--
-- Ported from the devbox global profile as a prebuilt release binary:
-- the upstream linux x64 tarball is fetched, sha256-pinned, and the
-- git-credential-manager binary plus the two .NET SkiaSharp support
-- libraries it loads from its own directory are staged into usr/bin
-- (the .so files must sit beside the binary). Register it with
-- `git config --global credential.helper manager` on the host.

return {
    default = snap {
        name = "git-credential-manager",
        version = "2.7.3",
        summary = "Cross-platform Git credential helper (GCM)",
        description = [[
            Git Credential Manager (GCM) is a secure Git credential
            helper built on .NET that authenticates to GitHub, GitLab,
            Bitbucket, and Azure DevOps via OAuth and stores
            credentials in the OS credential store.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/git-ecosystem/git-credential-manager/releases/download/v2.7.3/gcm-linux-x64-2.7.3.tar.gz",
            sha256 = "c7935c3e1b22681d56011b580086aeb6d60f3f0aaf6ef9c581480356988ff804",
        },

        build = table.concat({
            "install -Dm755 git-credential-manager $STAGE/usr/bin/git-credential-manager",
            "install -Dm755 libSkiaSharp.so $STAGE/usr/bin/libSkiaSharp.so",
            "install -Dm755 libHarfBuzzSharp.so $STAGE/usr/bin/libHarfBuzzSharp.so",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            ["git-credential-manager"] = app {
                command = "usr/bin/git-credential-manager",
            },
        },
    },
}
