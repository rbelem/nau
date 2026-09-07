-- git-credential-oauth: a git credential helper that authenticates
-- to GitHub, GitLab, Bitbucket, and other forges via OAuth device
-- flow.
--
-- Ported from the devbox global profile as a prebuilt release binary:
-- the upstream linux amd64 tarball is fetched, sha256-pinned, and the
-- git-credential-oauth binary (flat at the tarball root, static Go
-- binary) is staged directly into usr/bin. Register it with
-- `git config --global credential.helper` on the host.

return {
    default = snap {
        name = "git-credential-oauth",
        version = "0.17.2",
        summary = "Git credential helper for OAuth device flow",
        description = [[
            git-credential-oauth is a Git credential helper that
            authenticates to GitHub, GitLab, Bitbucket, and other
            forges via the OAuth device flow, storing tokens via your
            configured credential store. Pairs well with
            git-credential-manager alternatives for headless setups.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/hickford/git-credential-oauth/releases/download/v0.17.2/git-credential-oauth_0.17.2_linux_amd64.tar.gz",
            sha256 = "7a234633ddb24c8f208505763bcb7daaa80ad068e6a4753e7660d558443b1d4a",
        },

        build = table.concat({
            "install -Dm755 git-credential-oauth $STAGE/usr/bin/git-credential-oauth",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            ["git-credential-oauth"] = app {
                command = "usr/bin/git-credential-oauth",
            },
        },
    },
}
