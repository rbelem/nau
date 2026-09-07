-- p7zip: high-compression file archiver (7-Zip for Linux).
--
-- Ported from the devbox global profile (devbox's p7zip 17.06 is the
-- legacy port of 7-Zip; this packages the current upstream Linux
-- release by the original 7-Zip author, ip7z/7zip) as a prebuilt
-- release binary: the linux-x64 tarball is fetched, sha256-pinned,
-- and the 7zz console binary (flat at the tarball root) is staged
-- directly into usr/bin.

return {
    default = snap {
        name = "p7zip",
        version = "26.03",
        summary = "7-Zip file archiver for Linux (7zz)",
        description = [[
            7-Zip is a file archiver with a high compression ratio,
            supporting its native 7z format plus zip, tar, xz, gzip,
            and more. This package ships the official upstream Linux
            console binary 7zz (successor of the p7zip port).
        ]],
        license = "LGPL-2.1-or-later with unRAR restriction",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/ip7z/7zip/releases/download/26.03/7z2603-linux-x64.tar.xz",
            sha256 = "dc99eff5008f1ab79bd7084c68513701547a808a89502bf4133683535ab3c695",
        },

        -- Tarball layout gotcha: this tarball is flat EXCEPT for a
        -- single top-level directory (MANUAL/), which the source-root
        -- finder (find_source_root) picks as $SRC/cwd. Resolve the
        -- binary against $SRC/.. so the build works for either layout.
        build = table.concat({
            "install -Dm755 \"$SRC/../7zz\" $STAGE/usr/bin/7zz",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            ["7zz"] = app {
                command = "usr/bin/7zz",
            },
        },
    },
}
