-- diffutils: GNU diff, diff3, sdiff, and cmp utilities
--
-- Source: https://ftp.gnu.org/gnu/diffutils/
-- Provides file comparison utilities.

return {
    default = snap {
        name = "diffutils",
        version = "3.10",
        summary = "GNU diff, diff3, sdiff, and cmp utilities",
        description = [[
            GNU Diffutils provides the diff, diff3, sdiff, and cmp
            commands. These utilities compare files and show the
            differences between them. diff compares files line by line,
            cmp compares bytes, and diff3 merges three files together.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        source = {
            url = "https://ftp.gnu.org/gnu/diffutils/diffutils-3.10.tar.xz",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
