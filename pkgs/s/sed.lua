-- sed: GNU stream editor for filtering and transforming text
--
-- Source: https://ftp.gnu.org/gnu/sed/
-- Provides the sed stream editor utility.

return {
    default = snap {
        name = "sed",
        version = "4.9",
        summary = "GNU stream editor for filtering and transforming text",
        description = [[
            sed (stream editor) is a non-interactive command-line text
            editor. sed is commonly used to filter text, i.e., it reads
            specific lines and makes changes according to the given
            commands. It supports regular expressions and in-place editing.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://ftp.gnu.org/gnu/sed/sed-4.9.tar.xz",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
