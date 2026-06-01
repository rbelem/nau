-- grep: GNU regular expression pattern matcher
--
-- Source: https://ftp.gnu.org/gnu/grep/
-- Provides grep, egrep, and fgrep for searching text.

return {
    default = snap {
        name = "grep",
        version = "3.12",
        summary = "GNU regular expression pattern matcher",
        description = [[
            GNU grep searches input files for lines containing a match to
            a given pattern list. When it finds a match in a line, it copies
            the line to standard output (by default), or produces whatever
            other sort of output you have requested with options. Also
            includes egrep and fgrep.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://ftp.gnu.org/gnu/grep/grep-3.12.tar.xz",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
