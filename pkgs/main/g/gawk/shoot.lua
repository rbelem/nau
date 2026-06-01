-- gawk: GNU awk, a pattern scanning and processing language
--
-- Source: https://ftp.gnu.org/gnu/gawk/
-- Provides the gawk programming language for text processing.

return {
    default = snap {
        name = "gawk",
        version = "5.3",
        summary = "GNU awk, a pattern scanning and processing language",
        description = [[
            gawk is the GNU implementation of awk, a programming language
            for easy text processing. It is a powerful tool for data
            extraction and reporting. The language supports variables,
            expressions, regular expressions, and associative arrays.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        source = {
            url = "https://ftp.gnu.org/gnu/gawk/gawk-5.3.1.tar.xz",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
