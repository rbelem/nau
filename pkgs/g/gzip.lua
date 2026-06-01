-- gzip: GNU compression utility
--
-- Source: https://ftp.gnu.org/gnu/gzip/
-- Provides the gzip and gunzip compression tools.

return {
    default = snap {
        name = "gzip",
        version = "1.13",
        summary = "GNU compression utility",
        description = [[
            GNU gzip is a popular data compression program. It uses the
            DEFLATE algorithm for compression, originally implemented in
            the zlib library. The gzip format is widely used on the
            Internet and in Unix-like systems. Includes gzip, gunzip,
            and zcat.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://ftp.gnu.org/gnu/gzip/gzip-1.13.tar.xz",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
