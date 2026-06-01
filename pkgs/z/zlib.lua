-- zlib: Compression library
--
-- Source: https://zlib.net/
-- Provides the zlib compression and decompression library.

return {
    default = snap {
        name = "zlib",
        version = "1.3.2",
        summary = "Compression library",
        description = [[
            zlib is a massively-spiffy yet seriously-not-bloated
            compression library. It provides in-memory compression and
            decompression functions, including integrity checks of the
            uncompressed data. Implements the DEFLATE compression
            algorithm used in gzip, PNG, and many other formats.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://zlib.net/zlib-1.3.2.tar.gz",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
