-- zstd: Zstandard fast real-time compression
--
-- Source: https://github.com/facebook/zstd
-- Provides the zstd compression utility and library.

return {
    default = snap {
        name = "zstd",
        version = "1.5",
        summary = "Zstandard fast real-time compression",
        description = [[
            Zstandard is a fast lossless compression algorithm, targeting
            real-time compression scenarios at zlib-level and better
            compression ratios. The zstd command-line tool provides
            compression and decompression of .zst files. Also includes
            the libzstd shared library.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        source = {
            url = "https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz",
        },
        build = "make prefix=/usr && make install PREFIX=/usr DESTDIR=$STAGE",
    },
}
