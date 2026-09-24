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

        -- Interim leak-scan escape (ADR-0018 Decision 3, issue #22), same
        -- rationale as tmux/htop/tig: the leaked nix gcc wrapper bakes
        -- RUNPATH=/shuttle-build-prefix/usr/lib64 into the produced
        -- libz.so (the lib64 spelling joined the baked set when the pool
        -- glibc payload's loader-lib list gained the lib64 dir). That
        -- path does not exist at runtime; silenced here, visibly logged
        -- by the leak scan, pending the RUNPATH repair (issue #22's
        -- portability follow-up).
        leaks_ok = { "/shuttle-build-prefix/usr/lib64" },
    },
}
