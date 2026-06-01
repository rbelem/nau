-- tar: GNU tape archiver
--
-- Source: https://ftp.gnu.org/gnu/tar/
-- Provides the tar archiving utility for creating and extracting archives.

return {
    default = snap {
        name = "tar",
        version = "1.35",
        summary = "GNU tape archiver",
        description = [[
            GNU tar is an archiver that creates and handles file archives
            in various formats. It is the standard tool for creating
            compressed and uncompressed archives on Unix-like systems.
            Supports gzip, bzip2, xz, and zstd compression.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://ftp.gnu.org/gnu/tar/tar-1.35.tar.xz",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
