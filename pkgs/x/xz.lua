-- xz: XZ Utils compression tools
--
-- Source: https://github.com/tukaani-project/xz
-- Provides the xz, lzma, and related compression utilities.

return {
    default = snap {
        name = "xz",
        version = "5.6",
        summary = "XZ Utils compression tools",
        description = [[
            XZ Utils provide a general-purpose data compression tool with
            high compression ratio. The xz format uses LZMA2 compression,
            and the legacy .lzma format is also supported. Includes xz,
            unxz, xzcat, lzma, unlzma, lzcat, and the liblzma library.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://github.com/tukaani-project/xz/releases/download/v5.6.4/xz-5.6.4.tar.gz",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
