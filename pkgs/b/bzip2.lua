-- bzip2: Block-sorting file compressor
--
-- Source: https://sourceware.org/bzip2/
-- Provides the bzip2 compression utility and library.

return {
    default = snap {
        name = "bzip2",
        version = "1.0",
        summary = "Block-sorting file compressor",
        description = [[
            bzip2 is a freely available, patent-free, high-quality data
            compressor. It typically compresses files to within 10% to 15%
            of the best available techniques (the PPM family of statistical
            compressors), whilst being around twice as fast at compression
            and six times faster at decompression.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz",
        },
        -- Split of the original compound build into ordered parts: the
        -- shared object library first, then the tools, then install.
        -- All parts share $SRC; every command targets it with -C because
        -- part work dirs start empty.
        parts = {
            ["shared-lib"] = { build = "make -C $SRC -f Makefile-libbz2_so" },
            tools = {
                build = "make -C $SRC",
                after = { "shared-lib" },
            },
            install = {
                build = "make -C $SRC install PREFIX=$STAGE/usr",
                after = { "tools" },
            },
        },
    },
}
