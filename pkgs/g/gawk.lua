-- gawk: GNU awk, a pattern scanning and processing language
--
-- Source: https://ftp.gnu.org/gnu/gawk/
-- Provides the gawk programming language for text processing.

return {
    default = snap {
        name = "gawk",
        version = "5.4.1",
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
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://ftp.gnu.org/gnu/gawk/gawk-5.4.1.tar.xz",
            sha256 = "07f6f7342b7febe4313fc2c2542ad93d64fe20ad8717200109f105a826f5fd37",
        },
        -- gawk's configure records the sandbox build prefix in its
        -- RUNPATHs (binaries + every extension .so) when readline sits
        -- in the merged build prefix — the leak scan refuses the pack
        -- otherwise (live 2026-10-03 daily converge). The same
        -- build-only class binutils silences.
        leaks_ok = {
            "/nau-build-prefix",
            "/nau-build-prefix/usr/lib64",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
