-- pcre2: Perl-Compatible Regular Expressions library (10.x API).
--
-- Pool prerequisite for glib (GRegex links libpcre2-8). The 8-bit
-- library is what glib consumes; 16/32-bit variants stay off to keep
-- the payload small. Release tarball with pre-generated configure;
-- sha256-pinned.
--
-- Requires: glibc

return {
    default = snap {
        name = "pcre2",
        version = "10.48",
        summary = "Perl-Compatible Regular Expressions library (2nd API)",
        description = [[
            PCRE2 is a library of functions implementing regular
            expression pattern matching with semantics as close as
            possible to Perl 5. This package builds the 8-bit PCRE2
            library (libpcre2-8) used by glib's GRegex.
        ]],
        license = "BSD-3-Clause",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },

        source = {
            url = "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.48/pcre2-10.48.tar.gz",
            sha256 = "ebcc25aadf2a51fa1fefa9b8bc9e7a79b3dae86870a0f1152a22e42befd46888",
        },

        build = table.concat({
            "./configure --prefix=/usr --disable-static --disable-pcre2-16 --disable-pcre2-32",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
            -- libtool .la metadata embeds the configure-time prefix
            -- (/shuttle-build-prefix) and is obsolete at runtime — consumers
            -- use the .so libs and .pc pkg-config files. Strip so the build
            -- prefix cannot leak.
            "find $STAGE/usr/lib -name '*.la' -delete",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        -- Interim leak-scan escape (ADR-0018 Decision 3, issue #22), same
        -- rationale as tmux/htop/tig: the leaked nix gcc wrapper bakes
        -- RUNPATH=/shuttle-build-prefix/usr/lib64 into the produced
        -- libraries and test binaries (pcre2test; the lib64 spelling
        -- joined the baked set when the pool glibc payload's loader-lib
        -- list gained the lib64 dir). That path does not exist at
        -- runtime; silenced here, visibly logged by the leak scan,
        -- pending the RUNPATH repair (issue #22's portability follow-up).
        leaks_ok = { "/shuttle-build-prefix/usr/lib64" },
    },
}
