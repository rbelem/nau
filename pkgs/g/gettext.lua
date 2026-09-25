-- gettext: GNU internationalization and localization library
--
-- Source: https://ftp.gnu.org/gnu/gettext/gettext-0.22.5.tar.xz
return {
    default = snap {
        name = "gettext",
        version = "0.22.5",
        summary = "GNU internationalization and localization library",
        description = [[GNU gettext 0.22.5 provides a set of tools and documentation for producing
multi-lingual messages. It includes the libintl library for use in programs
and the xgettext, msgfmt, and related tools for extracting and compiling
translation files. It is a core dependency for many GNU packages.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        build_deps = { "gcc", "make" },
        -- glibc: gettext's binaries link libc; libgcc/libstdcpp:
        -- libasprintf is C++ (DT_NEEDED libgcc_s.so.1 + libstdc++.so.6)
        -- (the empty requires was tolerated while the runtime libs
        -- leaked from the host; the leak-scan closure check now catches
        -- it, #180 payoff).
        requires = { "glibc", "libgcc", "libstdcpp" },
        source = { url = "https://ftp.gnu.org/gnu/gettext/gettext-0.22.5.tar.xz" },
        -- --without-libpsl n/a; gettext is a plain autotools build. The
        -- usr/share/info/dir index file it installs conflicts with glibc's
        -- in the merged build prefix (ADR-0018 hard-error on differing
        -- content) and is a generated index that no pool consumer reads —
        -- strip it.
        build = table.concat({
            -- GCC 14 made -Wincompatible-pointer-types a hard error (it
            -- fires in gettext 0.22.5's libtextstyle iconv-ostream
            -- vtable, and -w does not suppress the new defaults). The
            -- one-line demotion unblocks the 0.22.5 build under the deb
            -- gcc 14 payload; upstream restructured libtextstyle in
            -- 0.24, so this dies with the version bump.
            "export CFLAGS=-Wno-error=incompatible-pointer-types",
            "./configure --prefix=/usr",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
            "find $STAGE/usr/share/info -maxdepth 1 -name dir -delete",
            -- libtool .la metadata embeds the configure-time prefix
            -- (/shuttle-build-prefix) and nothing in the pool consumes
            -- .la files at runtime (libstdcpp/expat precedent) — strip
            -- them so the build prefix cannot leak.
            "find $STAGE/usr -name '*.la' -delete",
        }, " && "),

        -- Interim leak-scan escape (ADR-0018 Decision 3, issue #22), same
        -- rationale as tmux/htop/tig: the leaked nix gcc wrapper bakes
        -- RUNPATH=/shuttle-build-prefix/usr/lib64 into the produced
        -- binaries (recode-sr-latin et al; the lib64 spelling joined the
        -- baked set when the pool glibc payload's loader-lib list gained
        -- the lib64 dir). That path does not exist at runtime; silenced
        -- here, visibly logged by the leak scan, pending the RUNPATH
        -- repair (issue #22's portability follow-up).
        leaks_ok = { "/shuttle-build-prefix/usr/lib64" },
    },
}
