-- automake: GNU tool for generating Makefile.in files
--
-- Source: https://ftp.gnu.org/gnu/automake/automake-1.17.tar.xz
return {
    default = snap {
        name = "automake",
        version = "1.17",
        summary = "GNU tool for generating Makefile.in files",
        description = [[Automake 1.17 is a tool for automatically generating Makefile.in files from
templates. It works with Autoconf to produce portable, GNU-standard
Makefiles. Each Makefile.in is created from a Makefile.am and can be
used by configure scripts to generate platform-specific Makefiles.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        build_deps = { "autoconf" },
        requires = { "autoconf" },
        source = { url = "https://ftp.gnu.org/gnu/automake/automake-1.17.tar.xz" },
        build = table.concat({
            -- The prefix perl payload's @INC is baked for a real-root
            -- /usr; automake's own perl scripts (aclocal and friends)
            -- need the merged-prefix lib dirs — perltidy.lua's export,
            -- same version pin. The tree lib/ (Automake::Config et al)
            -- covers make-time doc generation, and the automake share
            -- dir covers post-install aclocal runs in the same build.
            'export PERL5LIB="$PWD/lib:$SHUTTLE_BUILD_PREFIX/usr/share/automake-1.17:$SHUTTLE_BUILD_PREFIX/usr/lib/perl5/5.40.5:$SHUTTLE_BUILD_PREFIX/usr/lib/perl5/5.40.5/x86_64-linux-thread-multi"',
            "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
            -- The aclocal/automake drivers carry their perl lib dir
            -- (@datadir@/@PACKAGE@-@VERSION@) as a real-root path; wrap
            -- them (pool interpreter-wrapper pattern, #9) so the merged
            -- prefix's automake lib dir leads PERL5LIB in every context
            -- (build prefix, real root, extension tree). The m4-side:
            -- aclocal bakes both acdirs real-root — the automake-m4
            -- acdir (@datadir@/aclocal-@APIVERSION@, fatal scan) and
            -- the third-party acdir (@datadir@/aclocal, also fatal —
            -- surfaced live on evtest after the first export landed) —
            -- and the automake driver bakes its .am libdir
            -- (Automake::Config $libdir) the same way. The aclocal
            -- driver resets its lists under AUTOMAKE_UNINSTALLED (its
            -- own "don't refer to installation directories from the
            -- build environment" mode) and re-honors
            -- ACLOCAL_AUTOMAKE_DIR afterwards; third-party dirs stay
            -- reachable via ACLOCAL_PATH, which parses after the
            -- reset. The libdir has the AUTOMAKE_LIBDIR override, so
            -- the wrapper exports the triple (#211).
            table.concat({
                "for f in aclocal automake aclocal-1.17 automake-1.17; do",
                '  [ -e "$STAGE/usr/bin/$f" ] || continue',
                '  mv "$STAGE/usr/bin/$f" "$STAGE/usr/bin/$f.real"',
                "  cat > \"$STAGE/usr/bin/$f\" <<EOF",
                "#!/bin/sh",
                'd=\\$(dirname "\\$(readlink -f "\\$0")")',
                'PERL5LIB="\\$d/../share/automake-1.17\\${PERL5LIB:+:\\$PERL5LIB}"',
                'export PERL5LIB',
                'ACLOCAL_AUTOMAKE_DIR="\\$d/../share/aclocal-1.17"',
                'export ACLOCAL_AUTOMAKE_DIR',
                'AUTOMAKE_LIBDIR="\\$d/../share/automake-1.17"',
                'export AUTOMAKE_LIBDIR',
                "AUTOMAKE_UNINSTALLED=1",
                "export AUTOMAKE_UNINSTALLED",
                'exec "\\$d/$f.real" "\\$@"',
                "EOF",
                '  chmod +x "$STAGE/usr/bin/$f" || exit 1',
                "done",
                -- Wrapper contract, asserted: every driver carries the
                -- shim (a raw 37K driver reappearing means the loop
                -- missed a name — loud failure, pool convention).
                "for f in aclocal automake aclocal-1.17 automake-1.17; do test \"$(head -1 \"$STAGE/usr/bin/$f\")\" = '#!/bin/sh' || { echo \"automake wrapper missing on $f\" >&2; exit 1; }; done",
            }, "\n"),
        }, " && "),

        -- Interim leak-scan escape (ADR-0018 Decision 3, issue #22): the
        -- generated perl drivers embed their build-time paths (the
        -- @PERL@/@AUTOM4TE@/@pkgdatadir@ substitutions resolve into the
        -- merged build prefix). Text references, silenced with the bare
        -- prefix entry, pending the RUNPATH repair (issue #22).
        leaks_ok = { "/shuttle-build-prefix" },
    },
}
