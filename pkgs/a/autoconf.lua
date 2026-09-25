-- autoconf: GNU tool for generating configure scripts
--
-- Source: https://ftp.gnu.org/gnu/autoconf/autoconf-2.72.tar.xz
return {
    default = snap {
        name = "autoconf",
        version = "2.72",
        summary = "GNU tool for generating configure scripts",
        description = [[Autoconf 2.72 generates shell scripts that can automatically configure source
code packages. These scripts adapt packages to many kinds of UNIX-like
systems without manual user intervention. Autoconf creates a configuration
script from a template file that lists operating system features.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        -- perl: the autoconf/autom4te drivers are perl scripts — the
        -- interpreter must ride the payload closure (#180 payoff: the
        -- host perl used to leak through the sandbox PATH; the
        -- canonicalized build PATH no longer carries it).
        leaks_ok = { "/shuttle-build-prefix/usr/share/autoconf", "/shuttle-build-prefix" },
        requires = { "m4", "perl" },
        source = { url = "https://ftp.gnu.org/gnu/autoconf/autoconf-2.72.tar.xz" },
        build = table.concat({
            -- The prefix perl payload's @INC is baked for a real-root
            -- /usr (its Config); in a merged prefix the perl lib dirs
            -- sit under the prefix — perltidy.lua's export, same
            -- version pin.
            'export PERL5LIB="$SHUTTLE_BUILD_PREFIX/usr/lib/perl5/5.40.5:$SHUTTLE_BUILD_PREFIX/usr/lib/perl5/5.40.5/x86_64-linux-thread-multi"',
            "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
            -- The autoconf drivers bake --prefix=/usr paths (the lib dir
            -- a real-root install would serve), which no merged prefix
            -- or extension tree can honor. Each driver honors env
            -- overrides (autom4te_perllibdir / AC_MACRODIR / trailer_m4)
            -- except autoscan/autoupdate's hardcoded @include — route
            -- all of them through a relocating wrapper, the pool's
            -- interpreter-wrapper pattern (#9): lib dir resolved
            -- relative to the invoked driver, working at a real root,
            -- under a merged prefix and in an extension tree alike.
            -- (m4 itself is found via the constant sandbox prefix the
            -- configure run baked, same path every prefix mounts.)
            table.concat({
                "for f in autoconf autoheader autom4te autoreconf autoscan autoupdate ifnames; do",
                '  mv "$STAGE/usr/bin/$f" "$STAGE/usr/bin/$f.real"',
                "  cat > \"$STAGE/usr/bin/$f\" <<EOF",
                "#!/bin/sh",
                'd=\\$(dirname "\\$(readlink -f "\\$0")")',
                'lib=\\$d/../share/autoconf',
                'export autom4te_perllibdir="\\$lib" AC_MACRODIR="\\$lib"',
                'export trailer_m4="\\$lib/autoconf/trailer.m4"',
                'AUTOM4TE="\\$d/autom4te" AUTOCONF="\\$d/autoconf" AUTOHEADER="\\$d/autoheader"',
                'export AUTOM4TE AUTOCONF AUTOHEADER',
                'PERL5LIB="\\$d/../lib/perl5/5.40.5:\\$d/../lib/perl5/5.40.5/x86_64-linux-thread-multi\\${PERL5LIB:+:\\$PERL5LIB}"',
                'export PERL5LIB',
                'exec "\\$d/$f.real" "\\$@"',
                "EOF",
                '  chmod +x "$STAGE/usr/bin/$f" || exit 1',
                "done",
                -- autom4te's include list is option-driven only (its
                -- @pkgdatadir@ default never lands in @include), and
                -- autoscan/autoupdate hardcode the /usr fallback: give
                -- all three the AC_MACRODIR-env default so the wrapper's
                -- export relocates the macro dir too. Shell sees \\$ as
                -- a literal $ — the perl runtime reads the env.
                "sed -i \"s#^my @include;\\$#my @include = (\\$ENV{'AC_MACRODIR'} || '/usr/share/autoconf');#\" \"$STAGE/usr/bin/autom4te.real\"",
                "sed -i \"s#^my @include = ('/usr/share/autoconf');\\$#my @include = (\\$ENV{'AC_MACRODIR'} || '/usr/share/autoconf');#\" \"$STAGE/usr/bin/autoscan.real\" \"$STAGE/usr/bin/autoupdate.real\"",
            }, "\n"),
        }, " && "),
    },
}
