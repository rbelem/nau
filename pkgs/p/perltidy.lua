-- perltidy: Perl source reformatter / pretty-printer
--
-- Source: https://cpan.metacpan.org/authors/id/S/SH/SHANCOCK/Perl-Tidy-20260826.tar.gz
-- Pure-perl MakeMaker port (issue #23's stopped item, unblocked by the
-- pool perl port in issue #34). Installs the `perltidy` binary and the
-- Perl::Tidy module into perl's site directories, so it rides on the
-- pool perl at runtime.

return {
    default = snap {
        name = "perltidy",
        version = "20260826",
        summary = "Perl source reformatter and pretty-printer",
        description = [[
            perltidy reads a perl program and writes another equivalent
            one with indentation and line wrapping chosen for maximum
            readability. Ships the perltidy CLI plus the Perl::Tidy
            module (the same code base powers perltidy's -html output),
            installed into the pool perl's site directories.
        ]],
        license = "GPL-2.0-or-later",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://cpan.metacpan.org/authors/id/S/SH/SHANCOCK/Perl-Tidy-20260826.tar.gz",
            sha256 = "104e3e5ee5c84524d5e50324d664c7859b1ac422ab97a3e7a248985a4b4f7f64",
        },

        build = table.concat({
            -- The pool perl lives in the merged build prefix; the sandbox
            -- does not extend PATH to it (git.lua documents the same
            -- convention). Makefile.PL and the install steps re-invoke
            -- perl from PATH.
            "export PATH=\"$SHUTTLE_BUILD_PREFIX/usr/bin:$PATH\"",
            -- The prefix perl's @INC is compiled in as /usr/lib/perl5/...
            -- which does not exist at build time (the prefix is mounted at
            -- /shuttle-build-prefix); PERL5LIB re-points it at the merged
            -- prefix tree. At runtime no override is needed: pods mount
            -- the closure at /, exactly where @INC looks.
            "export PERL5LIB=\"$SHUTTLE_BUILD_PREFIX/usr/lib/perl5/5.40.5:$SHUTTLE_BUILD_PREFIX/usr/lib/perl5/5.40.5/x86_64-linux-thread-multi\"",
            "export HOME=/tmp",
            "perl Makefile.PL",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
        }, " && "),

        type = "source",
        -- Pure perl: needs only the interpreter at runtime (glibc is the
        -- interpreter's own dependency; listed so the closure is explicit
        -- about the container's floor).
        requires = { "glibc", "perl" },

        apps = {
            perltidy = app {
                command = "usr/bin/perltidy",
            },
        },
    },
}
