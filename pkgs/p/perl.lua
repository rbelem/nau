-- perl: Perl 5 language interpreter
--
-- Source: https://cpan.metacpan.org/authors/id/S/SH/SHAY/perl-5.40.5.tar.gz
-- Ported for git's perl features (git-send-email and the perl-built
-- helpers) and pure-perl consumers like perltidy (issue #34).
--
-- Configuration shape (./Configure -des = accept every default silently):
--   -Dprefix=/usr            standard pool install prefix
--   -Dusethreads             threads-enabled interpreter (distro default)
--   -Uuseshrplib             static libperl linked into `perl` — no
--                            libperl.so soname to chase across pods
--   -Dman1dir=none           no man pages (payload hygiene)
--   -Dman3dir=none
-- Optional modules degrade gracefully by detection: no GDBM/NDBM/DB
-- headers exist in the sandbox, so the *DBM_File extensions are skipped;
-- no GUI anything exists in core perl. Runtime needs are all glibc
-- (libm/libpthread/libdl fold into glibc >= 2.34).

return {
    default = snap {
        name = "perl",
        version = "5.40.5",
        summary = "Perl 5 language interpreter",
        description = [[
            Perl 5 is a highly capable, feature-rich programming language
            with over 30 years of development. This build is a
            threads-enabled, statically-libperl'd interpreter with the
            core module set; extensions needing external C libraries
            (GDBM/NDBM/DB files, etc.) are skipped by Configure's own
            feature detection. Consumers: git's perl-side helpers
            (git-send-email, git-svn...), perltidy.
        ]],
        license = "Artistic-1.0-Perl",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://cpan.metacpan.org/authors/id/S/SH/SHAY/perl-5.40.5.tar.gz",
            sha256 = "09d926ae2d1b277c3bce62054c41da47c981380d719c41cf980b67945cc581ed",
        },

        build = table.concat({
            -- No /etc in the sandbox (so no passwd entry); Configure and
            -- some probe tools want a writable HOME.
            "export HOME=/tmp",
            -- -des: take every Configure default without asking. The
            -- explicit -D/-U overrides are the pool deltas on top.
            "./Configure -des -Dprefix=/usr -Dusethreads -Uuseshrplib -Dman1dir=none -Dman3dir=none",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
            -- installperl's man handling with man*dir=none writes the
            -- pod-derived .0 roff files to the DESTDIR root instead of
            -- skipping them; drop the strays so the payload root stays
            -- clean.
            "find $STAGE -maxdepth 1 -name '*.0' -type f -delete",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        -- Interim leak-scan escape (ADR-0018 Decision 3, issue #22), same
        -- rationale as git/htop/libstdcpp: the nix gcc wrapper bakes
        -- RUNPATH=/shuttle-build-prefix/usr/lib into the produced perl
        -- binary and every XS-shared object. That path does not exist at
        -- runtime; silenced here, visibly logged by the leak scan,
        -- pending the RUNPATH repair (issue #22's portability follow-up).
        leaks_ok = { "/shuttle-build-prefix/usr/lib" },

        apps = {
            perl = app {
                command = "usr/bin/perl",
            },
        },
    },
}
