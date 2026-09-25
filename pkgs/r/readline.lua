-- readline: GNU Readline library for line editing
--
-- Source: https://ftp.gnu.org/gnu/readline/
-- Provides the readline library for interactive command-line editing.

return {
    default = snap {
        name = "readline",
        version = "8.3",
        summary = "GNU Readline library for line editing",
        description = [[
            The GNU Readline library provides a set of functions for use
            by applications that allow users to edit command lines as they
            are typed in. Both Emacs and vi editing modes are available.
            Readline also includes history expansion and programmable
            completion features.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://ftp.gnu.org/gnu/readline/readline-8.3.tar.gz",
        },
        build = table.concat({
            "./configure --prefix=/usr --with-shared && make && make install DESTDIR=$STAGE",
            -- The install-info-generated usr/share/info/dir index differs
            -- from glibc's, and the merged build prefix requires identical
            -- content at shared paths (same escape as libffi/gettext).
            -- glibc's copy survives as the index.
            "rm -f $STAGE/usr/share/info/dir",
        }, " && "),

        -- Interim leak-scan escape (ADR-0018 Decision 3, issue #22), same
        -- rationale as tmux/htop/tig: the leaked nix gcc wrapper bakes
        -- RUNPATH=/shuttle-build-prefix/usr/lib64 into the produced
        -- libreadline.so (the lib64 spelling joined the baked set when
        -- the pool glibc payload's loader-lib list gained the lib64
        -- dir). That path does not exist at runtime; silenced here,
        -- visibly logged by the leak scan, pending the RUNPATH repair
        -- (issue #22's portability follow-up).
        leaks_ok = { "/shuttle-build-prefix/usr/lib64" },
    },
}
