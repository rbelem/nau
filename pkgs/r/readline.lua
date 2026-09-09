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
    },
}
