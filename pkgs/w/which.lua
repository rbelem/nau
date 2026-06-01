-- which: Show the full path of shell commands
--
-- Source: https://ftp.gnu.org/gnu/which/
-- Provides the which utility for locating commands in PATH.

return {
    default = snap {
        name = "which",
        version = "2.23",
        summary = "Show the full path of shell commands",
        description = [[
            which takes one or more arguments. For each of its arguments
            it prints to stdout the full path of the executables that
            would have been executed when this argument had been entered
            at the shell prompt. It searches the user's PATH for matching
            executables.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://ftp.gnu.org/gnu/which/which-2.23.tar.gz",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
