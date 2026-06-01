-- bash: GNU Bourne-Again Shell
--
-- Source: https://ftp.gnu.org/gnu/bash/
-- Provides the bash shell and related utilities.

return {
    default = snap {
        name = "bash",
        version = "5.3",
        summary = "GNU Bourne-Again Shell",
        description = [[
            Bash is a sh-compatible command language interpreter that
            executes commands read from the standard input or from a file.
            Bash also incorporates useful features from the Korn and C
            shells (ksh and csh). It is the default shell on most Linux
            distributions.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        source = {
            url = "https://ftp.gnu.org/gnu/bash/bash-5.3.tar.gz",
        },
        build = "./configure --prefix=/usr --without-bash-malloc && make && make install DESTDIR=$STAGE",
    },
}
