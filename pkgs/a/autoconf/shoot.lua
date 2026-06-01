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
        source = { url = "https://ftp.gnu.org/gnu/autoconf/autoconf-2.72.tar.xz" },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
