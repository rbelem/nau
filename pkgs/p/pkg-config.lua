-- pkg-config: system for managing library compile/link flags
--
-- Source: https://pkgconfig.freedesktop.org/releases/pkg-config-0.29.2.tar.gz
return {
    default = snap {
        name = "pkg-config",
        version = "0.29.2",
        summary = "System for managing library compile/link flags",
        description = [[pkg-config 0.29.2 is a helper tool used when compiling applications and
libraries. It helps to insert the correct compiler options on the command
line so an application can use gcc -o test test.c `pkg-config --libs --cflags glib-2.0`.
This build uses the internal glib to avoid external dependencies.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        requires = {},
        source = { url = "https://pkgconfig.freedesktop.org/releases/pkg-config-0.29.2.tar.gz" },
        build = "./configure --prefix=/usr --with-internal-glib && make && make install DESTDIR=$STAGE",
    },
}
