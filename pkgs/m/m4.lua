-- m4: GNU macro processor
--
-- Source: https://ftp.gnu.org/gnu/m4/m4-1.4.19.tar.xz
return {
    default = snap {
        name = "m4",
        version = "1.4.19",
        summary = "GNU macro processor",
        description = [[GNU M4 1.4.19 is a macro processor that copies its input to the output,
expanding macros as it goes. It has built-in functions for including files,
running shell commands, doing arithmetic, manipulating text, and more.
Autoconf and other GNU build tools depend on M4 for macro expansion.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        requires = {},
        source = { url = "https://ftp.gnu.org/gnu/m4/m4-1.4.19.tar.xz" },
        parts = {
            m4 = { plugin = "autotools" },
        },
    },
}
