-- nano: GNU nano text editor
--
-- Source: https://nano-editor.org/
-- Provides the nano text editor for the terminal.

return {
    default = snap {
        name = "nano",
        version = "8.3",
        summary = "GNU nano text editor",
        description = [[
            GNU nano is a small and friendly text editor. It aims to
            emulate the Pico text editor while also offering several
            enhancements. Features include syntax highlighting, line
            numbering, multiple buffers, search and replace with regular
            expressions, smooth scrolling, and auto-indentation.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc", "ncurses" },
        source = {
            url = "https://nano-editor.org/dist/v8/nano-8.3.tar.xz",
        },
        build = "./configure --prefix=/usr --enable-utf8 && make && make install DESTDIR=$STAGE",
    },
}
