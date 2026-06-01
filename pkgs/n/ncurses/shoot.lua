-- ncurses: New curses library for terminal handling
--
-- Source: https://ftp.gnu.org/gnu/ncurses/
-- Provides the ncurses terminal UI library and terminfo database.

return {
    default = snap {
        name = "ncurses",
        version = "6.5",
        summary = "New curses library for terminal handling",
        description = [[
            The ncurses (new curses) library is a free software emulation
            of curses in System V Release 4.0 and more. It uses terminfo
            format, supports pads, colors, multiple highlights, form
            characters and function-key mapping. Provides the tic, infocmp,
            and tput utilities along with the shared libraries.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        source = {
            url = "https://ftp.gnu.org/gnu/ncurses/ncurses-6.5.tar.gz",
        },
        build = "./configure --prefix=/usr --with-shared --with-termlib --enable-pc-files && make && make install DESTDIR=$STAGE",
    },
}
