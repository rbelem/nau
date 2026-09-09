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
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://ftp.gnu.org/gnu/ncurses/ncurses-6.5.tar.gz",
        },
        build = "./configure --prefix=/usr --with-shared --with-termlib --enable-pc-files --without-cxx-binding --with-pkg-config-libdir=/usr/lib/pkgconfig && make && make install DESTDIR=$STAGE",
        -- Interim leak-scan escape (ADR-0018 Decision 3, issue #22 / #30 lane
        -- follow-up): the nix gcc wrapper bakes the merged build prefix into
        -- the installed `ncursesw6-config`, whose --prefix/--libdir echoes
        -- /shuttle-build-prefix/usr/lib. The text scanner's Leak.reference is
        -- the exact prefix marker `/shuttle-build-prefix`, so leaks_ok must
        -- match that string. Silenced here, visibly logged by the leak scan,
        -- pending the RUNPATH/config repair (portability follow-up).
        leaks_ok = { "/shuttle-build-prefix" },
    },
}
