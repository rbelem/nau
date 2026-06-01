-- htop: Interactive process viewer
--
-- Source: https://htop.dev/
-- Provides the htop interactive process and system monitor.

return {
    default = snap {
        name = "htop",
        version = "3.3",
        summary = "Interactive process viewer",
        description = [[
            htop is an interactive process viewer for Unix systems. It is
            a text-mode application (for console or X terminals) and
            requires ncurses. htop is similar to top but allows scrolling
            vertically and horizontally, and provides a nicer visual
            interface for managing processes.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        source = {
            url = "https://github.com/htop-dev/htop/archive/refs/tags/3.3.0.tar.gz",
        },
        build = "./autogen.sh && ./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
