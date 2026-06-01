-- kbd: Linux keyboard utilities and console fonts
--
-- Source: https://mirrors.edge.kernel.org/pub/linux/utils/kbd/
-- Provides keyboard setup, console fonts, and virtual terminal tools.

return {
    default = snap {
        name = "kbd",
        version = "2.7",
        summary = "Linux keyboard utilities and console fonts",
        description = [[
            The kbd package contains tools for managing the Linux console
            (virtual terminal). Includes loadkeys for setting keyboard
            mappings, setfont for loading console fonts, showkey for
            displaying keycodes, and a collection of console fonts and
            keymaps.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        source = {
            url = "https://mirrors.edge.kernel.org/pub/linux/utils/kbd/kbd-2.7.1.tar.xz",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
