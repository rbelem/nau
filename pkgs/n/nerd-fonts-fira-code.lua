-- nerd-fonts-fira-code: Nerd Fonts patched Fira Code typeface.
--
-- Font payload package (pod entry): stages the upstream Nerd Fonts
-- release tarball (v3.5.1, sha256-pinned) into the fontconfig-scanned
-- path /usr/share/fonts/truetype. Pure data — no build, no runtime
-- requires; fontconfig-using consumers pick the fonts up from the
-- merged payload tree.

return {
    default = snap {
        name = "nerd-fonts-fira-code",
        version = "3.5.1",
        summary = "Fira Code typeface patched with Nerd Fonts glyphs",
        description = [[
            Fira Code is a monospaced font with programming ligatures.
            This package carries the Nerd Fonts (v3.5.1) patched
            variants — Nerd Font, Nerd Font Mono, and Nerd Font Propo —
            staged into /usr/share/fonts/truetype for fontconfig-based
            consumers.
        ]],
        license = "OFL-1.1",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/ryanoasis/nerd-fonts/releases/download/v3.5.1/FiraCode.tar.xz",
            sha256 = "68e3bd6164864b8b514605bc34e3a87ac401c8c48682fcce6478c70263340207",
        },

        build = "mkdir -p $STAGE/usr/share/fonts/truetype/nerd-fonts-fira-code && cp $SRC/*.ttf $SRC/LICENSE $STAGE/usr/share/fonts/truetype/nerd-fonts-fira-code/",

        type = "source",
        requires = {},
    },
}
