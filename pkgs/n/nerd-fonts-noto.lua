-- nerd-fonts-noto: Nerd Fonts patched Noto typeface set.
--
-- Font payload package (pod entry): stages the upstream Nerd Fonts
-- release tarball (v3.5.1, sha256-pinned) into the fontconfig-scanned
-- path /usr/share/fonts/truetype. Noto is the largest Nerd Fonts
-- family (Sans, Serif, Mono and their condensed/weights); the payload
-- is correspondingly large. Pure data — no build, no runtime
-- requires; fontconfig-using consumers pick the fonts up from the
-- merged payload tree.

return {
    default = snap {
        name = "nerd-fonts-noto",
        version = "3.5.1",
        summary = "Noto typeface set patched with Nerd Fonts glyphs",
        description = [[
            Noto is Google's font family covering a wide range of
            scripts. This package carries the Nerd Fonts (v3.5.1)
            patched Noto variants — Sans, Serif, and Mono with their
            weights and condensed cuts — staged into
            /usr/share/fonts/truetype for fontconfig-based consumers.
        ]],
        license = "OFL-1.1",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/ryanoasis/nerd-fonts/releases/download/v3.5.1/Noto.tar.xz",
            sha256 = "818deb4370c71315986b7d7a92c0dc508dd785a8d57f7cdfa871397a3a3834ab",
        },

        build = "mkdir -p $STAGE/usr/share/fonts/truetype/nerd-fonts-noto && cp $SRC/*.ttf $SRC/LICENSE_OFL.txt $STAGE/usr/share/fonts/truetype/nerd-fonts-noto/",

        type = "source",
        requires = {},
    },
}
