-- nerd-fonts-hack: Nerd Fonts patched Hack typeface.
--
-- Font payload package (pod entry): stages the upstream Nerd Fonts
-- release tarball (v3.5.1, sha256-pinned) into the fontconfig-scanned
-- path /usr/share/fonts/truetype. Pure data — no build, no runtime
-- requires; fontconfig-using consumers pick the fonts up from the
-- merged payload tree.
--
-- Requires: none (font data)

return {
    default = snap {
        name = "nerd-fonts-hack",
        version = "3.5.1",
        summary = "Hack typeface patched with Nerd Fonts glyphs",
        description = [[
            Hack is a typeface designed for source code. This package
            carries the Nerd Fonts (v3.5.1) patched variants — Nerd
            Font, Nerd Font Mono, and Nerd Font Propo — staged into
            /usr/share/fonts/truetype for fontconfig-based consumers.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/ryanoasis/nerd-fonts/releases/download/v3.5.1/Hack.tar.xz",
            sha256 = "cdd389472e10e2261520140ff1b382b4f8a226af5fd0b2735b975d31151d9c3c",
        },

        build = "mkdir -p $STAGE/usr/share/fonts/truetype/nerd-fonts-hack && cp $SRC/*.ttf $SRC/LICENSE.md $STAGE/usr/share/fonts/truetype/nerd-fonts-hack/",

        type = "source",
        requires = {},
    },
}
