-- xxd: hex dumper that produces (and restores) hexadecimal dumps of
-- files, shipped with vim.
--
-- Ported from the devbox global profile as a source build: the vim
-- 9.0.0609 tag tarball (the upstream xxd source lives in vim's tree —
-- same artifact nixpkgs' xxd builds) is fetched, sha256-pinned, and
-- only the standalone xxd subdirectory is compiled via its own
-- Makefile in the build sandbox. The build runs at the tarball's
-- STRIPPED root (find_source_root): paths are relative to it.

return {
    default = snap {
        name = "xxd",
        version = "9.0.0609",
        summary = "Hex dumper from the vim project",
        description = [[
            xxd creates a hex dump of a file or standard input, and can
            convert a hex dump back to the original binary form (-r).
            Commonly used in pipelines and forensics; ships the exact
            xxd source from the vim repository at tag v9.0.0609.
        ]],
        license = "Vim",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/vim/vim/archive/refs/tags/v9.0.0609.tar.gz",
            sha256 = "3cbb87c5bfd773b295ed16841777c65441d9533f2b24a74a256e21fa3eda3944",
        },

        build = table.concat({
            "make -C src/xxd -f Makefile",
            "install -Dm755 src/xxd/xxd $STAGE/usr/bin/xxd",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            xxd = app {
                command = "usr/bin/xxd",
            },
        },
    },
}
