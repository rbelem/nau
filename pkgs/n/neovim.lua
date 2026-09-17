-- neovim: Vim-fork text editor (neovim/neovim).
--
-- Ported from devbox-global's devbox.d/neovim flake — with one deliberate
-- substitution, per the porting dossier: the flake builds FROM SOURCE
-- through neovim-nightly-overlay (a nightly-channel Nix build of the C
-- tree plus wrapNeovim scaffolding); a from-source build here would
-- re-bootstrap that whole toolchain for no payoff. Pool strategy is
-- upstream's official PREBUILT release tarball instead, pinned to the
-- newest STABLE tag v0.12.5 (the repo's `stable` alias points here;
-- `nightly` is excluded by construction). Version delta vs the flake
-- (nightly channel) is accepted: pool packages pin releases, never
-- moving tags.
--
-- Asset naming changed at v0.11+: `nvim-linux-x86_64.tar.gz` (the
-- pre-0.11 `nvim-linux-x64.tar.gz` pattern 404s on this tag). Release
-- asset = byte-stable upload, sha256 computed locally; the flake has no
-- tarball hash to cross-check (its SRI covers the source build), so
-- TOFU via shuttle.lock is the pin story, same as every prebuilt port
-- whose flake builds from source.
--
-- Runtime deps (ldd on bin/nvim): glibc family + libgcc_s.so.1 only —
-- libluv/luajit/treesitter parsers ship inside the tarball (lib/),
-- ncurses is NOT linked (nvim's TUI reads the host terminfo db). Hence
-- requires = { glibc, libgcc }; pool libgcc provides libgcc_s.so.1.
--
-- Flake deltas noted, not ported: wrapNeovim's viAlias/vimAlias/vimdiff
-- are reproduced as tiny sh wrappers (the pack stage's fs::copy
-- dereferences symlinks, and the interpreter-wrapper pass follows them —
-- bun.lua note). withNodeJs/withPython3/withRuby are optional runtime
-- PROVIDERS (nvim shells out to them only when a config uses them); they
-- resolve from the user's PATH and are not requires. extraLuaPackages
-- lpeg is not bundled by upstream's tarball; configs needing it install
-- it per-user (rocks/packer), as outside the flake.
--
-- build_deps: (none) — plain tar, no zip.

return {
    default = snap {
        name = "neovim",
        version = "0.12.5",
        summary = "Ambitious Vim-fork text editor, official stable prebuilt",
        description = [[
            Neovim is a hyperextensible Vim-based text editor with
            built-in LSP client, treesitter highlighting, and Lua
            scripting. Ships the official linux-x86_64 release build of
            the stable v0.12.5 tag (self-contained: bundled luajit,
            treesitter parsers, and runtime), with vi/vim/vimdiff
            compatibility wrappers as the flake's aliases provided.
        ]],
        license = "Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/neovim/neovim/releases/download/v0.12.5/nvim-linux-x86_64.tar.gz",
            sha256 = "bce0f56eda1f1b1db6eee8f4133d7a38813ea07933837dd1777411ca384c6875",
        },

        -- Single-source flatten lands the tarball root's contents
        -- (bin/ lib/ share/) at $SRC; relayout into the /usr prefix.
        -- bin/ carries only the nvim ELF (no symlinks to dereference).
        build = table.concat({
            "mkdir -p $STAGE/usr",
            "cp -r bin lib share $STAGE/usr/",
            -- viAlias/vimAlias/vimdiff from the flake: sibling-relative
            -- sh wrappers, not symlinks (they would dereference).
            "printf '%s\\n' '#!/bin/sh' 'exec \"$(dirname \"$0\")/nvim\" \"$@\"' > $STAGE/usr/bin/vi",
            "printf '%s\\n' '#!/bin/sh' 'exec \"$(dirname \"$0\")/nvim\" \"$@\"' > $STAGE/usr/bin/vim",
            "printf '%s\\n' '#!/bin/sh' 'exec \"$(dirname \"$0\")/nvim\" -d \"$@\"' > $STAGE/usr/bin/vimdiff",
            "chmod +x $STAGE/usr/bin/vi $STAGE/usr/bin/vim $STAGE/usr/bin/vimdiff",
        }, " && "),

        type = "source",
        requires = { "glibc", "libgcc" },

        apps = {
            nvim = app {
                command = "usr/bin/nvim",
            },
            vi = app {
                command = "usr/bin/vi",
            },
            vim = app {
                command = "usr/bin/vim",
            },
            vimdiff = app {
                command = "usr/bin/vimdiff",
            },
        },
    },
}
