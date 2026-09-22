-- neovim: Vim-fork text editor (neovim/neovim).
--
-- Ported from devbox-global's devbox.d/neovim flake — with the flake's
-- nightly CHANNEL parity: the flake builds FROM SOURCE through
-- neovim-nightly-overlay (a nightly-channel Nix build of the C tree
-- plus wrapNeovim scaffolding); a from-source build here would
-- re-bootstrap that whole toolchain for no payoff. Pool strategy is
-- upstream's official PREBUILT release tarball from the `nightly`
-- tag, declared floating (`floating = true`): the tarball moves with
-- every upstream push, and sync re-resolves it the same way
-- hermes-agent re-resolves its release.
--
-- Why nightly, not the newest stable (v0.12.5): the 0.12 line dropped
-- the `vim.uri` Lua module; current plugin pins still reach it from
-- init and crash before the first frame (nvim-lspconfig 2026-08 pin,
-- E5113 at vim/_init_packages). The 0.13-dev tree restored it; the
-- user config that ran on the flake's nightly boots clean on it. The
-- earlier "pool packages pin releases, never moving tags" reading is
-- superseded here by the hermes-agent precedent: floating pins ARE a
-- pool mechanism, and TOFU moves from release-time to sync-time.
--
-- Asset naming: `nvim-linux-x86_64.tar.gz` (the pre-0.11
-- `nvim-linux-x64.tar.gz` pattern 404s on 0.11+). Release asset =
-- upstream's byte-stable upload per push; sha256 pinned at port time,
-- re-hashed by sync under the float. The flake has no tarball hash to
-- cross-check (its SRI covers the source build), so TOFU via
-- shuttle.lock is the pin story, same as every prebuilt port whose
-- flake builds from source.
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
        version = "0.13.0-nightly",
        summary = "Ambitious Vim-fork text editor, official nightly prebuilt",
        description = [[
            Neovim is a hyperextensible Vim-based text editor with
            built-in LSP client, treesitter highlighting, and Lua
            scripting. Ships the official linux-x86_64 nightly build
            (self-contained: bundled luajit, treesitter parsers, and
            runtime), with vi/vim/vimdiff compatibility wrappers as the
            flake's aliases provided. Floating pin: sync re-resolves the
            nightly tag.
        ]],
        license = "Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        floating = true,

        source = {
            url = "https://github.com/neovim/neovim/releases/download/nightly/nvim-linux-x86_64.tar.gz",
            sha256 = "971e0541910bfde3d9d22d44bfa3651ae4b9dc005b9484208994c43a775275eb",
        },

        -- Single-source flatten lands the tarball root's contents
        -- (bin/ lib/ share/) at $SRC; relayout into the /usr prefix.
        -- bin/ carries only the nvim ELF (no symlinks to dereference).
        --
        -- Farm app assemblies carry only the command's usr/bin subtree
        -- (issue #37 siblings), so nvim's own runtime discovery
        -- (bin/../share/nvim) finds nothing there and $VIMRUNTIME
        -- collapses to the nonexistent compile-time default — every
        -- `require('vim.*')` beyond the embedded bootstrap dies
        -- (vim.uri E5113). The treesitter parsers ride along by
        -- relocation into the runtime (rtp-relative parser search), and
        -- bin/nvim becomes a wrapper pinning VIMRUNTIME: first the
        -- payload layout (sandbox/store), then the generation's
        -- extension tree (usr/usr doubling is load-bearing, §5.7).
        build = table.concat({
            "mkdir -p $STAGE/usr",
            "cp -r bin lib share $STAGE/usr/",
            "cp -r lib/nvim/parser share/nvim/runtime/parser",
            "mv $STAGE/usr/bin/nvim $STAGE/usr/bin/nvim.bin",
            "printf '%s\\n' '#!/bin/sh' 'd=$(dirname \"$(readlink -f \"$0\")\")' 'r=$d/../../share/nvim/runtime' 'if test ! -d \"$r\"' 'then r=$d/../../../../extensions/neovim/usr/usr/share/nvim/runtime' 'fi' 'r=$(readlink -f \"$r\")' 'VIMRUNTIME=$r exec \"$d/nvim.bin\" \"$@\"' > $STAGE/usr/bin/nvim",
            "chmod +x $STAGE/usr/bin/nvim",
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
