-- jcode: coding agent harness — blazing-fast TUI, multi-model, swarm
-- coordination (1jehuang/jcode).
--
-- Medium-tier flake port survey (issue #25): the flake is a prebuilt
-- release fetch, not a source build — ported as a release-fetch
-- package in the #20 pattern (the cheap-tier batch missed this one).
-- The upstream linux-x86_64 release tarball is fetched, sha256-pinned
-- (digest cross-checked against the flake pin), and staged into
-- usr/bin.
--
-- Layout note (mirrors the flake): the tarball ships a sh launcher
-- (`jcode-linux-x86_64`) plus the real ELF (`jcode-linux-x86_64.bin`);
-- the launcher readlink-resolves itself, prepends its own directory to
-- LD_LIBRARY_PATH, and execs the .bin — so both keep their original
-- suffixed names side by side. The flake's `jcode` convenience symlink
-- is staged as a tiny sh wrapper instead: the pack step's stage copy
-- dereferences symlinks (fs::copy), which would materialize a full
-- second copy of the payload.
--
-- Runtime deps (ldd of the .bin): the glibc family plus libgcc_s.so.1
-- — no libstdc++ (the flake's stdenv.cc.cc.lib buildInput only fed
-- autoPatchelf's search path). NOTE: pool libgcc lands with the #34
-- lane — merge order libgcc → jcode, or resolution of this package
-- fails on a tree without it (same pattern as rust.lua's libgcc note).
--
-- Known caveat (farm/run layout): lone-blob execution strands the
-- launcher/.bin sibling pair — same class as pi's theme siblings and
-- gcm's libSkiaSharp.so; waits on a farm/run tree-assembly fix.

return {
    default = snap {
        name = "jcode",
        version = "0.61.1",
        summary = "Coding agent harness with fast TUI and swarm coordination",
        description = [[
            jcode is a coding agent harness: a fast terminal TUI,
            multi-model routing, and swarm coordination for parallel
            agent work. Ships as the self-contained upstream release
            (sh launcher + ELF binary); LLM credentials come from the
            environment at run time.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/1jehuang/jcode/releases/download/v0.61.1/jcode-linux-x86_64.tar.gz",
            sha256 = "0ccaa2338887b18c3da76b9f3cd84e7d3a762bda691e71df83440190f4825da0",
        },

        -- Flat tarball root: launcher + .bin at the source root.
        build = table.concat({
            "install -Dm755 jcode-linux-x86_64 $STAGE/usr/bin/jcode-linux-x86_64",
            "install -Dm755 jcode-linux-x86_64.bin $STAGE/usr/bin/jcode-linux-x86_64.bin",
            "printf '%s\\n' '#!/bin/sh' 'exec \"$(dirname \"$0\")/jcode-linux-x86_64\" \"$@\"' > $STAGE/usr/bin/jcode",
            "chmod +x $STAGE/usr/bin/jcode",
        }, " && "),

        type = "source",
        requires = { "glibc", "libgcc" },

        apps = {
            jcode = app {
                command = "usr/bin/jcode",
            },
        },
    },
}
