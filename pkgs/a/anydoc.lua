-- anydoc: document → GitHub-Flavored Markdown converter (firecrawl/anydoc).
--
-- Ported from devbox-global's devbox.d/anydoc flake: upstream ships the
-- CLI as the @firecrawl/anydoc npm package wrapping a prebuilt napi-rs
-- native module (Rust cdylib, glibc-linked). The flake is a stdenvNoCC
-- relayout of TWO registry tarballs — the main package plus the
-- @firecrawl/anydoc-linux-x64-gnu addon — with the addon .node dropped
-- into the package dir (the napi loader in index.js tries the local
-- ./anydoc.linux-x64-gnu.node before the platform npm package).
--
-- The two-tarball constraint resolves through the `sources` map (issue
-- #41): main lands at $SRC/main, the addon at $SRC/addon (both npm
-- `package/` top dirs flatten). Both sha256s cross-check against the
-- flake's fetchurl SRIs (base64→hex match, verified).
--
-- Runtime deps, from ldd + the flake: the .node cdylib needs glibc +
-- libgcc_s.so.1 only — no libstdc++ (Rust cdylibs link the panic runtime
-- in; the flake's stdenv.cc.cc.lib buildInput fed autoPatchelf's search
-- path, same as bun.lua's zlib note). The JS payload is self-contained
-- (the flake installs NO node_modules at all), but it must run from its
-- package dir — cli.js resolves its sibling index.js/anydoc.js and the
-- .node relative to __dirname — so the app is declared the zg.lua way:
-- command = the in-payload cli.js, interpreter = "node" (issue #9/#13).
-- The tree wrapper execs node on the cli.js's extension-tree path — the
-- only runtime-correct shape; a farm blob path strands the __dirname
-- derivation and a hand-rolled sh launcher is never tree-routed (sh
-- shebangs are host-guaranteed, so the emitter copies them verbatim —
-- found live on the daily pod 2026-09-18). `node` in requires covers
-- the interpreter; glibc covers node itself.
--
-- build_deps: (none).

return {
    default = snap {
        name = "anydoc",
        version = "0.2.4",
        summary = "Convert Word, PowerPoint, Excel, ODT, RTF, EPUB, CSV, PDF to Markdown",
        description = [[
            anydoc converts documents (doc, docx, odt, pdf, ppt, pptx,
            rtf, epub, xlsx, ods, odp, csv) to GitHub-Flavored
            Markdown. Ships the npm-published CLI with its prebuilt
            napi-rs Rust core (linux-x64-gnu addon) staged in place, as
            the napi loader expects.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        sources = {
            main = {
                url = "https://registry.npmjs.org/@firecrawl/anydoc/-/anydoc-0.2.4.tgz",
                sha256 = "625bf6cdc24cc91eee8fbfe084c1fa56c71b17f034341d4a23bc8df0fdee31bd",
            },
            addon = {
                url = "https://registry.npmjs.org/@firecrawl/anydoc-linux-x64-gnu/-/anydoc-linux-x64-gnu-0.2.4.tgz",
                sha256 = "ca822ea3ad29a9b9ca6b7f6d2a6b3d5311153af25a6c35a7f5bdf0791fe7f2c9",
            },
        },

        -- The flake's unpackPhase + installPhase verbatim: package dir
        -- at lib/node_modules/@firecrawl/anydoc, addon .node (+ its
        -- package.json, which the flake also extracts) beside it, and
        -- the makeWrapper translated to a self-locating sh launcher.
        build = table.concat({
            "pkg=$STAGE/usr/lib/node_modules/@firecrawl/anydoc",
            'mkdir -p "$pkg"',
            'cp -r $SRC/main/. "$pkg/"',
            'cp $SRC/addon/anydoc.linux-x64-gnu.node $SRC/addon/package.json "$pkg/"',
        }, " && "),

        type = "source",
        requires = { "glibc", "node", "libgcc" },

        apps = {
            anydoc = app {
                command = "usr/lib/node_modules/@firecrawl/anydoc/cli.js",
                interpreter = "node",
            },
        },
    },
}
