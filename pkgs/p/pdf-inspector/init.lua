-- pdf-inspector: PDF classification, text extraction, Markdown
-- conversion (firecrawl/pdf-inspector; bins pdf2md / detect-pdf /
-- dump_ops).
--
-- Ported from devbox-global's devbox.d/pdf-inspector flake: a
-- buildRustPackage source build of the release tag whose postPatch
-- COPIES A LOCALLY AUTHORED Cargo.lock into the source tree, because
-- upstream does not commit one at the repo root (re-verified
-- 2026-09-21 via the GitHub contents API at ref v1.22.1: no root
-- Cargo.lock; the napi/ and wasm/ subcrate locks ship, the root
-- crate's does not). The flake's postPatch trick is realized here via
-- the recipe-local lock: the package is declared in directory form and
-- deps.cargo.lock = "recipe/Cargo.lock" resolves against the recipe
-- directory (the file sits next to this init.lua), so the deps fetch
-- reads the locally authored lock instead of the source tree's absent
-- one. The lock is REGENERATED FROM THE PINNED TAG on host cargo when
-- bumping: extract the tag tarball, run `cargo generate-lockfile` in
-- it, commit the result. Regeneration uses default features — at this
-- version `ocr` is opt-in (`default = []`), matching the flake.
--
-- The port follows the statix.lua template: deps.cargo vendors the
-- registry closure the lock pins into a content-addressed store blob
-- at FETCH time, and the sandbox build consumes it OFFLINE
-- (CARGO_NET_OFFLINE + source replacement at the mounted
-- $SHUTTLE_DEPS_DIR/vendor).
--
-- requires = { glibc }: pure Rust CLI over the glibc family (no C
-- deps; the flake declares no buildInputs).
--
-- build_deps: none — cargo/rustc resolve from the host toolchain
-- through the /nix bind (pool-wide source-build posture, statix.lua).
-- The tarball's rust-toolchain.toml (1.98 pin) is a rustup directive;
-- the non-rustup pool cargo ignores it (crate MSRV is 1.88).

return {
    default = snap {
        name = "pdf-inspector",
        version = "1.22.1",
        summary = "Fast PDF classification, text extraction, and Markdown conversion",
        description = [[
            pdf-inspector detects whether a PDF is scanned or
            text-based, extracts text with font/encoding awareness, and
            converts PDFs to Markdown (`pdf2md`), plus `detect-pdf` and
            `dump_ops` inspection tools. Rust crate built from the
            v1.22.1 tag against the vendored cargo dependency closure
            (deps.cargo), with the recipe-local Cargo.lock standing in
            for the lock upstream does not commit.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/firecrawl/pdf-inspector/archive/refs/tags/v1.22.1.tar.gz",
            -- Codeload tarball hash, computed locally. NOT comparable to
            -- the flake's SRI: fetchFromGitHub hashes nix's own
            -- normalized tree archive, GitHub's archive endpoint
            -- re-gzips — different bytes, same tree (statix.lua
            -- precedent). Content pinning rides shuttle.lock TOFU.
            sha256 = "2e6d2d2435ae052e3ca753d12a973e341b5f4f5ba65a12e47995b9d6bcbaa0ca",
        },

        deps = {
            cargo = { lock = "recipe/Cargo.lock" },
        },

        build = table.concat({
            -- Cargo offline wiring (issue #36), statix.lua verbatim: a
            -- writable CARGO_HOME on the sandbox's /tmp tmpfs plus a
            -- source replacement pointing at the mounted, hash-verified
            -- vendor closure.
            "export CARGO_HOME=/tmp/shuttle-cargo-home CARGO_NET_OFFLINE=true",
            'mkdir -p "$CARGO_HOME"',
            'printf \'[source.crates-io]\\nreplace-with = "shuttle-vendored"\\n\\n[source.shuttle-vendored]\\ndirectory = "%s"\\n\' "$SHUTTLE_DEPS_DIR/vendor" > "$CARGO_HOME/config.toml"',
            -- Root crate carries the lib + all three bins; cargo
            -- install lays them out under $STAGE/bin.
            "cargo install --path $SRC --root $STAGE",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            pdf2md = app {
                command = "bin/pdf2md",
            },
            ["detect-pdf"] = app {
                command = "bin/detect-pdf",
            },
            dump_ops = app {
                command = "bin/dump_ops",
            },
        },
    },
}
