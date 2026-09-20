-- pdf-inspector: PDF classification, text extraction, Markdown
-- conversion (firecrawl/pdf-inspector; bins pdf2md / detect-pdf /
-- dump_ops).
--
-- Ported from devbox-global's devbox.d/pdf-inspector flake: a
-- buildRustPackage source build of the v1.20.0 release tag whose
-- postPatch COPIES A LOCALLY AUTHORED Cargo.lock into the source tree,
-- because upstream does not commit one at the repo root (the napi/ and
-- wasm/ subcrate locks ship, but the root crate's does not; v1.20.0's
-- release page also carries no prebuilt assets). The port follows the
-- statix.lua template: deps.cargo vendors the registry closure the lock
-- pins into a content-addressed store blob at FETCH time, and the
-- sandbox build consumes it OFFLINE (CARGO_NET_OFFLINE + source
-- replacement at the mounted $SHUTTLE_DEPS_DIR/vendor).
--
-- KNOWN GAP (reported in the porting dossier): deps.cargo reads its
-- lockfile from the fetched SOURCE tree (dep_fetch.rs resolves
-- `lock` relative to the source root; there is no fetch-time hook to
-- inject the flake's locally authored file), and the DSL has no second
-- artifact slot that could carry it — so v1.20.0 as published cannot
-- resolve its closure and the deps fetch will fail at the missing
-- Cargo.lock. Everything else here is exact. Cleanest fixes, in order:
-- (a) upstream PR committing a root Cargo.lock at the pinned tag/next
-- release (the flake proves the lock is stable to generate), after
-- which this declaration builds as-is; (b) a DSL hook to seed the lock
-- at deps-fetch time (mirroring the flake's postPatch). A fork rev is
-- deliberately NOT pinned — pool rules pin what the flake pins.
--
-- requires = { glibc }: pure Rust CLI over the glibc family (no C
-- deps; the flake declares no buildInputs).
--
-- build_deps: none — cargo/rustc resolve from the host toolchain
-- through the /nix bind (pool-wide source-build posture, statix.lua).
-- The tarball's rust-toolchain.toml (1.98 pin) is a rustup directive;
-- the non-rustup pool cargo ignores it.

return {
    default = snap {
        name = "pdf-inspector",
        version = "1.20.0",
        summary = "Fast PDF classification, text extraction, and Markdown conversion",
        description = [[
            pdf-inspector detects whether a PDF is scanned or
            text-based, extracts text with font/encoding awareness, and
            converts PDFs to Markdown (`pdf2md`), plus `detect-pdf` and
            `dump_ops` inspection tools. Rust crate built from the
            v1.20.0 tag against the vendored cargo dependency closure
            (deps.cargo); NOTE: blocked until a root Cargo.lock is
            resolvable — see the port header in the package definition.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/firecrawl/pdf-inspector/archive/refs/tags/v1.20.0.tar.gz",
            -- Codeload tarball hash, computed locally. NOT comparable to
            -- the flake's SRI: fetchFromGitHub hashes nix's own
            -- normalized tree archive, GitHub's archive endpoint
            -- re-gzips — different bytes, same tree (statix.lua
            -- precedent). Content pinning rides shuttle.lock TOFU.
            sha256 = "3bb2229e6b39ada3646a68debecb50bf91c53883b075070ad3705839c37aace1",
        },

        deps = {
            cargo = { lock = "Cargo.lock" },
        },

        build = table.concat({
            -- Cargo offline wiring (issue #36), statix.lua verbatim: a
            -- writable CARGO_HOME on the sandbox's /tmp tmpfs plus a
            -- source replacement pointing at the mounted, hash-verified
            -- vendor closure.
            "export CARGO_HOME=/tmp/shuttle-cargo-home CARGO_NET_OFFLINE=true",
            "mkdir -p \"$CARGO_HOME\"",
            "printf '[source.crates-io]\\nreplace-with = \"shuttle-vendored\"\\n\\n[source.shuttle-vendored]\\ndirectory = \"%s\"\\n' \"$SHUTTLE_DEPS_DIR/vendor\" > \"$CARGO_HOME/config.toml\"",
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
