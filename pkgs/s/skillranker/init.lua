-- skillranker (sr): session-specific skill advice powered by TypeSafe.ai Jev.
--
-- Pool port (issue #206) of devbox-global devbox.d/skillranker @
-- 3fe85c432ba5e2b4f980e842fc94d57fae6c4189 (mirror-don't-bump: bump the
-- source pins, the recipe-local Cargo.lock.pathdeps, and this comment
-- rev together — the flake's own discipline).
--
-- Tier: Rust source build over the cargo dep-fetch resolver (ADR-0017).
-- Upstream has NO release artifacts; the flake builds rev-pinned source
-- via rust-overlay's nightly. Three pinned source inputs ride the
-- `sources` map (anydoc/agentmemory pattern): skillranker at $SRC/sr,
-- the frankensearch git workspace at $SRC/frankensearch, asupersync at
-- $SRC/asupersync (the [patch.crates-io] redirect target).
--
-- Git deps → path deps, exactly the flake's prePatch: frankensearch's
-- workspace is not parseable from a clean checkout (the tools/
-- optimize_params member path-deps on ../../../fast_cmaes, a sibling
-- repo outside the tree — not part of skillranker's graph, dropped),
-- and nixpkgs-style lockfile rewriting can't vendor git workspaces
-- anyway. The build seds the three git specifiers to vendor-git/ paths
-- inside the source tree and strips the git `source` lines from the
-- source Cargo.lock, keeping it byte-consistent with the vendored
-- registry closure. The DEP FETCH consumes the RECIPE-LOCAL
-- Cargo.lock.pathdeps (same bytes as the flake carries, git sources
-- already stripped): the cargo resolver skips path/workspace members
-- (no `source`) and would reject git deps, so the pathdeps variant is
-- exactly the lockfile shape the registry fetch needs; every downloaded
-- .crate verifies against the lockfile checksum before extraction.
--
-- Toolchain decision (issue #206 asks this be recorded): the pool's
-- STABLE rust 1.97.1 (build_dep), not a nightly. Upstream pins
-- nightly-2026-08-31 in rust-toolchain.toml, but that file is a RUSTUP
-- selector — inert under the pool's non-rustup cargo — and the flake's
-- stated justification (stable ≤1.98 rejecting frankensearch's
-- default-features=false workspace inheritance) does not reproduce on
-- the pin: the sed-rewritten tree builds clean under stable
-- cargo 1.97 (empirically verified 2026-09-25, release profile, 6m29s,
-- frankensearch-core/quill path deps compiled). No nightly pool package
-- exists and ADR-0018 wants explicit declared toolchains, not a second
-- toolchain payload for one consumer.
--
-- build_deps: gcc (cc crate: blake3's SSE4.1/AVX .c objects; rusqlite
-- bundled sqlite3.c) + rust. No zlib: ldd on the verified build shows
-- only libgcc_s + glibc (no libz, no libstdc++).
--
-- requires: glibc + libgcc — exactly the ldd set above.
--
-- Upstream's test suite drives harness/session fixtures and is not
-- hermetic in the offline sandbox (the flake sets doCheck = false for
-- the same reason); the pool build runs no test phase either.

return {
    default = snap {
        name = "skillranker",
        version = "0.1.0-main-3fe85c4",
        summary = "Session-specific skill advice powered by TypeSafe.ai Jev",
        description = [[
            skillranker (`sr`) ranks the skills available to a coding
            agent session and returns session-specific advice, scoring
            candidates with TypeSafe.ai Jev typed judgments over a
            frankensearch-backed index. Rust source build of the pinned
            upstream rev through the pool's cargo dep-fetch path.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        sources = {
            sr = {
                url = "https://codeload.github.com/Dicklesworthstone/skillranker/tar.gz/3fe85c432ba5e2b4f980e842fc94d57fae6c4189",
                sha256 = "76627113e8de709562214bddf81ede1c4c0ffff290b0dd86adc454cf211266d6",
            },
            frankensearch = {
                url = "https://codeload.github.com/Dicklesworthstone/frankensearch/tar.gz/39047c44c3a92ceb71d25c602913b8b2888e2fe7",
                sha256 = "87b3651c609a5407abfd10e9af5ea3d9b7caf03d484ac2786cdc92825110ea77",
            },
            asupersync = {
                url = "https://codeload.github.com/Dicklesworthstone/asupersync/tar.gz/81fb7b579ce5f161622f1524391f5202a641cc2e",
                sha256 = "f23a4fa3bbd1a84a0c8324990b80e53eb4aa4783a39fd116f11b35b5d1fff3e5",
            },
        },

        -- Registry-only closure from the recipe-local pathdeps lockfile:
        -- the git workspaces ship as source inputs and become path deps
        -- in the build (above); everything else is checksum-verified
        -- crates.io content fetched into the vendored closure.
        deps = {
            cargo = { lock = "recipe/Cargo.lock.pathdeps" },
        },

        build = table.concat({
            -- Git deps → vendored path deps (the flake's prePatch,
            -- $SRC is writable inside the sandbox). frankensearch first
            -- drops its out-of-tree fast_cmaes member, else the
            -- workspace does not parse.
            "cd $SRC/sr",
            "mkdir -p vendor-git",
            "cp -a $SRC/frankensearch vendor-git/frankensearch",
            "cp -a $SRC/asupersync vendor-git/asupersync",
            'sed -i \'\\|"tools/optimize_params",|d\' vendor-git/frankensearch/Cargo.toml',
            "sed -E -i "
                .. "-e 's#frankensearch-(core|quill|index) = \\{ git = \"[^\"]+\", rev = \"[^\"]+\"#frankensearch-\\1 = { path = \"vendor-git/frankensearch/crates/frankensearch-\\1\"#' "
                .. "-e 's#asupersync = \\{ git = \"[^\"]+\", rev = \"[^\"]+\"#asupersync = { path = \"vendor-git/asupersync\"#' "
                .. "Cargo.toml",
            "sed -i '/source = \"git+/d' Cargo.lock",
            -- Cargo offline wiring (statix pattern, issue #36): writable
            -- CARGO_HOME on the sandbox /tmp tmpfs, source replacement
            -- pointing at the mounted, hash-verified vendor closure.
            "export CARGO_HOME=/tmp/shuttle-cargo-home CARGO_NET_OFFLINE=true",
            'mkdir -p "$CARGO_HOME"',
            'printf \'[source.crates-io]\\nreplace-with = "shuttle-vendored"\\n\\n[source.shuttle-vendored]\\ndirectory = "%s"\\n\' "$SHUTTLE_DEPS_DIR/vendor" > "$CARGO_HOME/config.toml"',
            -- Root package carries the sr bin ([[bin]] in the root
            -- Cargo.toml); --root $STAGE lands it at $STAGE/bin/sr.
            'cargo install --path . --root "$STAGE"',
        }, " && "),

        type = "source",
        requires = { "glibc", "libgcc" },
        build_deps = { "gcc", "rust" },

        apps = {
            sr = app {
                command = "bin/sr",
            },
        },
    },
}
