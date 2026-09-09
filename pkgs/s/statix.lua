-- statix: lints and anti-patterns for the Nix language.
--
-- Pool port for the small-tools lane (issue #23), unblocked by the
-- cargo resolver (issue #36, ADR-0017 extension): the Rust dependency
-- closure resolves from upstream's Cargo.lock (89 registry crates),
-- fetched as
-- checksum-verified `.crate` downloads from crates.io at FETCH time
-- (outside the sandbox, which stays net-unshared), extracted into a
-- `cargo vendor`-equivalent tree, and stored as one content-addressed
-- pod-store blob. The sandbox build consumes it OFFLINE: a source
-- replacement config points cargo at the mounted `$SHUTTLE_DEPS_DIR`
-- vendor tree and `CARGO_NET_OFFLINE=true` makes hermeticity explicit.
--
-- build_deps: none — cargo/rustc resolve from the host toolchain
-- through the /nix bind (the pool-wide source-build posture). The pool
-- `rust` package (issue #24) is the declared end state, but payloads
-- built through the pod path carry store-exec launcher wrappers
-- (issue #12 repair) that cannot execute from a merged build prefix —
-- flipping to build_deps = { "rust" } waits on that ADR-0018 gap.

return {
    default = snap {
        name = "statix",
        version = "0.5.8",
        summary = "Lints and suggestions for the Nix programming language",
        description = [[
            statix checks Nix code for common anti-patterns and
            reports them with suggestions; `statix check` lints,
            `statix fix` applies safe rewrites. Rust crate, source
            build via cargo against the vendored deps closure
            (deps.cargo, issue #36).
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/nerdypepper/statix/archive/refs/tags/v0.5.8.tar.gz",
            sha256 = "547ee83df5814c18f8577b5ca25a1f12a416900b6eaa95821386a28090e8a89d",
        },

        deps = {
            cargo = { lock = "Cargo.lock" },
        },

        build = table.concat({
            -- Cargo offline wiring (issue #36): a writable CARGO_HOME on
            -- the sandbox's /tmp tmpfs plus a source replacement pointing
            -- at the mounted, hash-verified vendor closure.
            "export CARGO_HOME=/tmp/shuttle-cargo-home CARGO_NET_OFFLINE=true",
            "mkdir -p \"$CARGO_HOME\"",
            "printf '[source.crates-io]\\nreplace-with = \"shuttle-vendored\"\\n\\n[source.shuttle-vendored]\\ndirectory = \"%s\"\\n' \"$SHUTTLE_DEPS_DIR/vendor\" > \"$CARGO_HOME/config.toml\"",
            -- statix is a virtual workspace (root Cargo.toml carries only
            -- [workspace]); the installable package is the bin/ member.
            "cargo install --path $SRC/bin --root $STAGE",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            statix = app {
                command = "bin/statix",
            },
        },
    },
}
