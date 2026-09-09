-- statix: lints and anti-patterns for the Nix language.
--
-- Pool port attempt for the small-tools lane (issue #23). Rust crate
-- built in-sandbox with the cargo plugin: the plugin moves the
-- toolchain to build_deps (ADR-0018 Decision 5, issue #26) — the host
-- rust toolchain resolves inside the sandbox through the /nix bind,
-- and toolchain-gcc-gnu-x86_64 provides the linker.
--
-- NOTE (blocked): the hermetic sandbox unshares the network and
-- clears the environment, so cargo cannot reach crates.io for the
-- crate's dependencies (no HOME/CARGO_HOME either — cargo fails to
-- find its home before any fetch attempt). A source build needs a
-- vendored-deps mechanism (cargo vendor staged into the source, or a
-- deps.cargo resolver mirroring deps.pip/deps.npm); statix publishes
-- no prebuilt release binaries to fall back on. Kept here as the
-- record of the intended declaration; the build fails with
-- "error: could not find Cargo home".
--
-- Requires: glibc
-- build_deps: (via cargo plugin) toolchain-gcc-gnu-x86_64

return {
    default = snap {
        name = "statix",
        version = "0.5.8",
        summary = "Lints and suggestions for the Nix programming language",
        description = [[
            statix checks Nix code for common anti-patterns and
            reports them with suggestions; `statix check` lints, 
            `statix fix` applies safe rewrites. Rust crate, source
            build via the cargo plugin.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/nerdypepper/statix/archive/refs/tags/v0.5.8.tar.gz",
            sha256 = "547ee83df5814c18f8577b5ca25a1f12a416900b6eaa95821386a28090e8a89d",
        },

        parts = {
            statix = {
                plugin = "cargo",
            },
        },

        type = "source",
        requires = { "glibc" },

        apps = {
            statix = app {
                command = "bin/statix",
            },
        },
    },
}
