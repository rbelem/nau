-- toolchain-rust-probe: build_deps consumer probe for the pool rust
-- toolchain package (ticket #24).
--
-- Not a pool package — a fixture proving the dual-use contract: a
-- package that lists `rust` in build_deps gets cargo/rustc/clippy/
-- rustfmt merged into its build prefix (usr/bin leads the sandbox
-- PATH), so the build script can invoke them by bare name inside the
-- hermetic sandbox.
--
-- Build:
--   shuttle build --file test-fixtures/toolchain-rust-probe.lua

return {
    default = snap {
        name = "toolchain-rust-probe",
        version = "0.1.0",
        summary = "Probe: consumes pool rust as a build_dep",
        description = [[
            Empty-payload probe whose build script runs `cargo --version`
            and `rustc --version` inside the sandbox. Green build = the
            rust toolchain package is consumable via build_deps.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",

        -- The harness requires a fetchable source whenever `build` is
        -- set; the probe stages nothing from it. Reuse the smallest
        -- already-pinned pool tarball (dcg, from pkgs/d/dcg.lua).
        source = {
            url = "https://github.com/Dicklesworthstone/destructive_command_guard/releases/download/v0.14.1/dcg-x86_64-unknown-linux-musl.tar.xz",
            sha256 = "e7b39be070ad98f74a1edd59fefb8ac41865ab2aa2c5a4252eb71c5413f3f9df",
        },

        build_deps = { "rust" },

        -- Plain word/redirect commands only: the sandbox preflight
        -- parses command words, and $() nesting confuses it. cargo
        -- refuses to run without HOME (rustc doesn't care).
        build = table.concat({
            "HOME=/tmp cargo --version > cargo-version.txt",
            "rustc --version > rustc-version.txt",
            "grep -q '^cargo 1.98.1' cargo-version.txt",
            "grep -q '^rustc 1.98.1' rustc-version.txt",
            "cat cargo-version.txt rustc-version.txt",
        }, " && "),
    },
}
