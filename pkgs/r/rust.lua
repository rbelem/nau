-- rust: The Rust toolchain — cargo, rustc, std, clippy, rustfmt.
--
-- Ticket #24 — pool toolchain package, dual-use: pod-installable for
-- daily use AND consumable as a build_dep by other packages (the merged
-- build prefix puts usr/bin first on the sandbox PATH, so bare
-- `cargo`/`rustc` resolve inside a consumer's hermetic build).
--
-- Port strategy — FETCH, not source bootstrap: the pool cargo plugin
-- (plugins.rs) only ASSUMES a rust toolchain — it pins
-- toolchain-gcc-gnu-x86_64 as its build_dep for the C linker/toolchain
-- side, and no rust package existed in pkgs/. This is that missing
-- toolchain, from the official static.rust-lang.org dist tarball for
-- x86_64-unknown-linux-gnu (the same artifact rustup installs), digest
-- taken from the signed channel-rust-stable.toml manifest
-- (xz_hash). Bootstrap from source is a multi-hour self-build with no
-- payoff: the dist tarball IS the reference toolchain.
--
-- Components merged into the classic prefix layout, exactly what the
-- tarball's own install.sh produces minus docs: cargo, rustc (which
-- brings librustc_driver + the bundled libLLVM), rust-std for the
-- build target, clippy and rustfmt. rustc resolves its sysroot via
-- /proc/self/exe ($ORIGIN-relative), so the merged usr/bin + usr/lib
-- tree works unmodified in the read-only merged build prefix and in a
-- pod store tree. Docs, llvm-tools, rust-analysis and rust-analyzer
-- are deliberately not staged: dead weight in every consumer payload.
--
-- requires: glibc + libgcc (libgcc_s.so.1 is a DT_NEEDED of both the
-- cargo and rustc drivers — pool libgcc is the unwinder provider).
-- NOTE: pool libgcc lands with the #34 lane — merge order libgcc →
-- rust, or resolution of this package fails on a tree without it.

return {
    default = snap {
        name = "rust",
        version = "1.98.1",
        summary = "Rust toolchain — cargo, rustc, std, clippy, rustfmt",
        description = [[
            The official Rust distribution for x86_64-unknown-linux-gnu:
            cargo (package manager and build driver), rustc (compiler,
            with its bundled LLVM), the standard library for the build
            target, clippy, and rustfmt. Merged into usr/bin + usr/lib
            so pod installs expose `cargo`/`rustc` and build_deps
            consumers invoke them by bare name in the hermetic sandbox.
        ]],
        license = "MIT OR Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://static.rust-lang.org/dist/2026-09-03/rust-1.98.1-x86_64-unknown-linux-gnu.tar.xz",
            sha256 = "5326b36c53de11d148c8f8dab6553a3d1006c2cfd32123683073fad3c302605b",
        },

        -- $SRC is the dist root (rust-1.98.1-x86_64-unknown-linux-gnu/);
        -- each component dir carries its own slice of the classic prefix
        -- layout — merge them into $STAGE/usr. Only rustc ships lib/ +
        -- libexec/ (driver dylibs, bundled LLVM, proc-macro server); the
        -- other components are bin-only.
        build = table.concat({
            "mkdir -p $STAGE/usr/bin $STAGE/usr/lib",
            "cp -a $SRC/cargo/bin/. $STAGE/usr/bin/",
            "cp -a $SRC/rustc/bin/. $STAGE/usr/bin/",
            "cp -a $SRC/rustc/lib/. $STAGE/usr/lib/",
            "cp -a $SRC/rustc/libexec $STAGE/usr/libexec",
            "cp -a $SRC/rust-std-x86_64-unknown-linux-gnu/lib/. $STAGE/usr/lib/",
            "cp -a $SRC/clippy-preview/bin/. $STAGE/usr/bin/",
            "cp -a $SRC/rustfmt-preview/bin/. $STAGE/usr/bin/",
        }, " && "),

        type = "source",
        requires = { "glibc", "libgcc" },

        apps = {
            cargo = app {
                command = "usr/bin/cargo",
            },
            rustc = app {
                command = "usr/bin/rustc",
            },
            clippy = app {
                command = "usr/bin/cargo-clippy",
            },
            rustfmt = app {
                command = "usr/bin/rustfmt",
            },
        },
    },
}
