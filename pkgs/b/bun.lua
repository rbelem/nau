-- bun: Incredibly fast JavaScript runtime, bundler, test runner, and
-- package manager (oven-sh/bun).
--
-- Ticket #25 — pool toolchain package (third of the flake-toolchain
-- set, after go and rust at 11bd94c), dual-use: pod-installable for
-- daily use AND consumable as a build_dep by other packages (the
-- merged build prefix puts usr/bin first on the sandbox PATH, so a
-- bare `bun`/`bunx` resolves inside a consumer's hermetic build).
--
-- Port strategy — FETCH, not source bootstrap: bun publishes official
-- self-contained prebuilt linux-x64 releases; a from-source build in
-- the sandbox (C++/LLVM/WebKit toolchain) is a multi-hour bootstrap
-- with no payoff. The flake pins the x64-baseline variant (Nehalem
-- ISA, no AVX/AVX2 — VirtualBox/older-CPU compatible); we pin the
-- same artifact, digest cross-checked against the flake's SRI hash.
--
-- Runtime deps (ldd): the glibc family only — zlib and libstdc++ are
-- statically linked into the official build, so nothing beyond glibc
-- is required (the flake's zlib/cc.lib buildInputs only fed
-- autoPatchelf's search path).
--
-- Layout: the release asset is a .zip — the harness only extracts
-- tar.{gz,xz}/tgz sources, so the build extracts the zip itself with
-- the pool's 7zz (p7zip as a build_deps: the merged build prefix puts
-- it on the sandbox PATH). The flake's bunx symlink is staged as a
-- tiny sh wrapper instead — the pack step's stage copy dereferences
-- symlinks (fs::copy), which would materialize a full second copy of
-- the binary, and the interpreter-wrapper pass follows symlinks when
-- rewriting command files (node.lua note). `bunx cmd` ≡ `bun x cmd`.
--
-- requires = { glibc }: the official build statically links zlib and
-- libstdc++ (the flake's zlib/cc.lib buildInputs only fed
-- autoPatchelf's search path).
--
-- build_deps: p7zip (7zz extracts the .zip source; build-time only).

return {
    default = snap {
        name = "bun",
        version = "1.4.2",
        summary = "Bun JavaScript runtime, bundler, test runner, package manager",
        description = [[
            Bun is an all-in-one JavaScript/TypeScript runtime: run,
            bundle, test, and package JS projects with a single fast
            tool. Ships the official linux-x64-baseline release binary
            (no AVX required) so pod installs expose `bun`/`bunx` and
            build_deps consumers invoke them by bare name in the
            hermetic sandbox.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/oven-sh/bun/releases/download/bun-v1.4.2/bun-linux-x64-baseline.zip",
            sha256 = "c678040f14fe0440eb839d37cbd0ce4c051a32da72806ac97de6a6aab6bf728f",
        },

        -- The raw .zip sits in the build dir (the harness only unpacks
        -- tar.* sources); 7zz comes from the p7zip build_dep via the
        -- merged prefix PATH. -y: non-interactive (stdin is not a tty).
        build = table.concat({
            "7zz x -y -obun-extracted bun-linux-x64-baseline.zip",
            "install -Dm755 bun-extracted/bun-linux-x64-baseline/bun $STAGE/usr/bin/bun",
            "printf '%s\\n' '#!/bin/sh' 'exec \"$(dirname \"$0\")/bun\" x \"$@\"' > $STAGE/usr/bin/bunx",
            "chmod +x $STAGE/usr/bin/bunx",
        }, " && "),

        type = "source",
        requires = { "glibc" },
        build_deps = { "p7zip" },

        apps = {
            bun = app {
                command = "usr/bin/bun",
            },
            bunx = app {
                command = "usr/bin/bunx",
            },
        },
    },
}
