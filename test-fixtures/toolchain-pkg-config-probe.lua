-- toolchain-pkg-config-probe: pool pkg-config as a build_dep (issue #44).
--
-- Not a pool package — a fixture proving the pkg-config half of the #44
-- acceptance: the pool pkg-config package builds, is consumable as a
-- build_deps entry, and resolves a SIBLING build_dep's library (pool
-- libffi) through the sandbox wiring — PKG_CONFIG_PATH finds the .pc in
-- the merged prefix, PKG_CONFIG_SYSROOT_DIR rewrites the /usr-rooted
-- paths onto the prefix, and the resolved flags feed a real pool-gcc
-- compile, link and in-sandbox run.
--
-- Build:
--   shuttle build --file test-fixtures/toolchain-pkg-config-probe.lua

return {
    default = snap {
        name = "toolchain-pkg-config-probe",
        version = "0.1.0",
        summary = "Probe: pkg-config resolves sibling build_deps",
        description = [[
            Empty-payload probe whose build script drives the pool
            pkg-config against a sibling build_dep (libffi) and compiles,
            links and runs a trivial C consumer with the resolved flags.
            Green build = pool pkg-config is consumable via build_deps
            and its .pc resolution lands in the merged build prefix.
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

        build_deps = { "toolchain", "pkg-config", "libffi" },

        -- The wiring assertions name the sandbox contract directly: the
        -- pool pkg-config (not a host one) resolves libffi from the
        -- prefix, with the sysroot-rewritten -L the .pc produces
        -- (--cflags is empty by design: pkg-config filters default
        -- include dirs; headers ride the compiler's baked sysroot).
        build = table.concat({
            "set -x",
            "test \"$(command -v pkg-config)\" = /shuttle-build-prefix/usr/bin/pkg-config",
            "pkg-config --modversion libffi | grep -q '^3\\.'",
            "pkg-config --libs libffi | grep -q 'shuttle-build-prefix/usr/lib'",
            "pkg-config --libs libffi | grep -q -- '-lffi'",
            -- A real consumer: the resolved flags feed pool gcc; the
            -- result runs in-sandbox against the prefix lib.
            "printf 'int main(void){return 0;}\\n' > t.c",
            "gcc t.c -o t $(pkg-config --cflags --libs libffi)",
            "test -x t",
            "LD_LIBRARY_PATH=$SHUTTLE_BUILD_PREFIX/usr/lib:$SHUTTLE_BUILD_PREFIX/usr/lib64 ./t",
            "echo toolchain-pkg-config-probe: pkg-config resolves sibling build_deps green",
        }, " && "),
    },
}
