-- toolchain-gcc-probe: build_deps consumer probe for the pool gcc
-- toolchain (ticket #38), mirroring the go/rust probes.
--
-- Not a pool package — a fixture proving the dual-use contract: a
-- package that lists the "toolchain" alias in build_deps gets the
-- whole GCC toolchain merged into its build prefix (usr/bin leads the
-- sandbox PATH), so the build script can compile C AND C++ through
-- bare `gcc`/`g++` inside the hermetic sandbox and run the results
-- against the prefix glibc.
--
-- Build:
--   shuttle build --file test-fixtures/toolchain-gcc-probe.lua

return {
    default = snap {
        name = "toolchain-gcc-probe",
        version = "0.1.0",
        summary = "Probe: consumes the toolchain alias as a build_dep",
        description = [[
            Empty-payload probe whose build script compiles a trivial C
            binary and a trivial C++ binary with the merged-prefix
            toolchain and runs them via the prefix loader. Green build =
            the toolchain alias resolves and the toolchain is consumable
            via build_deps.
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

        -- The alias seed exercises alias resolution through the dep
        -- resolver: "toolchain" must land on toolchain-gcc-gnu-x86_64
        -- and merge its full closure (gcc, binutils, glibc, gmp, mpfr,
        -- mpc, isl, linux-headers, zlib, libstdcpp) into one prefix.
        build_deps = { "toolchain" },

        -- The merged prefix is the sysroot the pool gcc was configured
        -- with, so in-sandbox compiles need no extra flags. The
        -- compiled binaries run via the prefix's own loader with the
        -- prefix libc on LD_LIBRARY_PATH — portable across hosts
        -- regardless of what /lib64 carries.
        build = table.concat({
            "printf 'int main(void){return 42;}\\n' > t.c",
            "gcc t.c -o t",
            "test -x t",
            "LD_LIBRARY_PATH=/shuttle-build-prefix/usr/lib:/shuttle-build-prefix/usr/lib64 /shuttle-build-prefix/lib64/ld-linux-x86-64.so.2 ./t",
            "printf '#include <cstdio>\\nint main(){return 7;}\\n' > t.cpp",
            "g++ t.cpp -o tc",
            "LD_LIBRARY_PATH=/shuttle-build-prefix/usr/lib:/shuttle-build-prefix/usr/lib64 /shuttle-build-prefix/lib64/ld-linux-x86-64.so.2 ./tc",
            "gcc --version | head -1 | grep -q '16\\.1\\.0'",
            "g++ --version | head -1 | grep -q '16\\.1\\.0'",
            "echo toolchain-gcc-probe: C and C++ compiles green",
        }, " && "),
    },
}
