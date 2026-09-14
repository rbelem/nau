-- toolchain-cgo-probe: CGO-in-the-pool probe (issue #44).
--
-- Not a pool package — a fixture proving the CGO host contract: a Go
-- build with CGO_ENABLED=1 compiles its C half with the pool gcc
-- (build_deps toolchain), discovers a pool library through the pool
-- pkg-config (the `#cgo pkg-config:` directive drives `pkg-config
-- --cflags/--libs` inside the hermetic sandbox against PKG_CONFIG_PATH),
-- links against it, and the result RUNS in-sandbox against the same
-- prefix. This is the #44 acceptance: "a cgo-using Go consumer builds
-- green offline in-sandbox against pool libs".
--
-- The sandbox wiring under test (src/snap.rs):
--   PATH    — prefix usr/bin leads, so go finds pool gcc, and cgo execs
--             it (CC=gcc is also exported by build_prefix_toolchain_env)
--   CC/CXX  — exported when the prefix carries a C toolchain
--   PKG_CONFIG_PATH / PKG_CONFIG_SYSROOT_DIR — .pc resolution against
--             the merged prefix (build_prefix_env)
--   gate    — the build declares CGO_ENABLED=1 AND declares the
--             toolchain, so ensure_cgo_toolchain passes (the negative —
--             a CGO build without the toolchain — fails closed with the
--             named fix; covered by unit tests and a live negative run)
--
-- Build:
--   shuttle build --file test-fixtures/toolchain-cgo-probe.lua

return {
    default = snap {
        name = "toolchain-cgo-probe",
        version = "0.1.0",
        summary = "Probe: CGO Go consumer builds against pool C libs",
        description = [[
            Probe whose build script compiles a cgo-using Go program
            (calls libffi through #cgo pkg-config) with the pool gcc
            inside the hermetic sandbox, links it against the pool
            libffi, verifies the DT_NEEDED set with the pool readelf,
            stages the binary, and RUNS it in-sandbox against the
            prefix. Staging puts the binary through the ADR-0018 leak
            scan: libffi and glibc are declared in requires, so the
            linked sonames resolve into runtime payloads and the
            build_deps-only toolchain stays build-only. Green build =
            the pool C toolchain is a working CGO host, pkg-config
            resolves sibling build_deps, and the closure split holds.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",

        -- The harness requires a fetchable source whenever `build` is
        -- set; nothing in the payload comes from it (the binary is built
        -- from the inline go.mod/main.go below). Reuse the smallest
        -- already-pinned pool tarball (dcg, from pkgs/d/dcg.lua).
        source = {
            url = "https://github.com/Dicklesworthstone/destructive_command_guard/releases/download/v0.14.1/dcg-x86_64-unknown-linux-musl.tar.xz",
            sha256 = "e7b39be070ad98f74a1edd59fefb8ac41865ab2aa2c5a4252eb71c5413f3f9df",
        },

        -- Both lists, per the ADR-0018 build/link split: the toolchain,
        -- pkg-config and libffi are build-time-only; libffi (linked) and
        -- glibc (the cgo binary's libc) are also runtime deps. The leak
        -- scan checks that split on the staged binary.
        build_deps = { "toolchain", "go", "pkg-config", "libffi" },
        requires = { "glibc", "libffi" },

        -- The env wiring assertions come first (the wiring IS the
        -- contract), then the cgo build itself. GOCACHE/GOPATH live on
        -- the sandbox's writable /tmp; GOPROXY=off proves the build is
        -- offline (no module deps — stdlib plus the cgo C half only).
        build = table.concat({
            "set -x",
            -- Sandbox wiring (issue #44): the pool toolchain and
            -- pkg-config shadow the host; CC/CXX name the pool driver.
            "test \"$(command -v gcc)\" = /shuttle-build-prefix/usr/bin/gcc",
            "test \"$(command -v pkg-config)\" = /shuttle-build-prefix/usr/bin/pkg-config",
            -- Go env (cgo side of the contract): the sandbox exports
            -- CGO_ENABLED=1 (this recipe's declaration) and CC resolves
            -- to the pool gcc for the C half of the build.
            "export GOCACHE=/tmp/go-build-cache GOMODCACHE=/tmp/go-mod-cache GOPATH=/tmp/go-path",
            "export CGO_ENABLED=1 GOPROXY=off GOFLAGS=-mod=mod",
            "test \"$(go env CC)\" = gcc",
            "test \"$(go env CGO_ENABLED)\" = 1",
            -- pkg-config resolves the sibling build_dep through the
            -- sysroot-rewritten .pc paths. Note --cflags is EMPTY by
            -- design: pkg-config filters default include dirs
            -- (-I/usr/include), and the headers are consumed through the
            -- pool gcc's own baked sysroot (/shuttle-build-prefix) — the
            -- --libs -L proves the sysroot rewrite is live.
            "pkg-config --modversion libffi | grep -q '^3\\.'",
            "pkg-config --libs libffi | grep -q 'shuttle-build-prefix/usr/lib'",
            "pkg-config --libs libffi | grep -q -- '-lffi'",
            -- The cgo consumer: C half calls libffi, discovered via the
            -- #cgo pkg-config directive (cgo execs `pkg-config --cflags/
            -- --libs libffi` itself, inside the sandbox).
            "printf '%s\\n' 'module cgoprobe' '' 'go 1.21' > go.mod",
            "printf '%s\\n' 'package main' '' '/*' '#cgo pkg-config: libffi' '#include <ffi.h>' '*/' 'import \"C\"' '' 'import \"fmt\"' '' 'func main() {' '    abi := C.ffi_get_default_abi()' '    fmt.Printf(\"libffi default ABI: %d\\n\", int(abi))' '}' > main.go",
            "go build -o cgoprobe .",
            -- Link truth, verified with the pool binutils readelf: the
            -- C half pulled in libffi via pkg-config and libc via cgo.
            "readelf -d cgoprobe | grep -q 'Shared library: \\[libffi.so.8\\]'",
            "readelf -d cgoprobe | grep -q 'Shared library: \\[libc.so.6\\]'",
            -- Smoke: RUN it in-sandbox against the prefix libffi (the
            -- loader resolves libc from the sandbox's system binds;
            -- libffi stages into usr/lib64 — hence both dirs).
            "LD_LIBRARY_PATH=$SHUTTLE_BUILD_PREFIX/usr/lib:$SHUTTLE_BUILD_PREFIX/usr/lib64 ./cgoprobe | grep -q 'libffi default ABI'",
            -- Stage it: the leak scan now verifies the closure split on a
            -- real ELF (libffi.so.8/libc.so.6 → requires payloads), and
            -- the snap ships a runnable app.
            "mkdir -p $STAGE/usr/bin && cp cgoprobe $STAGE/usr/bin/cgoprobe",
            "echo toolchain-cgo-probe: CGO build, link and in-sandbox run green",
        }, " && "),

        apps = {
            cgoprobe = app {
                command = "usr/bin/cgoprobe",
            },
        },
    },
}
