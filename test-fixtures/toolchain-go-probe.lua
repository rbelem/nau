-- toolchain-go-probe: build_deps consumer probe for the pool go
-- toolchain package (ticket #24).
--
-- Not a pool package — a fixture proving the dual-use contract: a
-- package that lists `go` in build_deps gets the toolchain merged into
-- its build prefix (usr/bin leads the sandbox PATH), so the build
-- script can invoke go by bare name inside the hermetic sandbox.
--
-- Build:
--   shuttle build --file test-fixtures/toolchain-go-probe.lua

return {
    default = snap {
        name = "toolchain-go-probe",
        version = "0.1.0",
        summary = "Probe: consumes pool go as a build_dep",
        description = [[
            Empty-payload probe whose build script runs `go version` and
            checks the resolved GOROOT inside the sandbox. Green build =
            the go toolchain package is consumable via build_deps.
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

        build_deps = { "go" },

        -- Plain word/redirect commands only: the sandbox preflight
        -- parses command words, and $() nesting confuses it.
        build = table.concat({
            "go version",
            "go version > go-version.txt && grep -q 'go1.27.1 linux/amd64' go-version.txt",
            "go env GOROOT > goroot.txt && grep -q '/' goroot.txt",
            "cat go-version.txt goroot.txt",
        }, " && "),
    },
}
