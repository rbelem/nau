-- oh-my-pi: coding agent with the IDE wired in (can1357/oh-my-pi) —
-- the `omp` CLI.
--
-- Medium-tier flake port survey (issue #25): the flake is a prebuilt
-- release fetch, not a source build — ported as a release-fetch
-- package in the #20 pattern (the cheap-tier batch missed this one).
-- The raw omp-linux-x64 release asset is fetched, sha256-pinned
-- (digest cross-checked against the flake pin), and installed
-- directly.
--
-- The asset is the bun-linux-x64-baseline bun-compile build (no AVX —
-- VirtualBox/older-CPU compatible, the reason the flake pins this
-- variant). Never strip/patchelf Bun-compiled binaries: they embed
-- their JS bytecode and corrupt under ELF rewriting (pi/hunk
-- precedent).
--
-- requires = { glibc }: ldd shows only the glibc family (libc, ld-
-- linux, libpthread, libdl, libm) in DT_NEEDED — the JS runtime is
-- self-contained.

return {
    default = snap {
        name = "oh-my-pi",
        version = "17.3.0",
        summary = "Coding agent with the IDE wired in (omp)",
        description = [[
            oh-my-pi (omp) is a coding agent CLI with IDE integration:
            multi-model agentic coding from the terminal. Ships as the
            bun-compiled baseline upstream release binary; LLM
            credentials come from the environment at run time.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/can1357/oh-my-pi/releases/download/v17.3.0/omp-linux-x64",
            sha256 = "287f07366f29896ef1e345423dab79b82a8dc0c1593383e20dfdd62a9dd2e799",
        },

        build = table.concat({
            "install -Dm755 omp-linux-x64 $STAGE/usr/bin/omp",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            omp = app {
                command = "usr/bin/omp",
            },
        },
    },
}
