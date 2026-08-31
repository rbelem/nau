-- toolchain-bootstrap: Full toolchain bootstrap orchestrator
--
-- Meta-package that orchestrates the 3-stage GCC bootstrap:
--
--   Stage 0 (stage0-gcc):
--     Host compiler → minimal C-only cross-compiler
--     Purpose: Broke circular dependency with minimal build time
--
--   Stage 1 (stage1-gcc):
--     Stage0 compiler → full C/C++ cross-compiler with optimization
--     Purpose: Self-hosting toolchain built from bootstrap
--
--   Stage 2 (stage1-gcc rebuilt):
--     Stage1 compiler → rebuild full C/C++ compiler
--     Purpose: Verification — stage1 and stage2 outputs should match
--
-- After bootstrap completes, the resulting toolchain is equivalent to
-- the standard toolchain-gcc-gnu-x86_64 meta-package. The bootstrap is
-- only needed when building the toolchain from source for the first
-- time on a new architecture or without a host compiler.
--
-- Aliases: bootstrap
-- Requires: stage0-gcc, stage1-gcc
--
-- Usage:
--   shuttle build --order --file pkgs/t/toolchain-bootstrap.lua
--   → prints build order: stage0 → binutils → gmp → ... → stage1
--
--   shuttle build --file pkgs/t/toolchain-bootstrap.lua bootstrap
--   → builds the full bootstrap chain
return {
    default = snap {
        name = "toolchain-bootstrap",
        version = "14.2.0",
        summary = "Bootstrap orchestrator — stage0 → stage1 → full toolchain",
        description = [[
            Orchestrates the three-stage GCC bootstrap process.
            Required when building a toolchain from source without
            a pre-existing cross-compiler.

            Bootstrap workflow:
              1. Build stage0-gcc (host → minimal cross-compiler)
              2. Build stage1-gcc (stage0 → full C/C++ compiler)
              3. (Optional) Build stage1-gcc again as stage2 to verify

            After bootstrap, the output can replace the standard
            toolchain-gcc-gnu-x86_64 meta-package. The two are
            functionally equivalent.

            The bootstrap is architecture-agnostic: change the
            `target` field in stage0-gcc.lua and stage1-gcc.lua
            to target different platforms (e.g. aarch64-linux-gnu).
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "meta",
        aliases = { "bootstrap" },
        requires = {
            "stage0-gcc",
            "stage1-gcc",
        },
    },
}
