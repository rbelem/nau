-- toolchain: alias entry for the default GCC toolchain.
--
-- The pool "toolchain" alias is OWNED by toolchain-gcc-gnu-x86_64
-- (declared in that meta's `aliases`). Alias names must resolve
-- wherever package names do: `shuttle pod add toolchain`,
-- `build_deps = { "toolchain" }`, and `build-deps`'s own
-- `requires = { "toolchain" }` all resolve THROUGH this file — the
-- Rust-side package resolver (resolve_pkg) is path-based, so the alias
-- needs a real collection entry to land on.
--
-- The file is a thin re-export, not a second definition: the meta is
-- defined exactly once, in toolchain-gcc-gnu-x86_64.lua, and this
-- entry returns it under its canonical name. The DSL `require` maps
-- the module name onto pkgs/<letter>/<name>.lua and runs it in the
-- same worker VM (the jq multi-file-package pattern, generalized to a
-- cross-package re-export).

local gcc_toolchain = require("t/toolchain-gcc-gnu-x86_64")

return { default = gcc_toolchain.default }
