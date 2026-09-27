-- pasta: alias entry for the passt payload (one binary, two names).
--
-- podman's `requires` names this payload "pasta" (the entrypoint it
-- execs for rootless networking); the pool defines it once, in
-- passt.lua, under its canonical name. Alias names must resolve
-- wherever package names do: the Rust-side package resolver
-- (resolve_pkg) is path-based, so the alias needs a real collection
-- entry to land on (the toolchain.lua pattern, generalized).
--
-- The file is a thin re-export, not a second definition.

local passt = require("p/passt")

return { default = passt.default }
