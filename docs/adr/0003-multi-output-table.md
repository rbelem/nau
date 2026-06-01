# Multi-output table structure for shoot.lua

Every `shoot.lua` returns a table of named outputs: `return { default = snap { ... }, server = snap { ... } }`. A single-file project uses the `default` key; multi-output projects (a server snap + a CLI snap) use named keys. This is Nix flake-inspired: one declarative file describes everything a project produces, and `shoot build <name>` selects a specific output. The alternative (one file per snap, implied by Snapcraft convention) would require multiple config files and lose cross-output composition via `merge()` and `require()`.
