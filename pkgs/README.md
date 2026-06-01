# pkgs — shoot package index

Ubuntu-style pool layout for Snap package definitions.
Inspired by https://archive.ubuntu.com/ubuntu/ubuntu/pool/main/

## Layout

```
pkgs/
  <first-letter>/        # First letter of package name
    <package-name>.lua   # Single-file package (most common)
    <package-name>/      # Multi-file package directory
      init.lua           # Required: package definition
      lib.lua            # Optional: package-specific Lua helpers
  ...
  lib/                   # Shared Lua modules
    cli.lua              # CLI app template
    daemon.lua           # Daemon/service template
    desktop.lua          # Desktop app template
  README.md
```

Each package is either:
- **Single file**: `pkgs/<letter>/<name>.lua` containing the full definition
- **Directory**: `pkgs/<letter>/<name>/init.lua` + optional helpers (`lib.lua`, etc.)

## Finding packages

```
pkgs/j/jq/init.lua          # package: jq (multi-file, has lib.lua helper)
pkgs/h/hello.lua            # package: hello (single file)
pkgs/s/systemd.lua          # package: systemd (single file)
pkgs/o/openssl.lua          # package: openssl (single file)
```

## Usage with the index

The `shoot index` command can scan `pkgs/` to build `package-index.json`,
which the `index()` DSL function uses at require time.

## Adding a package

For a simple package (single file):
```bash
vim pkgs/<first-letter>/<name>.lua
```

For a package with helper files:
```bash
mkdir pkgs/<first-letter>/<name>
vim pkgs/<first-letter>/<name>/init.lua
vim pkgs/<first-letter>/<name>/lib.lua
```
