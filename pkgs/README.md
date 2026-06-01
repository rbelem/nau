# pkgs — shoot package index

Ubuntu-style pool layout for Snap package definitions.
Inspired by https://archive.ubuntu.com/ubuntu/ubuntu/pool/main/

## Layout

```
pkgs/
  <first-letter>/        # First letter of package name
    <package-name>/      # Package directory
      shoot.lua          # Required: package definition (ADR-0003 format)
      lib.lua            # Optional: package-specific Lua helpers
  ...
  lib/                   # Shared Lua modules
    cli.lua              # CLI app template
    daemon.lua           # Daemon/service template
    desktop.lua          # Desktop app template
  README.md
```

Packages starting with `lib` go under `lib<first-letter>/`, following
Debian/Ubuntu convention (e.g. `libssl` → `pkgs/libl/libssl/`).

## Finding packages

```
pkgs/j/jq/shoot.lua        # package: jq
pkgs/h/hello/shoot.lua     # package: hello
pkgs/s/systemd/shoot.lua   # package: systemd
pkgs/o/openssl/shoot.lua   # package: openssl
```

## Usage with the index

The `shoot index` command can scan `pkgs/` to build `package-index.json`,
which the `index()` DSL function uses at require time.

## Adding a package

```bash
mkdir -p pkgs/<first-letter>/<package>
vim pkgs/<first-letter>/<package>/shoot.lua
```
