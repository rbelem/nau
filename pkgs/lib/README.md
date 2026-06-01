# pool/lib — shared Lua templates

Reusable app definition templates. Loaded with `require("pkgs.lib.<module>")`.

| Module | Function | Default plugs |
|---|---|---|
| `cli.lua` | `app()` | home, network |
| `daemon.lua` | `app()` | network, network-bind |
| `desktop.lua` | `app()` | desktop, x11, wayland, opengl |

### Usage in a package

```lua
local cli = require("pkgs.lib.cli")

return {
    default = snap {
        name = "myapp",
        version = "1.0",
        apps = {
            mytool = cli.app { command = "bin/mytool" },
        },
    },
}
```
