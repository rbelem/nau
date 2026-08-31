# jq (golden parity port of pkgs/j/jq/init.lua + pkgs/j/jq/lib.lua)
# `lib` comes from the store via a host-rewritten import (never raw file I/O);
# `merge`/`snap` come from the host-injected prelude wrap.

let lib = import "lib.ncl" in

{
  default = snap (
    merge
      {
        name = "jq",
        version = "1.8.1",
        summary = "Lightweight and flexible command-line JSON processor",
        description = "            jq is like sed for JSON data — you can use it to slice,\n            filter, map and transform structured data with the same\n            ease that sed, awk, grep and friends let you play with text.\n        ",
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        source = "https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-1.8.1.tar.gz",
        architectures = ["amd64", "arm64"],
        type = "source",
        requires = ["glibc"],
        stage = "./stage/",
        apps = {
          # Compose from the shared CLI template, override with jq-specific values
          jq = lib.cli_app { command = "bin/jq" },
        },
      }
      {
        # Extra overrides can be stacked here (e.g. plugs specific to jq)
        apps = {
          jq = { plugs = ["home"] },  # jq only needs file read access, not network
        },
      }
  ),
}
