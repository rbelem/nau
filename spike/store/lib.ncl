# Shared templates for CLI tools packaged as snaps.
# Port of pkgs/j/jq/lib.lua. Composes via the host-provided prelude:
# `shuttle-prelude` is a host alias rewritten to the in-memory prelude seed.

let { merge, .. } = import "shuttle-prelude" in

{
  cli_app | not_exported = fun overrides =>
    merge
      {
        command | priority 0 = "bin/tool",
        plugs = ["home", "network"],
      }
      overrides,
}
