# Shared templates for CLI tools packaged as snaps.
# Port of pkgs/j/jq/lib.lua. Composes via the host-provided prelude:
# `nau-prelude` is a host alias rewritten to the in-memory prelude seed.

let { merge, .. } = import "nau-prelude" in

{
  cli_app | not_exported = fun overrides =>
    merge
      {
        command | priority 0 = "bin/tool",
        plugs = ["home", "network"],
      }
      overrides,
}
