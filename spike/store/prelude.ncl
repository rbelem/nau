# shoot DSL prelude (ADR-0009 spike).
#
# Authored definitions never import this file: the HOST merges it into every
# program as an in-memory input (the "wrap" of Decision 2 — the enforcement
# point is shoot's wrap, never the author's annotation).
#
# All machinery fields are `not_exported`, so eval_full_for_export yields the
# pure data record for serde extraction (Decision 3).
#
# The package index is provided by the host as the `index_data` field (also
# not_exported, priority 0 default): in-process it is seeded directly; in the
# subprocess model it crosses the parent<->child IPC pipe.

let SnapType = std.contract.custom (fun label value =>
  if
    std.is_string value
    && std.array.fold_left
      (fun acc t => acc || value == t)
      false
      ["source", "meta", "store"]
  then
    'Ok value
  else
    'Error { message = "snap type must be one of: source, meta, store" })
in

let AppContract = {
  command | String,
  daemon | String | optional,
  plugs | Array String | optional,
  slots | Array String | optional,
  environment | { _ | Dyn } | optional,
} in

let PinContract = {
  name | String,
  revision | Number | optional,
  sha3_384 | String | optional,
} in

{
  index_data | not_exported = null,  # @host-replace: the host swaps this line for the populated index record

  app | not_exported = fun opts =>
    opts | AppContract,

  snap | not_exported = fun opts =>
    (
      {
        grade | priority 0 = "stable",
        confinement | priority 0 = "strict",
      }
      & opts
    )
    | {
        name | String,
        version | String,
        summary | String | optional,
        description | String | optional,
        license | String | optional,
        grade | String | optional,
        confinement | String | optional,
        source | String | optional,
        stage | String | optional,
        architectures | Array String | optional,
        type | SnapType | optional,
        requires | Array String | optional,
        aliases | Array String | optional,
        plugs | { _ | Dyn } | optional,
        slots | { _ | Dyn } | optional,
        inputs | { _ | Dyn } | optional,
        apps | { _ | AppContract } | optional,
      },

  image | not_exported = fun opts =>
    opts | {
      name | String,
      version | String,
      base | PinContract,
      kernel | { _ | Dyn } | optional,
      gadget | PinContract | optional,
      bootloader | { _ | Dyn } | optional,
      snaps | Array PinContract | optional,
      disk | { _ | Dyn } | optional,
      sysctl | Array String | optional,
    },

  pin | not_exported = fun pin_name pin_opts =>
    if pin_opts == null then
      { name = pin_name } | PinContract
    else
      ({ name = pin_name } & pin_opts) | PinContract,

  index | not_exported = fun index_name =>
    if std.record.has_field index_name index_data then
      std.record.insert "name" index_name index_data."%{index_name}"
    else
      null
      | std.contract.custom (fun label value =>
        'Error { message = "snap '%{index_name}' not found in package index" }),

  merge | not_exported = fun base overrides =>
    if base == null then overrides
    else if overrides == null then base
    else if !std.is_record base || !std.is_record overrides then
      # Lua merge semantics: arrays and scalars are replaced outright.
      overrides
    else
      std.array.fold_left
        (fun acc field =>
          let b =
            if std.record.has_field field acc then
              acc."%{field}"
            else
              null
          in
          # %record/insert% is add-only: drop the old field first when present.
          let stripped =
            if std.record.has_field field acc then
              std.record.remove field acc
            else
              acc
          in
          std.record.insert field (merge b overrides."%{field}") stripped)
        base
        (std.record.fields overrides),
}
