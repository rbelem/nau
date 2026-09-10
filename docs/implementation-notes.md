# Implementation Notes

Tactical findings from the reproducibility-pipeline and pods sessions that are
not architectural decisions (those live in `docs/adr/`). Each one is easy to get
wrong twice.

## Snap Store client (`src/store.rs`)

- **`revision` is top-level in a channel-map entry**, not nested under `channel`.
  `ChannelInfo` carries `track`, `risk`, and `architecture`; the sibling
  `ChannelMapEntry.revision` holds the revision.
- **Channels are written `track/risk`** (e.g. `latest/stable`) and parsed as
  such — not a bare channel name.

## SquashFS / image assembly

- **`unsquashfs -f` is not "force".** `-f` means something else in unsquashfs and
  breaks extraction. To silence device-node warnings, use `-no-xattrs` (see
  `src/units.rs`).
- **`SOURCE_DATE_EPOCH` is native to mksquashfs 4.4+.** Do not pass `-mkfs-time`;
  just ensure the environment variable is inherited by the child process
  (`src/snap.rs`, `src/image.rs`, `src/pod.rs`). `shuttle doctor` checks the
  mksquashfs version for this capability.

## Lua DSL ↔ Rust boundary (`src/lua.rs`)

- **`index()` is a Rust closure** registered on the Lua state in `src/lua.rs`,
  not defined in the Lua DSL file. It reads the `SHUTTLE_ARCH` and
  `SHUTTLE_INDEX_PATH` environment variables for context (set by the CLI in
  `src/main.rs`).
- Environment variables use the current `SHUTTLE_` prefix; the old `SHOOT_`
  prefix is gone.
