# mksquashfs subprocess for snap packaging

Snaps are packaged by shelling out to `mksquashfs` rather than using a Rust SquashFS library. `mksquashfs` is maintained, documented, handles all SquashFS edge cases (compression, permissions, xattrs, timestamps), and is already required by the Snap ecosystem. A Rust library would duplicate this logic and drift from the `snapd`-expected format. The downside: `mksquashfs` must be installed on the host (via `squashfs-tools`), which `shoot doctor` checks.
