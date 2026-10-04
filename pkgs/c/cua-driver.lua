-- cua-driver: the Cua computer-use driver (Rust backend) for Linux.
--
-- Prebuilt release payload (the cua.lua shape): the cua-driver-rs
-- release ships a Linux x86_64 binary tarball holding the `cua-driver`
-- executable, its cursor theme, a GNOME Wayland helper extension, the
-- SDK shared library, a Node runtime module, and the ABI header.
--
-- Runtime deps verified by ldd over the pinned tarball: glibc,
-- libgcc_s, and hard DT_NEEDED libX11.so.6 + libXi.so.6 +
-- libxkbcommon.so.0 — hence the libx11/libxi/xkbcommon requires (the
-- X11 pair rides the pool's deb-seam libx11→libxcb→libxau/libxdmcp
-- chain, all pinned to the same snapshot timestamp as the gcc chart).
--
-- Layout mirrors upstream's single-directory install (everything the
-- driver looks up sits beside the binary): cua-cursor-theme and
-- wayland-helper/ land in usr/bin next to cua-driver; the SDK .so and
-- Node module land in usr/lib so the pod's LD_LIBRARY_PATH exposes
-- them to embedders; the ABI header goes to usr/include.

return {
    default = snap {
        name = "cua-driver",
        version = "0.33.2",
        summary = "Cua computer-use driver: inspect and operate native desktop apps",
        description = [[
            cua-driver gives agents tools to inspect and operate native
            desktop apps and browsers on Linux: snapshot an app's
            accessibility tree, act through snapshot-bound element
            tokens, native menu paths, or exact coordinates, and verify
            from fresh state. Connectable from the CLI, MCP, or typed
            SDKs. Ships with its cursor theme and the GNOME Wayland
            helper extension beside the binary, plus the SDK shared
            library and Node runtime module for embedders.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/trycua/cua/releases/download/cua-driver-rs-v0.33.2/cua-driver-rs-0.33.2-linux-x86_64-binary.tar.gz",
            sha256 = "845d0c4eb15d9baaf1343e53074dbfbbef5adcc4e415526b929e549d250f221b",
        },

        -- Tarball is flat (entries at the root, no top-level dir), so
        -- cwd stays at the extraction root.
        build = table.concat({
            "install -Dm755 cua-driver $STAGE/usr/bin/cua-driver",
            "install -Dm755 cua-cursor-theme $STAGE/usr/bin/cua-cursor-theme",
            "mkdir -p $STAGE/usr/bin/wayland-helper",
            "cp -R wayland-helper/. $STAGE/usr/bin/wayland-helper/",
            "install -Dm755 libcua_driver_sdk.so $STAGE/usr/lib/libcua_driver_sdk.so",
            "install -Dm755 cua_driver_node_runtime.node $STAGE/usr/lib/cua_driver_node_runtime.node",
            "install -Dm644 cua_driver_abi.h $STAGE/usr/include/cua/cua_driver_abi.h",
            'test -x "$STAGE/usr/bin/cua-driver"',
            'test -e "$STAGE/usr/bin/wayland-helper/winrects@cua/metadata.json"',
            'test -e "$STAGE/usr/lib/libcua_driver_sdk.so"',
        }, " && "),

        type = "source",
        requires = { "glibc", "libgcc", "xkbcommon", "libx11", "libxi" },

        apps = {
            ["cua-driver"] = app {
                command = "usr/bin/cua-driver",
            },
        },
    },
}
