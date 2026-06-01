-- fuse: Filesystem in Userspace library and tools
--
-- Source: https://github.com/libfuse/libfuse
-- Provides the FUSE library and utilities for userspace filesystems.

return {
    default = snap {
        name = "fuse",
        version = "3.17",
        summary = "Filesystem in Userspace library and tools",
        description = [[
            FUSE (Filesystem in Userspace) is an interface for userspace
            programs to export a filesystem to the Linux kernel. The
            libfuse library makes it possible to implement a fully
            functional filesystem in a userspace program. Provides fusermount3
            and the libfuse3 shared library.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://github.com/libfuse/libfuse/releases/download/fuse-3.17.4/fuse-3.17.4.tar.gz",
        },
        build = "meson setup build --prefix=/usr && ninja -C build && DESTDIR=$STAGE ninja -C build install",
    },
}
