-- kmod: Linux kernel module handling
--
-- Source: https://mirrors.edge.kernel.org/pub/linux/utils/kernel/kmod/
-- Provides tools for loading and managing kernel modules.

return {
    default = snap {
        name = "kmod",
        version = "33",
        summary = "Linux kernel module handling",
        description = [[
            kmod is a set of tools to manage common tasks with Linux
            kernel modules. It provides the modprobe, insmod, rmmod,
            lsmod, modinfo, and depmod commands as replacements for the
            older module-init-tools package.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        source = {
            url = "https://mirrors.edge.kernel.org/pub/linux/utils/kernel/kmod/kmod-33.tar.xz",
        },
        build = "meson setup build --prefix=/usr && ninja -C build && DESTDIR=$STAGE ninja -C build install",
    },
}
