-- lxc: Linux Containers runtime
--
-- Source: https://github.com/lxc/lxc
-- Provides tools for creating and managing system containers.

return {
    default = snap {
        name = "lxc",
        version = "6.0",
        summary = "Linux Containers runtime",
        description = [[
            LXC (Linux Containers) is an operating system-level
            virtualization method for running multiple isolated Linux
            systems on a single host. LXC provides a lightweight
            virtualization environment with near-native performance.
            Includes lxc-create, lxc-start, lxc-stop, lxc-attach,
            and the liblxc shared library.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        source = {
            url = "https://github.com/lxc/lxc/releases/download/lxc-6.0.2/lxc-6.0.2.tar.gz",
        },
        build = "meson setup build --prefix=/usr && ninja -C build && DESTDIR=$STAGE ninja -C build install",
    },
}
