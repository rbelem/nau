-- linux-headers: Linux kernel header files for 7.0
--
-- Source: https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.0.tar.xz
--
-- Staged via the make plugin's build-only form (`install = false` — the
-- headers_install target IS the staging step; the kernel tree has no
-- `install` target we want). `variables` carries ARCH and
-- INSTALL_HDR_PATH=$STAGE/usr onto the single command.

return {
    default = snap {
        name = "linux-headers",
        version = "7.0",
        summary = "Kernel headers for Linux 7.0",
        description = [[Linux kernel headers from version 7.0 provide the C header files that define
the interface between the Linux kernel and userspace libraries. These headers
are required for compiling the GNU C Library (glibc), kernel modules, and
other programs that need to interact with the kernel at a low level.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        requires = {},
        source = { url = "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.0.tar.xz" },
        parts = {
            headers = {
                plugin = "make",
                options = {
                    target = "headers_install",
                    install = false,
                    variables = { ARCH = "x86_64", INSTALL_HDR_PATH = "$STAGE/usr" },
                },
            },
        },
    },
}
