-- linux-headers: Linux kernel header files for 6.6
--
-- Source: https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.tar.xz
return {
    default = snap {
        name = "linux-headers",
        version = "6.6",
        summary = "Kernel headers for Linux 6.6",
        description = [[Linux kernel headers from version 6.6 provide the C header files that define
the interface between the Linux kernel and userspace libraries. These headers
are required for compiling the GNU C Library (glibc), kernel modules, and
other programs that need to interact with the kernel at a low level.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        source = { url = "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.tar.xz" },
        build = "make headers_install ARCH=x86_64 INSTALL_HDR_PATH=$STAGE/usr",
    },
}
