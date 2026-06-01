-- util-linux: Miscellaneous system utilities for Linux
--
-- Source: https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/
-- Provides essential utilities like mount, fdisk, lsblk, and more.

return {
    default = snap {
        name = "util-linux",
        version = "2.42",
        summary = "Miscellaneous system utilities for Linux",
        description = [[
            util-linux is a large collection of low-level Linux system
            utilities. Includes mount, fdisk, lsblk, losetup, mkswap,
            swapon, dmesg, kill, login, su, wall, and many other essential
            tools needed to administer a Linux system.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v2.42/util-linux-2.42.tar.xz",
        },
        build = "./configure --prefix=/usr --without-systemd && make && make install DESTDIR=$STAGE",
    },
}
