-- lvm2: Logical Volume Manager 2
--
-- Source: https://mirrors.edge.kernel.org/pub/linux/utils/lvm2/
-- Provides tools for managing logical volumes and volume groups.

return {
    default = snap {
        name = "lvm2",
        version = "2.03",
        summary = "Logical Volume Manager 2",
        description = [[
            LVM2 provides tools for creating and managing logical volumes
            on Linux. It allows physical disks to be combined into volume
            groups, from which logical volumes can be allocated. Supports
            snapshots, mirroring, striping, and thin provisioning.
            Includes pvcreate, vgcreate, lvcreate, and related commands.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://mirrors.edge.kernel.org/pub/linux/utils/lvm2/v2.03/lvm2-2.03.29.tgz",
        },
        build = "./configure --prefix=/usr --sysconfdir=/etc --with-udev-prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
