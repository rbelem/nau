-- xfsprogs: XFS filesystem utilities
--
-- Source: https://mirrors.edge.kernel.org/pub/linux/utils/fs/xfs/xfsprogs/
-- Provides mkfs.xfs, xfs_repair, and related XFS management tools.

return {
    default = snap {
        name = "xfsprogs",
        version = "6.12",
        summary = "XFS filesystem utilities",
        description = [[
            xfsprogs provides the userspace utilities for managing the
            XFS filesystem. Includes mkfs.xfs for creating XFS filesystems,
            xfs_repair for checking and repairing, xfs_admin for changing
            parameters, xfs_info for displaying filesystem geometry, and
            xfs_growfs for online filesystem expansion.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        source = {
            url = "https://mirrors.edge.kernel.org/pub/linux/utils/fs/xfs/xfsprogs/xfsprogs-6.12.0.tar.xz",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
