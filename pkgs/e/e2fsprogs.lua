-- e2fsprogs: Ext2/3/4 filesystem utilities
--
-- Source: https://mirrors.edge.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/
-- Provides mke2fs, fsck, tune2fs, and related filesystem tools.

return {
    default = snap {
        name = "e2fsprogs",
        version = "1.47",
        summary = "Ext2/3/4 filesystem utilities",
        description = [[
            e2fsprogs provides the filesystem utilities for use with the
            ext2, ext3, and ext4 filesystems. Includes mke2fs for creating
            filesystems, e2fsck for checking and repairing, tune2fs for
            adjusting filesystem parameters, and dumpe2fs for displaying
            filesystem information.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://mirrors.edge.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v1.47.2/e2fsprogs-1.47.2.tar.xz",
        },
        build = "./configure --prefix=/usr --enable-elf-shlibs && make && make install DESTDIR=$STAGE",
    },
}
