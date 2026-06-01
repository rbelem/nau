-- dosfstools: FAT filesystem utilities
--
-- Source: https://github.com/dosfstools/dosfstools
-- Provides mkfs.fat, fsck.fat, and fatlabel for FAT filesystems.

return {
    default = snap {
        name = "dosfstools",
        version = "4.2",
        summary = "FAT filesystem utilities",
        description = [[
            dosfstools provides utilities for creating and checking FAT
            (MS-DOS) filesystems. Includes mkfs.fat (mkfs.vfat) for
            creating FAT12/FAT16/FAT32 filesystems, fsck.fat for checking
            and repairing, and fatlabel for managing volume labels.
            Essential for EFI System Partitions and removable media.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://github.com/dosfstools/dosfstools/releases/download/v4.2/dosfstools-4.2.tar.gz",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
