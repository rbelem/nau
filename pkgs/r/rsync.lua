-- rsync: Fast incremental file transfer
--
-- Source: https://rsync.samba.org/
-- Provides the rsync utility for efficient file synchronization.

return {
    default = snap {
        name = "rsync",
        version = "3.4",
        summary = "Fast incremental file transfer",
        description = [[
            rsync is a fast and extraordinarily versatile file copying
            tool. It can copy locally, to/from another host over any
            remote shell, or to/from a remote rsync daemon. It offers a
            large number of options that control every aspect of its
            behavior and permit very flexible specification of the set
            of files to be copied.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        source = {
            url = "https://download.samba.org/pub/rsync/rsync-3.4.1.tar.gz",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
