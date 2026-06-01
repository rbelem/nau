-- btrfs-progs: Btrfs filesystem utilities
--
-- Source: https://mirrors.edge.kernel.org/pub/linux/kernel/people/kdave/btrfs-progs/
-- Provides mkfs.btrfs, btrfs, and related filesystem management tools.

return {
    default = snap {
        name = "btrfs-progs",
        version = "6.12",
        summary = "Btrfs filesystem utilities",
        description = [[
            btrfs-progs provides the userspace utilities for managing the
            Btrfs filesystem. Includes mkfs.btrfs for creating filesystems,
            btrfs for general management (subvolume, snapshot, scrub,
            balance, device, filesystem), and btrfsck for checking and
            repairing Btrfs filesystems.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://mirrors.edge.kernel.org/pub/linux/kernel/people/kdave/btrfs-progs/btrfs-progs-v6.12.tar.xz",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
