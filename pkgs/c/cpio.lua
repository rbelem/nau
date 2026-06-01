-- cpio: GNU copy-in/out archive tool
--
-- Source: https://ftp.gnu.org/gnu/cpio/
-- Provides the cpio archive utility for initramfs and package creation.

return {
    default = snap {
        name = "cpio",
        version = "2.15",
        summary = "GNU copy-in/out archive tool",
        description = [[
            GNU cpio copies files into or out of a cpio or tar archive.
            Archives are files that contain a collection of other files
            plus information about them, such as their file name, owner,
            timestamps, and access permissions. cpio is commonly used in
            initramfs generation and RPM package creation.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://ftp.gnu.org/gnu/cpio/cpio-2.15.tar.bz2",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
