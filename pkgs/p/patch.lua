-- patch: GNU patch for applying diff files
--
-- Source: https://ftp.gnu.org/gnu/patch/
-- Provides the patch utility for applying diff/patch files.

return {
    default = snap {
        name = "patch",
        version = "2.7",
        summary = "GNU patch for applying diff files",
        description = [[
            GNU patch takes a patch file containing a difference listing
            produced by the diff program and applies those differences to
            one or more original files, producing patched versions. It is
            an essential tool for software development and package building.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://ftp.gnu.org/gnu/patch/patch-2.7.6.tar.xz",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
