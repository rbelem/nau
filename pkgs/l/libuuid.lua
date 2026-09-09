-- libuuid: DCE compatible Universally Unique Identifier library.
--
-- The canonical libuuid ships inside the util-linux release tarball;
-- this port builds ONLY the library (headers + shared object +
-- pkg-config metadata) via --disable-all-programs --enable-libuuid,
-- so consumers (e.g. libmount users) pull a small payload instead of
-- the whole util-linux tool set.
--
-- Requires: glibc

return {
    default = snap {
        name = "libuuid",
        version = "2.42",
        summary = "DCE compatible Universally Unique Identifier library",
        description = [[
            libuuid is used to generate unique identifiers for objects
            that may be accessible beyond the local system (UUIDs as
            specified by RFC 9530, formerly RFC 4122). This package
            carries only the library from the util-linux release: the
            uuid.h header, the shared object, and its pkg-config file.
        ]],
        license = "GPL-3.0-or-later",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },

        source = {
            url = "https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v2.42/util-linux-2.42.tar.xz",
            sha256 = "3452b260bbaa775d6e749ac3bb22111785003fc1f444970025c8da26dfa758e9",
        },

        build = table.concat({
            "./configure --prefix=/usr --disable-all-programs --enable-libuuid --without-systemd",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
        }, " && "),

        type = "source",
        requires = { "glibc" },
    },
}
