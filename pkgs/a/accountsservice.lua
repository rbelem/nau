-- accountsservice: D-Bus interface for user account query and manipulation
--
-- Source: https://gitlab.freedesktop.org/accountsservice/accountsservice
-- Provides the AccountsService daemon and library.

return {
    default = snap {
        name = "accountsservice",
        version = "23.13",
        summary = "D-Bus interface for user account query and manipulation",
        description = [[
            AccountsService provides a D-Bus interface for querying and
            manipulating user account information. It abstracts away the
            differences between /etc/passwd and other user databases.
            Used by display managers and desktop environments to enumerate
            users and manage their properties.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://gitlab.freedesktop.org/accountsservice/accountsservice/-/archive/23.13.9/accountsservice-23.13.9.tar.gz",
        },
        build = "meson setup build --prefix=/usr && ninja -C build && DESTDIR=$STAGE ninja -C build install",
    },
}
