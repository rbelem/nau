-- shadow: Shadow password file utilities
--
-- Source: https://github.com/shadow-maint/shadow
-- Provides user and group management utilities (useradd, passwd, etc.).

return {
    default = snap {
        name = "shadow",
        version = "4.17",
        summary = "Shadow password file utilities",
        description = [[
            The shadow-utils package includes the necessary programs for
            converting UNIX password files to the shadow password format,
            plus programs for managing user and group accounts. Includes
            useradd, userdel, usermod, groupadd, groupdel, groupmod,
            login, su, passwd, chage, and related utilities.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://github.com/shadow-maint/shadow/releases/download/4.17.4/shadow-4.17.4.tar.gz",
        },
        build = "./configure --prefix=/usr --sysconfdir=/etc --with-libpam && make && make install DESTDIR=$STAGE",
    },
}
