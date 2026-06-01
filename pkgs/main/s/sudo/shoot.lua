-- sudo: Execute a command as another user
--
-- Source: https://www.sudo.ws/
-- Provides the sudo privilege escalation utility.

return {
    default = snap {
        name = "sudo",
        version = "1.9",
        summary = "Execute a command as another user",
        description = [[
            sudo allows a permitted user to execute a command as the
            superuser or another user, as specified by the security
            policy. The real and effective uid and gid are set to match
            those of the target user as specified in the passwd database.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        source = {
            url = "https://www.sudo.ws/dist/sudo-1.9.17p2.tar.gz",
        },
        build = "./configure --prefix=/usr --sysconfdir=/etc --with-pam && make && make install DESTDIR=$STAGE",
    },
}
