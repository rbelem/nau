-- linux-pam: Pluggable Authentication Modules for Linux
--
-- Source: https://github.com/linux-pam/linux-pam
-- Provides the PAM framework for authentication and session management.

return {
    default = snap {
        name = "linux-pam",
        version = "1.7",
        summary = "Pluggable Authentication Modules for Linux",
        description = [[
            Linux-PAM is a system of libraries that handle the
            authentication tasks of applications (services) on the system.
            The library provides a stable general interface (PAM API) that
            privilege granting programs (such as login and su) defer to for
            authentication decisions.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://github.com/linux-pam/linux-pam/releases/download/v1.7.0/Linux-PAM-1.7.0.tar.xz",
        },
        build = "./configure --prefix=/usr --sysconfdir=/etc --libdir=/usr/lib && make && make install DESTDIR=$STAGE",
    },
}
