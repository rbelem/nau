-- openssh: secure shell server and client
--
-- Source: https://www.openssh.com/
-- Provides sshd (server), ssh (client), scp, sftp, and ssh-keygen.
-- Essential for remote system administration and secure file transfer.

return {
    default = snap {
        name = "openssh",
        version = "10.3p1",
        summary = "Secure shell server and client",
        description = [[
            OpenSSH provides secure encrypted communication between two
            untrusted hosts over an insecure network. Includes the sshd
            server daemon, ssh client, scp, sftp, and key management tools.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc", "openssl", "zlib" },
        source = {
            url = "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-9.9p2.tar.gz",
        },
        build = "./configure --prefix=/usr --sysconfdir=/etc/ssh --with-md5-passwords && make && make install DESTDIR=$STAGE",
    },
}
