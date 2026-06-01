-- gnupg: GNU Privacy Guard cryptographic suite
--
-- Source: https://gnupg.org/ftp/gcrypt/gnupg/
-- Provides the gpg tool for encryption, signing, and key management.

return {
    default = snap {
        name = "gnupg",
        version = "2.5",
        summary = "GNU Privacy Guard cryptographic suite",
        description = [[
            GnuPG is a complete and free implementation of the OpenPGP
            standard as defined by RFC4880. It is used for encrypting and
            signing data and communications. The gpg2 binary provides the
            core functionality, while gpg-agent manages private keys.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://gnupg.org/ftp/gcrypt/gnupg/gnupg-2.5.5.tar.bz2",
        },
        build = "./configure --prefix=/usr --sysconfdir=/etc && make && make install DESTDIR=$STAGE",
    },
}
