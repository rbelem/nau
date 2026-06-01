-- libgcrypt: GNU cryptographic library
--
-- Source: https://gnupg.org/ftp/gcrypt/libgcrypt/
-- Provides a general-purpose cryptographic library.

return {
    default = snap {
        name = "libgcrypt",
        version = "1.11",
        summary = "GNU cryptographic library",
        description = [[
            Libgcrypt is a general-purpose cryptographic library based on
            the code from GnuPG. It provides functions for all
            cryptographic building blocks: symmetric ciphers, hash
            algorithms, MACs, public key algorithms, large integer
            functions, and random number generation.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-1.11.1.tar.bz2",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
