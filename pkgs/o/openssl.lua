-- openssl: cryptography and SSL/TLS toolkit
--
-- Source: https://www.openssl.org/source/
-- Provides cryptographic libraries (libcrypto, libssl) and command-line tools.
-- Required for secure network communications and package verification.

return {
    default = snap {
        name = "openssl",
        version = "3.4.1",
        summary = "Cryptography and SSL/TLS toolkit",
        description = [[
            OpenSSL is a robust, commercial-grade, full-featured toolkit for
            the Transport Layer Security (TLS) and Secure Sockets Layer (SSL)
            protocols. Includes libcrypto (general-purpose cryptography) and
            libssl (TLS/SSL implementation).
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc", "zlib" },
        source = {
            url = "https://www.openssl.org/source/openssl-3.4.1.tar.gz",
        },
        build = "./Configure --prefix=/usr --openssldir=/etc/ssl && make && make install DESTDIR=$STAGE",
    },
}
