-- openssl: cryptography and SSL/TLS toolkit
--
-- Source: https://www.openssl.org/source/
-- Provides cryptographic libraries (libcrypto, libssl) and command-line tools.
-- Required for secure network communications and package verification.

return {
    default = snap {
        name = "openssl",
        version = "3.6.2",
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
            url = "https://www.openssl.org/source/openssl-3.6.2.tar.gz",
        },
        -- --libdir=lib: openssl's Configure defaults to lib64 on x86_64, but
        -- the pool merged-prefix convention (ADR-0018) is a single /usr tree
        -- where consumers look in usr/lib (LDFLAGS/PKG_CONFIG_PATH only cover
        -- usr/lib and usr/lib/pkgconfig). Without this, curl's configure
        -- cannot detect OpenSSL ("--with-openssl was given but OpenSSL could
        -- not be detected") because its .pc files and .so libs land in
        -- usr/lib64, outside the build-prefix lookup paths.
        build = "./Configure --prefix=/usr --libdir=lib --openssldir=/etc/ssl && make && make install DESTDIR=$STAGE",

        -- Interim leak-scan escape (ADR-0018 Decision 3, issue #22), same
        -- rationale as tmux/htop/tig: the leaked nix gcc wrapper bakes
        -- RUNPATH=/shuttle-build-prefix/usr/lib64 into the produced
        -- openssl binary and libraries (the lib64 spelling joined the
        -- baked set when the pool glibc payload's loader-lib list gained
        -- the lib64 dir). That path does not exist at runtime; silenced
        -- here, visibly logged by the leak scan, pending the RUNPATH
        -- repair (issue #22's portability follow-up).
        leaks_ok = { "/shuttle-build-prefix/usr/lib64" },
    },
}
