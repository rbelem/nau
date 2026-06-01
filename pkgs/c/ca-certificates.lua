-- ca-certificates: Mozilla CA certificate bundle
--
-- Source: https://curl.se/docs/caextract.html
-- Provides root CA certificates for TLS certificate verification.

return {
    default = snap {
        name = "ca-certificates",
        version = "2025",
        summary = "Mozilla CA certificate bundle",
        description = [[
            ca-certificates provides a curated collection of root CA
            certificates extracted from Mozilla's NSS certificate store.
            These certificates are used by TLS libraries (OpenSSL, GnuTLS)
            to verify the identity of remote servers. Updated regularly
            to reflect changes in Mozilla's trust store.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        source = {
            url = "https://curl.se/ca/cacert-2025-01-01.pem",
        },
        build = "mkdir -p $STAGE/etc/ssl/certs && cp cacert-2025-01-01.pem $STAGE/etc/ssl/certs/ca-certificates.crt && cd $STAGE/etc/ssl/certs && c_rehash .",
    },
}
