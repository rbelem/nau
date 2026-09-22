-- ca-certificates: Mozilla CA certificate bundle
--
-- Source: https://curl.se/docs/caextract.html
-- Provides root CA certificates for TLS certificate verification.

return {
    default = snap {
        name = "ca-certificates",
        version = "2026",
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
        type = "source",
        requires = { "glibc" },
        -- Dated bundles rotate off curl.se (the 2025-01-01 pin 404'd —
        -- found while landing #130, which makes this package a hard curl
        -- require). Pin the current bundle AND its sha256: this payload
        -- is the trust anchor every wrapped curl ends up importing.
        source = {
            url = "https://curl.se/ca/cacert-2026-08-13.pem",
            -- sha256 f66dff1b…4d28480bc9 verified against the fetched
            -- bytes; matches the published cacert.pem.sha256 and the
            -- 2026-08-13 row (121 certs) on curl.se/docs/caextract.
            sha256 = "f66dff1bdf8f96060b8177976f8b7d9254bc89bc4db933d769f7384d28480bc9",
        },
        build = "mkdir -p $STAGE/etc/ssl/certs && cp cacert-2026-08-13.pem $STAGE/etc/ssl/certs/ca-certificates.crt && cd $STAGE/etc/ssl/certs && c_rehash .",
    },
}
