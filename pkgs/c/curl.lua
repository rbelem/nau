-- curl: Command-line tool for transferring data with URLs
--
-- Source: https://curl.se/
-- Provides the curl tool and libcurl library for URL transfers.

return {
    default = snap {
        name = "curl",
        version = "8.12",
        summary = "Command-line tool for transferring data with URLs",
        description = [[
            curl is a command-line tool for transferring data with URL
            syntax. It supports HTTP, HTTPS, FTP, FTPS, SCP, SFTP, TFTP,
            DICT, TELNET, LDAP, FILE, IMAP, SMTP, POP3 and RTSP protocols.
            Also provides libcurl, a client-side URL transfer library.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc", "zlib", "openssl" },
        source = {
            url = "https://curl.se/download/curl-8.12.1.tar.xz",
        },
        build = "./configure --prefix=/usr --with-openssl && make && make install DESTDIR=$STAGE",
    },
}
