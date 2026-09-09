-- curl: Command-line tool for transferring data with URLs
--
-- Source: https://curl.se/
-- Provides the curl tool and libcurl library for URL transfers.

return {
    default = snap {
        name = "curl",
        version = "8.20.0",
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
            url = "https://curl.se/download/curl-8.20.0.tar.xz",
        },
        -- --without-libpsl: curl 8.x makes libpsl a hard configure dependency
        -- (PSL cookie hardening); it is not in the pool and is optional
        -- functionality, so disable it explicitly or configure errors out
        -- ("libpsl libs and/or directories were not found").
        build = table.concat({
            "./configure --prefix=/usr --with-openssl --without-libpsl",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
            -- libtool .la metadata embeds the configure-time prefix and is
            -- obsolete at runtime (same strip as libevent/pcre2).
            "find $STAGE/usr/lib -name '*.la' -delete",
        }, " && "),

        -- Interim leak-scan escapes (ADR-0018 Decision 3, issue #22):
        -- 1. The nix gcc wrapper bakes RUNPATH=/shuttle-build-prefix/usr/lib
        --    into libcurl.so and the curl binary (htop/tig/tmux precedent).
        -- 2. configure bakes the merged prefix into the libcurl.pc Libs line
        --    and the curl-config script — build-time metadata, same class as
        --    ncurses' ncursesw6-config. All silenced visibly, pending the
        --    RUNPATH/portability repair.
        leaks_ok = { "/shuttle-build-prefix/usr/lib", "/shuttle-build-prefix" },
    },
}
