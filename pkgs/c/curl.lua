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
        requires = { "glibc", "zlib", "openssl", "ca-certificates" },
        -- build_deps flip (the gap-3 endgame, #174 + #171): curl builds
        -- with the pool gcc payload as its declared build tool — cc for
        -- the merged build prefix, not the caller's farm overlay. The
        -- flip waited on #174: the gcc deb set used to stage linux-libc-dev
        -- uapi headers, which collided with the linux-headers payload in
        -- the merged build prefix (one owning payload per shared subtree:
        -- glibc requires linux-headers, so every prefix carrying gcc
        -- already owns uapi through it; gcc must not restage it). With the
        -- deb set clean and gcc carrying amd64/arm64/armhf sets (#171),
        -- the declared build_dep covers every arch curl advertises — no
        -- host-compiler fallback needed on any port.
        build_deps = { "gcc" },
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
            -- CURL_CA_BUNDLE: openssl's --openssldir=/etc/ssl bakes the
            -- absolute HOST CA dir into libcurl, and the installed tree
            -- carries no CA bundle — https dies with "certificate problem"
            -- exit 60 (issue #130). The bundle ships in the ca-certificates
            -- payload, so bin/curl becomes a wrapper pinning CURL_CA_BUNDLE:
            -- the staged bundle first (merged build prefix / root-mounted
            -- payload layout), then the pod store layout (farm links a
            -- wrapper-managed command straight at its store blob; two
            -- dirnames reach the pod root, the #10/#13 PODROOT derivation,
            -- and the bundle rides the active generation's ca-certificates
            -- extension tree), then the extension-tree sibling package, and
            -- finally the host pair (git wrapper precedent — trust anchors
            -- are host policy, ADR-0030). The env var only supplies
            -- defaults — an explicit --cacert/-k still wins, and an
            -- ambient CURL_CA_BUNDLE (caller's own trust choice) is
            -- never clobbered. Exec resolves
            -- the real binary beside the shim, falling back through the
            -- pod tree (#13 shape): the farm links a wrapper-managed
            -- command straight at its bare store blob, where no sibling
            -- exists.
            "mv $STAGE/usr/bin/curl $STAGE/usr/bin/curl.real",
            "printf '%s\\n' '#!/bin/sh' 'd=$(dirname \"$(readlink -f \"$0\")\")' 'p=$(dirname \"$(dirname \"$d\")\")' 'c=$d/../../etc/ssl/certs/ca-certificates.crt' 'if test ! -f \"$c\"' 'then c=$p/active/extensions/ca-certificates/usr/etc/ssl/certs/ca-certificates.crt' 'fi' 'if test ! -f \"$c\"' 'then c=$d/../../../../ca-certificates/usr/etc/ssl/certs/ca-certificates.crt' 'fi' 'if test ! -f \"$c\"' 'then c=/etc/ssl/certs/ca-certificates.crt' 'fi' 'if test ! -f \"$c\"' 'then c=/etc/pki/tls/certs/ca-bundle.crt' 'fi' 'if test -f \"$c\" && test -z \"$CURL_CA_BUNDLE\"' 'then CURL_CA_BUNDLE=$c' 'export CURL_CA_BUNDLE' 'fi' 'r=$d/curl.real' 'if test ! -f \"$r\"' 'then r=$p/active/extensions/curl/usr/usr/bin/curl.real' 'fi' 'exec \"$r\" \"$@\"' > $STAGE/usr/bin/curl",
            "chmod +x $STAGE/usr/bin/curl",
        }, " && "),

        -- Interim leak-scan escapes (ADR-0018 Decision 3, issue #22):
        -- 1. The nix gcc wrapper bakes RUNPATH=/shuttle-build-prefix/usr/lib
        --    into libcurl.so and the curl binary (htop/tig/tmux precedent).
        -- 2. configure bakes the merged prefix into the libcurl.pc Libs line
        --    and the curl-config script — build-time metadata, same class as
        --    ncurses' ncursesw6-config. All silenced visibly, pending the
        --    RUNPATH/portability repair.
        leaks_ok = {
            "/shuttle-build-prefix/usr/lib",
            "/shuttle-build-prefix/usr/lib64",
            "/shuttle-build-prefix",
        },
    },
}
