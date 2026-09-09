-- libevent: event notification library
--
-- Ported as a pool prerequisite for tmux (tmux requires libevent >= 2
-- via pkg-config). Built from the upstream release tarball (configure
-- pre-generated — no autogen needed), sha256-pinned. OpenSSL support is
-- disabled (--disable-openssl): tmux only needs the core libevent, and
-- keeping the payload minimal avoids pulling openssl into the closure.
--
-- Runtime note: libevent is a shared-library dependency of tmux; it is
-- a `requires` entry (link-time AND runtime), which per ADR-0018 also
-- materializes into the merged build prefix so tmux can find it.

return {
    default = snap {
        name = "libevent",
        version = "2.1.12-stable",
        summary = "Event notification library",
        description = [[
            The libevent API provides a mechanism to execute a function
            when a specific event occurs on a file descriptor or after a
            given timeout. It is used by tmux and other event-driven
            applications. Built by default without OpenSSL support
            (the core library is all tmux needs).
        ]],
        license = "BSD-3-Clause",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz",
            sha256 = "92e6de1be9ec176428fd2367677e61ceffc2ee1cb119035037a27d346b0403bb",
        },

        build = table.concat({
            "./configure --prefix=/usr --disable-openssl",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
            -- libtool .la metadata files embed the configure-time prefix
            -- (/shuttle-build-prefix) and are obsolete at runtime — the shared
            -- .so libraries and .pc pkg-config files are what consumers need.
            -- Strip them so they cannot leak the build prefix.
            "find $STAGE/usr/lib -name '*.la' -delete",
        }, " && "),

        type = "source",
        requires = { "glibc" },
    },
}
