-- git: distributed version control (full feature set)
--
-- Ported from the devbox global profile as a source build. This is the
-- "full" git binary: built with https (libcurl), TLS/SSH (openssl),
-- compression (zlib), and PCRE2 pattern support, so it speaks the full
-- git smart protocol and remote helpers. Built directly with git's own
-- Makefile (autodetecting libcurl/openssl/zlib/pcre2 via the merged build
-- prefix); no `make configure` needed (autoconf not required).
--
-- Runtime deps: glibc, zlib, openssl, curl, pcre2 — all link-time AND
-- runtime libraries, so they go in `requires` (which per ADR-0018 also
-- materializes into the merged build prefix so the build can find them).
-- perl (issue #34): runtime for git's perl-side helpers (git-send-email,
-- git-svn, git-add--interactive...) and build-time only as a probe target
-- — the pool perl lands in the merged prefix, the build's PATH prepends
-- its bin, and git's Makefile perl probes succeed, so the perl-built
-- helpers ship with a /usr/bin/perl shebang that resolves inside a pod
-- closure. The toolchain (compiler) and pkg-config are build-time-only,
-- so they go in `build_deps`.
--
-- Not included: tcl/tk (gitk/git-gui) is NOT in the pool — built with
-- NO_TCLTK.
--
-- Requires: glibc, zlib, openssl, curl, pcre2, perl
-- build_deps: pkg-config, gettext

return {
    default = snap {
        name = "git",
        version = "2.47.2",
        summary = "Distributed version control system (full)",
        description = [[
            Git is a free and open source distributed version control
            system designed to handle everything from small to very large
            projects with speed and efficiency. This build is the full
            git binary: https transport (libcurl), TLS/SSH (openssl),
            zlib compression, and PCRE2 regex support.
        ]],
        license = "GPL-2.0-only",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/git/git/archive/refs/tags/v2.47.2.tar.gz",
            sha256 = "9d9e5d9b762188550b1dffaacea7f9709a43979b030c17f9424b2b27333ad52b",
        },

        build = table.concat({
            -- NO_EXPAT=1: git's http-push.c (legacy WebDAV push) is the only
            -- consumer of expat, which is not in the pool; smart-HTTP
            -- fetch/push via remote-curl does not need it.
            -- NO_TCLTK=1: gitk/git-gui need Tcl/Tk, which is not in the pool;
            -- without the flag the git-gui subdir runs po/*.msg builds and
            -- dies on the missing Tcl interpreter (Error 127).
            -- USE_LIBPCRE2=1: link the pool pcre2 so `git grep -P` works.
            -- CFLAGS -std=gnu17: the sandbox gcc (16.x) defaults to C23, where
            -- `thread_local` is a keyword; git 2.47 predates C23 support
            -- (upstream fixed in 2.48+) and fails to compile (index-pack.c
            -- "expected '{' before 'thread_local'"). Pin the gnu17 dialect.
            -- CPPFLAGS -I. first: the pool glibc payload ships its own tar.h
            -- (POSIX variant, no `struct ustar_header`), and the sandbox puts
            -- the build-prefix include dir before the Makefile's -I., so
            -- glibc's tar.h shadows git's own for builtin/get-tar-commit-id.c
            -- (a quoted include from builtin/ — the source root is not the
            -- file's dir). Search the source root first.
            -- LDFLAGS passed through: git's Makefile assigns LDFLAGS
            -- internally, silently discarding the sandbox's
            -- -L/shuttle-build-prefix/usr/lib (configure-based builds bake it
            -- into their Makefiles; plain-make git does not) — so -lz/-lssl/
            -- -lcrypto/-lpcre2-8 fail to link. Re-pass it as an override.
            -- PATH prepends the merged prefix bin: git probes dependencies by
            -- RUNNING curl-config / pcre2-config via $(shell ...), and the
            -- prefix bin dir is not on the sandbox PATH by default (meson's
            -- launcher documents the same convention). LD_LIBRARY_PATH makes
            -- those probe/build tools loadable (msgfmt needs the prefix's
            -- libgettextsrc).
            "PATH=\"$SHUTTLE_BUILD_PREFIX/usr/bin:$PATH\" LD_LIBRARY_PATH=\"$SHUTTLE_BUILD_PREFIX/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\" make -j$(nproc) prefix=/usr NO_EXPAT=1 NO_TCLTK=1 USE_LIBPCRE2=1 CFLAGS=\"-g -O2 -std=gnu17\" CPPFLAGS=\"-I. $CPPFLAGS\" LDFLAGS=\"$LDFLAGS\"",
            "PATH=\"$SHUTTLE_BUILD_PREFIX/usr/bin:$PATH\" LD_LIBRARY_PATH=\"$SHUTTLE_BUILD_PREFIX/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\" make install prefix=/usr NO_EXPAT=1 NO_TCLTK=1 USE_LIBPCRE2=1 CFLAGS=\"-g -O2 -std=gnu17\" CPPFLAGS=\"-I. $CPPFLAGS\" LDFLAGS=\"$LDFLAGS\" DESTDIR=$STAGE",
        }, " && "),

        type = "source",
        requires = { "glibc", "zlib", "openssl", "curl", "pcre2", "perl" },
        -- pkg-config: git's own Makefile probes libcurl/libpcre2 via
        -- pkg-config-provided metadata (curl-config/pcre2-config are the
        -- primary probes; pkg-config backs the USE_LIBPCRE2 detection).
        -- gettext: msgfmt compiles git's po/ translation catalogs at build
        -- time (runtime libintl comes from glibc itself).
        -- Both are build-time-only tools; the sandbox provides the compiler.
        build_deps = { "pkg-config", "gettext" },

        -- Interim leak-scan escape (ADR-0018 Decision 3, issue #22), same
        -- rationale as htop/tig/tmux: the nix gcc wrapper bakes
        -- RUNPATH=/shuttle-build-prefix/usr/lib into every binary and
        -- libexec/git-core helper git installs (~90 outputs, one shared
        -- reference string). That path does not exist at runtime; silenced
        -- here, visibly logged by the leak scan, pending the RUNPATH repair
        -- (issue #22's portability follow-up).
        leaks_ok = { "/shuttle-build-prefix/usr/lib" },

        apps = {
            git = app {
                command = "usr/bin/git",
            },
        },
    },
}
