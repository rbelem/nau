-- libseccomp: high-level interface to the Linux kernel's seccomp
-- system call filtering facility.
--
-- Pool port (issue #215): the ONLY required C dependency of podman's
-- default local build — the `seccomp` BUILDTAG is hard-coded on linux
-- (podman Makefile BUILDTAGS) and its cgo directive is
-- `#cgo pkg-config: libseccomp` (vendored
-- go.podman.io/seccomp/libseccomp-golang). Without it podman builds
-- with `seccomp_unsupported.go`, and every `podman run` that does not
-- pass `--security-opt seccomp=unconfined` dies at spec generation
-- with "seccomp not enabled in this build"
-- (common/pkg/seccomp/seccomp_unsupported.go errNotSupported).
-- Runtime consumers resolve libseccomp.so.2 by name through the #10
-- loader-lib machinery, exactly like zg's libstdcpp/libgcc pair.
--
-- Fetch tier: pinned upstream release tarball. The tarball even ships
-- the pre-generated syscalls.perf.c, but that is irrelevant: 2.6.x's
-- configure runs an unconditional gperf check and hard-errors without
-- it (as_fn_error "please install gperf"; src/Makefile.am regenerates
-- syscalls.perf via arch-gperf-generate), so build_deps carry the pool
-- gperf (pkgs/g/gperf, issue #216) on top of gcc + make.
--
-- Checksum cross-verified against the upstream
-- libseccomp-2.6.1.tar.gz.SHA256SUM asset (exact line match).

return {
    default = snap {
        name = "libseccomp",
        version = "2.6.1",
        summary = "High-level interface to Linux seccomp filtering",
        description = [[
            libseccomp provides a convenient, architecture-independent
            interface to the Linux kernel's seccomp system call
            filtering facility: PFC filter generation, per-arch
            translation, and filter installation via prctl(2). Built
            from the upstream release tarball for the pool's podman
            port (issue #215); its seccomp BUILDTAG links this library
            through the cgo pkg-config probe.
        ]],
        license = "LGPL-2.1-only",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/seccomp/libseccomp/releases/download/v2.6.1/libseccomp-2.6.1.tar.gz",
            sha256 = "501f66c667225d53791b97e1d7cf85ab764c297d04881f60f38f451c4b0ee1be",
        },

        -- Release tarball: configure is pre-generated. --disable-static:
        -- the consumer (podman's cgo) links the shared SONAME
        -- (libseccomp.so.2); a static archive would only widen the
        -- leak-scan surface.
        build = table.concat({
            "./configure --prefix=/usr --disable-static",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
        }, " && "),

        type = "source",
        requires = { "glibc" },
        build_deps = { "gcc", "make", "gperf" },

        -- The gcc payload's link driver bakes the merged build prefix into
        -- the RUNPATH of both ELFs (the .so and scmp_sys_resolver; exact
        -- string, per the cmake/make class), and libseccomp.la embeds the
        -- bare prefix in dependency_libs (the binutils 44550d7 class: .la
        -- files matter only at libtool link time, so the bare-prefix entry
        -- covers it while ELF scanning stays strict).
        leaks_ok = {
            "/shuttle-build-prefix/usr/lib64",
            "/shuttle-build-prefix/usr/lib",
            "/shuttle-build-prefix",
        },

        apps = {},
    },
}
