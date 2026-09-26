-- make: GNU Make build automation tool
--
-- Source: https://ftp.gnu.org/gnu/make/make-4.4.1.tar.gz
return {
    default = snap {
        name = "make",
        version = "4.4.1",
        summary = "GNU Make build automation tool",
        description = [[GNU Make 4.4.1 is a tool which controls the generation of executables and
other non-source files from source files. It automatically determines which
pieces of a large program need to be recompiled and issues commands to
recompile them.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://ftp.gnu.org/gnu/make/make-4.4.1.tar.gz",
            sha256 = "dd16fb1d67bfab79a72f5e8390735c49e3e8e70b4945a15ab1f81ddb78658fb3",
        },
        -- ADR-0018: no implicit host toolchain — the sandbox is env_clear,
        -- and this rebuild (recipe drift swept by `pod refresh automake`,
        -- issue #211) proved configure finds no compiler without the decl.
        build_deps = { "gcc", "make" },
        -- The gcc payload's link driver bakes the merged build prefix into
        -- the RUNPATH; make only ever executes inside build sandboxes where
        -- that prefix is mounted (leaks_ok both-spellings treatment, the
        -- autoconf/automake/binutils precedent, #180 residual notes).
        leaks_ok = { "/shuttle-build-prefix/usr/lib64", "/shuttle-build-prefix/usr/lib" },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
