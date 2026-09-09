-- gmp: GNU Multiple Precision Arithmetic Library
--
-- Source: https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.xz
return {
    default = snap {
        name = "gmp",
        version = "6.3.0",
        summary = "GNU Multiple Precision Arithmetic Library",
        description = [[GMP 6.3.0 is a free library for arbitrary precision arithmetic, operating
on signed integers, rational numbers, and floating-point numbers. It provides
a rich set of functions with a regular interface. GMP is a required dependency
for building GCC, MPFR, and MPC.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        requires = {},
        -- build_deps m4: GMP's build assembles its mpn assembly by running
        -- .asm files through m4; the sandbox toolchain ships none, so the
        -- pool m4 must be on the build PATH (merged build prefix, ADR-0018).
        build_deps = { "m4" },
        source = { url = "https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.xz" },
        build = table.concat({
            -- CFLAGS -O2 -std=gnu17: GMP 6.3.0's configure "long long
            -- reliability test 1" probe relies on pre-C23 semantics — it
            -- defines `void g(){}` (unspecified parameters before C23) and
            -- then calls `g` with 6 arguments. GCC 16 defaults to C23, where
            -- `()` means `(void)`, so the call is a hard "too many arguments"
            -- error and configure concludes "could not find a working
            -- compiler". Pin the gnu17 dialect so the probe compiles and runs
            -- for real (not masked). User CFLAGS fully replace GMP's default
            -- flags, so -O2 must be restated; the x86_64 compiler default
            -- -m64 keeps the ABI=64 probe's codegen correct.
            "./configure --prefix=/usr CFLAGS=\"-O2 -std=gnu17\" && make && make install DESTDIR=$STAGE",
            -- libtool drops .la metadata next to the libraries carrying
            -- absolute build-time paths (dependency_libs embeds the sandbox
            -- LDFLAGS, -L/shuttle-build-prefix/usr/lib); nothing in the pool
            -- consumes libtool archives at runtime, so strip them from the
            -- payload rather than ship build-host paths (libstdcpp/curl
            -- precedent).
            "find $STAGE -name '*.la' -type f -delete",
        }, " && "),
    },
}
