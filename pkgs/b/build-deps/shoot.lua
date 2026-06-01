-- build-deps: build essentials + default toolchain
--
-- Meta-package declaring the build dependencies needed to compile
-- packages from source. Includes autotools, make, pkg-config, and
-- the default toolchain (resolved via "toolchain" alias).
--
-- Aliases: build-essential
-- Requires: make, autoconf, automake, libtool, m4, texinfo, gettext,
--           pkg-config, perl, toolchain (resolves to default)

return {
    default = snap {
        name = "build-deps",
        version = "1.0.0",
        summary = "Build essentials including default toolchain for x86_64",
        description = [[
            Build dependencies meta-package. Declares the tools needed
            to compile source packages: GNU Autotools (autoconf, automake,
            libtool), make, pkg-config, texinfo, gettext, m4, and the
            default toolchain (toolchain → toolchain-gcc-gnu-x86_64).
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        aliases = { "build-essential" },
        requires = {
            "make", "autoconf", "automake", "libtool", "m4",
            "texinfo", "gettext", "pkg-config",
            "perl",  -- pulled by autotools
            "toolchain",  -- resolves via alias → gcc-gnu-x86_64
        },
    },
}
