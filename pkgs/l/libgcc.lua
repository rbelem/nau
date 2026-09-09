-- libgcc: GCC low-level runtime library (libgcc_s.so.1)
--
-- Prebuilt relayout of Debian trixie's libgcc-s1 (GCC 14.2.0 — version-
-- matched to the pool libstdcpp), following the pool's prebuilt-source
-- precedent (python's python-build-standalone, git-credential-manager).
--
-- Why prebuilt: building libgcc from the GCC source tree outside a
-- compiler bootstrap is actively unsupported. Its Makefile consumes
-- generated artifacts of the GCC build proper (libgcc.mvars, tm.h ->
-- defaults.h -> insn-modes.h, auto-host.h) that only an in-tree compiler
-- build produces; hand-seeding them accretes an unbounded set of
-- build-tree stubs, and a full compiler bootstrap is not a proportionate
-- build for a ~70KB runtime library. The .deb lands raw in $SRC (the
-- source layer only auto-extracts tarballs) and is unpacked with the
-- sandbox's own ar + xz tar.
--
-- Payload contract: SONAME libgcc_s.so.1, DT_NEEDED libc only, symbol
-- versions GCC_3.0 .. GCC_12.0.0 — covers libstdc++ 14.2 and prebuilt
-- consumers (git-credential-manager's .NET host). Relaid out from
-- Debian's multiarch path to the pool's /usr/lib64 (default ld.so
-- search path), plus the linker-facing libgcc_s.so symlink so
-- -lgcc_s resolves against the pool copy inside a build prefix.

return {
    default = snap {
        name = "libgcc",
        version = "14.2.0",
        summary = "GCC low-level runtime library (libgcc_s.so.1)",
        description = [[
            libgcc is the GCC runtime support library. It provides the
            unwinder (_Unwind_*), software integer arithmetic, and other
            compiler-internal helpers that generated code links against
            via libgcc_s.so.1. Runtime companion to the pool libstdcpp
            (GNU Standard C++ Library), version-matched at GCC 14.2.0.
        ]],
        grade = "stable",
        confinement = "strict",
        -- amd64 only, like the rest of the pool that actually builds on
        -- this host: arm64/armhf would need a configured cross toolchain.
        architectures = { "amd64" },
        type = "source",
        requires = { "glibc" },

        source = {
            url = "http://deb.debian.org/debian/pool/main/g/gcc-14/libgcc-s1_14.2.0-19_amd64.deb",
            sha256 = "3c71917b490d1a17aed43196a2787a256ecf060526cdb20216a74bedc061b150",
        },

        build = table.concat({
            -- A .deb is an ar archive holding debian-binary, control
            -- tarball and data tarball; binutils' ar + xz tar unpack it.
            "mkdir deb",
            "cd deb",
            "ar x $SRC/*.deb",
            "mkdir data",
            "tar -xaf data.tar.xz -C data",
            "install -Dm755 data/usr/lib/x86_64-linux-gnu/libgcc_s.so.1 $STAGE/usr/lib64/libgcc_s.so.1",
            "ln -s libgcc_s.so.1 $STAGE/usr/lib64/libgcc_s.so",
        }, " && "),
    },
}
