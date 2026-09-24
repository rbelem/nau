-- cmake: Cross-platform build system generator
--
-- Source: https://github.com/Kitware/CMake/releases/download/v3.31.0/cmake-3.31.0.tar.gz
return {
    default = snap {
        name = "cmake",
        version = "3.31.0",
        summary = "Cross-platform build system generator",
        description = [[CMake is a family of tools designed to build, test and package software.
It generates native makefiles and workspaces that can be used in any
compiler environment, supporting out-of-source and cross-platform builds.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        -- Cold-build closure (issue #114): the cmake binary links
        -- libstdc++/libgcc_s and the hermetic build sandbox resolves
        -- shared libraries only from the merged build prefix — with
        -- requires = {} the prefix carried neither, so consumers found
        -- cmake but could not exec it (dconf's meson: "Found CMake
        -- '/shuttle-build-prefix/usr/bin/cmake' but couldn't run it"),
        -- and a truly cold store dies at ninja's own build, which drives
        -- this cmake. Installed-pod operation only ever worked through
        -- the unrelated libstdcpp/libgcc pod extensions.
        requires = { "glibc", "libstdcpp", "libgcc" },
        source = { url = "https://github.com/Kitware/CMake/releases/download/v3.31.0/cmake-3.31.0.tar.gz" },
        -- -DCMAKE_USE_OPENSSL=OFF: the sandbox has no OpenSSL and cmake's
        -- bundled-curl crypto features are unused by its consumers (the
        -- pool ninja build). Bootstrap fails hard without this flag.
        build = "./configure --prefix=/usr -- -DCMAKE_USE_OPENSSL=OFF && make && make install DESTDIR=$STAGE",

        -- Interim leak-scan escape (ADR-0018 Decision 3, issue #22), same
        -- rationale as tmux/htop/tig: the leaked nix gcc wrapper bakes
        -- RUNPATH=/shuttle-build-prefix/usr/lib64 into the produced
        -- cmake/cpack/test binaries (the lib64 spelling joined the baked
        -- set when the pool glibc payload's loader-lib list gained the
        -- lib64 dir). That path does not exist at runtime; silenced here,
        -- visibly logged by the leak scan, pending the RUNPATH repair
        -- (issue #22's portability follow-up).
        leaks_ok = { "/shuttle-build-prefix/usr/lib64" },
    },
}
