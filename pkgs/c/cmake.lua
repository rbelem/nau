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
        requires = {},
        source = { url = "https://github.com/Kitware/CMake/releases/download/v3.31.0/cmake-3.31.0.tar.gz" },
        -- -DCMAKE_USE_OPENSSL=OFF: the sandbox has no OpenSSL and cmake's
        -- bundled-curl crypto features are unused by its consumers (the
        -- pool ninja build). Bootstrap fails hard without this flag.
        build = "./configure --prefix=/usr -- -DCMAKE_USE_OPENSSL=OFF && make && make install DESTDIR=$STAGE",
    },
}
