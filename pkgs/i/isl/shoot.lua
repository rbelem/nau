-- isl: Integer Set Library for GCC loop optimization
--
-- Source: https://libisl.sourceforge.io/isl-0.27.tar.xz
return {
    default = snap {
        name = "isl",
        version = "0.27",
        summary = "Integer Set Library for gcc loop optimization",
        description = [[ISL 0.27 is a C library for manipulating sets and relations of integer
points bounded by linear constraints. It supports operations like union,
intersection, and polyhedral transformations. GCC uses ISL for its Graphite
loop optimization framework to perform advanced loop nest optimizations.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        requires = { "gmp" },
        source = { url = "https://libisl.sourceforge.io/isl-0.27.tar.xz" },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
