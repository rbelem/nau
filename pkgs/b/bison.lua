-- bison: GNU parser generator (yacc compatible)
--
-- Source: https://ftp.gnu.org/gnu/bison/bison-3.8.2.tar.xz
-- (mirrors.kernel.org copy hashed: 9bba0214ccf7f1079c5d59210045227bcf619519840ebfa80cd3849cff5a5bf2)
-- Ported 2026-09-25: tmux 3.7's configure wants yacc and there was no
-- bison member — the drift rebuild died "yacc not found" (ADR-0018:
-- no implicit host tools).

return {
    default = snap {
        name = "bison",
        version = "3.8.2",
        summary = "GNU parser generator",
        description = [[Bison is a general-purpose parser generator that converts an
annotated context-free grammar into a deterministic LR or generalized LR
(GLR) parser. Installs bison and the yacc compatibility front end.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        requires = { "glibc", "m4" },
        source = { url = "https://ftp.gnu.org/gnu/bison/bison-3.8.2.tar.xz" },
        -- ADR-0018: no implicit host toolchain.
        build_deps = { "gcc", "make" },
        -- configure's help2man doc step is skipped when xexec is absent;
        -- m4 rides requires because generated parsers and bison itself
        -- exec it at runtime.
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
