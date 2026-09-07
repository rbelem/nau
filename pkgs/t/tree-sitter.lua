-- tree-sitter: the tree-sitter CLI — parser generator and playground
-- for tree-sitter grammars (parse/generate/test commands).
--
-- Ported from the devbox global profile as a prebuilt release binary:
-- the upstream linux-x64 .gz asset (a bare gzip of the binary, not a
-- tarball — it stays raw in the build dir) is fetched, sha256-pinned,
-- decompressed with python3's gzip module (no gunzip guarantee in the
-- build sandbox), and staged into usr/bin.

return {
    default = snap {
        name = "tree-sitter",
        version = "0.26.9",
        summary = "Parser generator toolset (tree-sitter CLI)",
        description = [[
            The tree-sitter command-line interface builds tree-sitter
            grammars (generate), parses and highlights source files
            (parse, highlight), and runs grammar test corpora (test).
            Tree-sitter is a parser generator tool and incremental
            parsing library used by editors for error-tolerant syntax
            trees.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/tree-sitter/tree-sitter/releases/download/v0.26.9/tree-sitter-linux-x64.gz",
            sha256 = "9ce82137caa65864e7ca8b869fd391cef88c9bd2a01c4371b9c4dd26c2585efb",
        },

        build = table.concat({
            "python3 -c \"import gzip,shutil; shutil.copyfileobj(gzip.open('tree-sitter-linux-x64.gz','rb'), open('tree-sitter','wb'))\"",
            "chmod +x tree-sitter",
            "install -Dm755 tree-sitter $STAGE/usr/bin/tree-sitter",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            ["tree-sitter"] = app {
                command = "usr/bin/tree-sitter",
            },
        },
    },
}
