-- graphify: turn any folder into a queryable knowledge graph, with Perl
-- support (rbelem/graphify fork of safishamsi/graphify, v9-perl line).
--
-- Ported from devbox-global's devbox.d/graphify flake. The flake consumes
-- the fork as a flake input (`github:rbelem/graphify/v9-perl`) whose
-- flake.lock pins rev 9112bf35973ab392173cbfda3e5a17b12f0800dc — this
-- port pins that rev's tarball (the branch ref itself moves and would
-- rot the pin). sha256 fd178469f9fa…, codeload-mirror verified; the
-- flake.lock narHash is a NAR-of-tree digest, so the cross-check is at
-- the rev level plus mirror consistency. Version 0.9.63-perl is the
-- flake's declared version (the fork's pyproject still says 0.9.63 —
-- the -perl suffix lives in the fork packaging, ported here).
--
-- License note: the flake's meta says MIT, but the fork's pyproject
-- declares Apache-2.0 (with LICENSE, LICENSE-MIT, and NOTICE files);
-- the SPDX here follows upstream's declaration.
--
-- Dependency closure: deps.pip against the uv.lock shipped in the fork
-- (requires-python >=3.10; pod python 3.14 fits). The lock forks
-- resolutions by python version — numpy 2.4.6/scipy 1.17.1/contourpy
-- 1.3.3 serve 3.14, the older forks (numpy 1.26.4 etc.) have no cp314
-- wheels and are skipped with a warning. Optional-extra deps without
-- py3.14 wheels (gensim, jieba, pot, tree-sitter-dm) are likewise
-- skipped; they back `graphify` extras this package never declares.
-- The lock carries openai + tiktoken, matching the flake's
-- propagatedBuildInputs (the gemini semantic backend).
--
-- tree-sitter-perl: the fork's pyproject requires it (the fork's whole
-- point) but its uv.lock was never regenerated to include it, so the
-- resolver cannot fetch it. Rather than rebuild the flake's inline
-- v1.2.1 recipe (the build sandbox cannot fetch a second source tree),
-- the built package is taken from the pool's tree-sitter-perl payload
-- via build_deps and copied into this package's site-packages: same
-- recipe as the flake's mkTreeSitterPerl (grammar.json → parser.c →
-- abi3 extension), one pool-canonical artifact, abi3 so it runs under
-- the pod's python 3.14. Version skew vs the flake (pool v2.0.0 vs
-- flake v1.2.1) is deliberate: both violate the pyproject range
-- (>=0.23,<0.26 — the flake's dontCheckRuntimeDeps posture), the pool
-- ships the newer grammar.
--
-- Requires: glibc plus libstdcpp/libgcc — the closure carries C++ and
--           Rust wheels (numpy 2.x, rapidfuzz, tiktoken, pydantic-core,
--           orjson) that link the system C++/gcc runtime.
-- build_deps: tree-sitter-perl (its site-packages payload supplies
--             tree_sitter_perl for the copy below).

return {
    default = snap {
        name = "graphify",
        version = "0.9.63-perl",
        summary = "Turn any folder into a queryable knowledge graph (with Perl support)",
        description = [[
            graphify parses a codebase with tree-sitter grammars
            (30+ languages, including Perl via the rbelem fork),
            builds a knowledge graph of files/entities/relations, and
            answers architecture questions over it (`graphify query`,
            `graphify path`, `graphify explain`). Ships the graphify
            CLI and the graphify-mcp MCP server. Semantic backends
            (OpenAI-compatible, Gemini) ride on the bundled openai +
            tiktoken. Built from the fork at the flake.lock-pinned
            rev; the pip dependency closure is declared via deps.pip
            against the fork's uv.lock and fetched as a content-hashed
            pod-store entry (ADR-0017).
        ]],
        license = "Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/rbelem/graphify/archive/9112bf35973ab392173cbfda3e5a17b12f0800dc.tar.gz",
            sha256 = "fd178469f9fa9a90c0a3e6acbdd7477863e6938f088d644fab1de9d6a10674cb",
        },

        deps = {
            pip = { lock = "uv.lock" },
        },

        build = table.concat({
            "mkdir -p $STAGE/usr/lib/python3.14/site-packages $STAGE/usr/bin",
            -- graphify is the uv workspace ROOT in its own uv.lock
            -- (editable source), so the resolver skips it: install the
            -- package from the source tree (pure Python, flat layout).
            "cp -r $SRC/graphify $STAGE/usr/lib/python3.14/site-packages/",
            'for w in "$SHUTTLE_DEPS_DIR"/*.whl; do '
                .. 'python3 -m zipfile -e "$w" "$STAGE/usr/lib/python3.14/site-packages/"; done',
            -- tree-sitter-perl is absent from the fork's uv.lock (see
            -- header): copy the pool tree-sitter-perl payload's built
            -- abi3 extension out of the merged build prefix.
            'cp -r "$SHUTTLE_BUILD_PREFIX/usr/lib/python3.14/site-packages/tree_sitter_perl" '
                .. "$STAGE/usr/lib/python3.14/site-packages/",
            -- The wheel console-script entry points
            -- (graphify = "graphify.__main__:main",
            --  graphify-mcp = "graphify.serve:_main"), generated by
            -- hand: the interpreter wrapper resolves python3 from the
            -- pod and PYTHONPATH from the staged site-packages.
            "printf '#!/usr/bin/env python3\\nfrom graphify.__main__ import main\\nmain()\\n' > $STAGE/usr/bin/graphify",
            "printf '#!/usr/bin/env python3\\nfrom graphify.serve import _main\\n_main()\\n' > $STAGE/usr/bin/graphify-mcp",
            "chmod +x $STAGE/usr/bin/graphify $STAGE/usr/bin/graphify-mcp",
        }, " && "),

        type = "source",
        requires = { "glibc", "libstdcpp", "libgcc" },
        build_deps = { "tree-sitter-perl" },

        -- The copied tree_sitter_perl/_binding .so was linked by the
        -- nix gcc wrapper with RUNPATH=/shuttle-build-prefix/usr/lib
        -- baked in (dead at runtime) — same interim leak-scan escape
        -- as tree-sitter-perl itself (ADR-0018 Decision 3, issue #22).
        leaks_ok = { "/shuttle-build-prefix/usr/lib" },

        apps = {
            graphify = app {
                command = "usr/bin/graphify",
                interpreter = "python3",
            },
            ["graphify-mcp"] = app {
                command = "usr/bin/graphify-mcp",
                interpreter = "python3",
            },
        },
    },
}
