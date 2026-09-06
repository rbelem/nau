-- zg: local-first hybrid workspace search (zvec-ai/zvec-grep).
--
-- Ported from the devbox global profile (Tier 2) as the first real
-- interpreter-based pod package (ADR-0017 dependency fetch, issue #13).
-- The npm closure resolves from upstream's package-lock.json (439
-- entries, fetched as pure tarball GETs with SRI verification), the
-- sandbox build compiles the TypeScript with the closure's own
-- typescript, and @node-llama-cpp is excluded from the stage: its
-- prebuilt CUDA/Vulkan backends cannot resolve here and zg
-- dynamic-imports it in try/catch (same pruning the devbox flake did).

return {
    default = snap {
        name = "zg",
        version = "0.2.1",
        summary = "Local-first hybrid workspace search for humans and AI agents",
        description = [[
            zg is a local-first hybrid workspace search CLI: BM25 +
            vector retrieval over an on-disk zvec index, MCP server
            mode, and embeddings via transformers.js/onnxruntime. Built
            from the upstream source tarball; the npm dependency closure
            is declared via deps.npm and fetched as a content-hashed
            pod-store entry (ADR-0017).
        ]],
        license = "Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/zvec-ai/zvec-grep/archive/refs/tags/v0.2.1.tar.gz",
            sha256 = "b468f8100d61c952d2093cbee71a2084b4acda9bea52102dc46c042e28cc587c",
        },

        deps = {
            npm = { lock = "package-lock.json" },
        },

        build = table.concat({
            -- tsc resolves imports by walking node_modules up from the
            -- source root; link the mounted closure there for the build.
            "ln -s \"$SHUTTLE_DEPS_DIR/node_modules\" node_modules",
            "node node_modules/typescript/bin/tsc -p tsconfig.json",
            "mkdir -p $STAGE/usr/lib/node_modules/@zvec/zvec-grep",
            "cp -r dist package.json $STAGE/usr/lib/node_modules/@zvec/zvec-grep/",
            -- Stage the full closure except the llama backends (see header).
            "tar -C \"$SHUTTLE_DEPS_DIR\" -cf - --exclude='./node_modules/@node-llama-cpp' node_modules | tar -C $STAGE/usr/lib/node_modules/@zvec/zvec-grep -xf -",
        }, " && "),

        type = "source",
        -- glibc for the runtime loader; gcc's libstdc++ backs the native
        -- .node addons (onnxruntime/sharp/zvec bindings) via the #10
        -- LD_LIBRARY_PATH wrapper machinery.
        requires = { "glibc", "gcc" },

        apps = {
            zg = app {
                command = "usr/lib/node_modules/@zvec/zvec-grep/dist/cli/index.js",
                interpreter = "node",
            },
        },
    },
}
