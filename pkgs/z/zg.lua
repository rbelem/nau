-- zg: local-first hybrid workspace search (zvec-ai/zvec-grep).
--
-- Ported from the devbox global profile (Tier 2) as the first real
-- interpreter-based pod package (ADR-0017 dependency fetch, issue #13).
-- The npm closure resolves from upstream's package-lock.json (439
-- entries, fetched as pure tarball GETs with SRI verification), the
-- sandbox build compiles the TypeScript with the closure's own
-- typescript. The @node-llama-cpp backends are excluded at FETCH time
-- via deps.npm.exclude (issue #14): their prebuilt CUDA/Vulkan wheels
-- cannot load here and zg dynamic-imports them in try/catch (same
-- pruning the devbox flake did), so they are never downloaded, never
-- extracted, and never pinned into the closure hash.

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
            npm = {
                lock = "package-lock.json",
                exclude = { "node_modules/@node-llama-cpp/*" },
            },
        },

        build = table.concat({
            -- tsc resolves imports by walking node_modules up from the
            -- source root; link the mounted closure there for the build.
            "ln -s \"$SHUTTLE_DEPS_DIR/node_modules\" node_modules",
            "node node_modules/typescript/bin/tsc -p tsconfig.json",
            "mkdir -p $STAGE/usr/lib/node_modules/@zvec/zvec-grep",
            "cp -r dist package.json $STAGE/usr/lib/node_modules/@zvec/zvec-grep/",
            -- Stage the whole closure (the llama backends never reached
            -- it — excluded at fetch time, see header).
            "tar -C \"$SHUTTLE_DEPS_DIR\" -cf - node_modules | tar -C $STAGE/usr/lib/node_modules/@zvec/zvec-grep -xf -",
        }, " && "),

        type = "source",
        -- glibc for the runtime loader; libstdcpp + libgcc for the C++ runtime
        -- that backs the native .node addons (onnxruntime/sharp/zvec bindings)
        -- via the #10 LD_LIBRARY_PATH wrapper machinery. The dedicated pool
        -- runtime packages (issue #34) provide libstdc++.so.6/libgcc_s.so.1;
        -- a full GCC source build is disproportionate for a runtime-only need
        -- and its fixinc/sysroot bootstrap is a separate concern.
        requires = { "glibc", "libstdcpp", "libgcc" },

        apps = {
            zg = app {
                command = "usr/lib/node_modules/@zvec/zvec-grep/dist/cli/index.js",
                interpreter = "node",
            },
        },
    },
}
