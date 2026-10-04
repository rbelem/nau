-- jev-ultrafast: a browser agent with a dynamic, indexed action space.
--
-- TypeSafe's Jev picks an operation (CLICK/TYPE_TEXT/SELECT/SCROLL/
-- WAIT/DONE/BLOCKED) and an element from a numbered table of observed
-- controls; a small LLM writes text only for TYPE_TEXT. One policy
-- request per decision cycle, no screenshots in the default loop.
-- Ships the `jev` demo (local inspector on 127.0.0.1:8766) plus the
-- browser-harness CLI it drives Chrome through.
--
-- Packaged from a commit snapshot of the upstream repo: no release
-- tags existed at packaging time (0.1.0 is the pyproject version), so
-- the source is pinned to main@1231850a (the codeload tarball of the
-- commit the uv.lock was validated against). Bump = re-pin commit +
-- sha256; upstream cuts tags, prefer the tag tarball then.
--
-- The dependency closure resolves from upstream's uv.lock via
-- deps.pip (ADR-0017): browser-harness 0.1.13 (+ cdp-use, fetch-use,
-- pillow, websockets) and httpx[http2]. The dev group (pytest, ruff)
-- drops out via the dev/prod split — jev-ultrafast is the editable
-- root, so its regular closure is the prod closure. pillow is the
-- only compiled dep; the resolver picks its cp314 manylinux x86_64
-- wheel for the pod's python 3.14.
--
-- The build unzips the wheels into site-packages, copies the pure
-- Python package tree from the source, and stages the three console
-- scripts by hand (jev = jev_ultrafast.demo:main; browser-harness /
-- browser-harness-mcp = browser_harness .run/.mcp_cli mains). The
-- wrapper hands site-packages to the pod's python3 via PYTHONPATH.
--
-- Runtime needs beyond the payload: a Chrome for browser-harness to
-- attach to (remote debugging; `browser-harness --doctor` checks),
-- and env auth — TYPESAFE_API_KEY (Jev) and TEXT_MODEL_API_KEY
-- (OpenAI-compatible text model; upstream's example uses an
-- OpenRouter key with inception/mercury-2.5, reasoning off). Keys are
-- env-only at runtime; the pod carries no secrets.

return {
    default = snap {
        name = "jev-ultrafast",
        version = "0.1.0",
        summary = "Browser agent that picks operations instead of generating (TypeSafe Jev)",
        description = [[
            jev-ultrafast runs a browser agent whose policy chooses an
            operation and a target element per decision cycle — one
            network round trip, text generated only for TYPE_TEXT.
            Includes the jev inspector demo (127.0.0.1:8766) and the
            browser-harness CLI/MCP entry points that attach Chrome.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/browser-use/jev-ultrafast/archive/1231850a0bf1a0c0341fe408ef1668dbbfdfac46.tar.gz",
            sha256 = "3bed2171ef064135c5192bad354b4a187f71ec397639d5ab676d02be37822211",
        },

        deps = {
            pip = { lock = "uv.lock" },
        },

        build = table.concat({
            "mkdir -p $STAGE/usr/lib/python3.14/site-packages $STAGE/usr/bin",
            "cp -r $SRC/jev_ultrafast $STAGE/usr/lib/python3.14/site-packages/",
            'for w in "$NAU_DEPS_DIR"/*.whl; do '
                .. 'python3 -m zipfile -e "$w" "$STAGE/usr/lib/python3.14/site-packages/"; done',
            "printf '#!/usr/bin/env python3\\nfrom jev_ultrafast.demo import main\\nmain()\\n' > $STAGE/usr/bin/jev",
            "printf '#!/usr/bin/env python3\\nfrom browser_harness.run import main\\nmain()\\n' > $STAGE/usr/bin/browser-harness",
            "printf '#!/usr/bin/env python3\\nfrom browser_harness.mcp_cli import main\\nmain()\\n' > $STAGE/usr/bin/browser-harness-mcp",
            "chmod +x $STAGE/usr/bin/jev $STAGE/usr/bin/browser-harness $STAGE/usr/bin/browser-harness-mcp",
        }, " && "),

        type = "source",
        requires = { "glibc" },
        -- the build unpacks wheels with `python3 -m zipfile` — ADR-0018:
        -- declare it, the pod-first sync env leaks no host python
        build_deps = { "python" },

        apps = {
            jev = app {
                command = "usr/bin/jev",
                interpreter = "python3",
            },
            ["browser-harness"] = app {
                command = "usr/bin/browser-harness",
                interpreter = "python3",
            },
            ["browser-harness-mcp"] = app {
                command = "usr/bin/browser-harness-mcp",
                interpreter = "python3",
            },
        },
    },
}
