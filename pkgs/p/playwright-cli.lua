-- playwright-cli: Microsoft's browser-automation CLI for AI agents
-- (@playwright/cli — open pages, snapshot, click, fill, extract via
-- natural-language-ish subcommands over the playwright-core API).
--
-- Port of devbox-global devbox.d/playwright-cli @ v0.1.20
-- (microsoft/playwright-cli tag v0.1.20; flake src hash
-- sha256-MSBXygESmOlZi8qryAsUN6jb30RbysdEZRBXocrXZ14=, npm closure
-- sha256-PZrjfveGYvPapua4eRV6FJRc9txh8OXSsbsxQmkiZPw=).
--
-- Source: the npm registry tarball (the published payload: bin shim
-- playwright-cli.js, skillCheck.js, skills/) rather than the git tag —
-- same content minus the dev-only scripts/tests npm drops. The real CLI
-- code lives INSIDE playwright-core
-- (playwright-core/lib/tools/cli-client/program), so the closure
-- carries playwright + playwright-core at the flake's exact pin
-- 1.64.0-alpha-2026-09-14: recipe-local package-lock.json filtered from
-- upstream's (dev-only @playwright/test, @types/node, undici-types
-- dropped; prod entries byte-identical). Pure JS — no native addons.
--
-- BROWSER PAIRING (ticket #200 decision): no browser is shipped. The
-- flake wrapped PLAYWRIGHT_BROWSERS_PATH to nixpkgs
-- playwright-driver.browsers; the pool chromium recipe is dispositioned
-- may-never-port (flatpak serves it), so the CLI pairs with the
-- system/flatpak browser through playwright's channel config instead:
--   - `playwright-cli open --browser=chrome` (branded channel → system
--     Chrome/Chromium), or
--   - PLAYWRIGHT_MCP_EXECUTABLE_PATH=<browser binary> / config
--     executablePath — e.g. the flatpak launcher `org.chromium.Chromium`
--     (on PATH via flatpak exports), or
--   - PLAYWRIGHT_MCP_BROWSER=<channel> to default the channel.
-- PLAYWRIGHT_BROWSERS_PATH stays unset and playwright's browser-fetching
-- postinstall never runs anywhere (the dep fetch is a --ignore-scripts
-- pure download and the build is pure staging), so the CLI never tries
-- to populate its own browser cache.
--
-- engines: node >=18 — pool node 26.7.0 fits. The runtime update check
-- (registry.npmjs.org ping) fails soft; NO_UPDATE_NOTIFIER=1 silences.
--
-- requires: node for the interpreter wrapper; glibc for the payload's
-- ELF-free JS to run against the node runtime's platform. build_deps:
-- (none) — pure staging, no build.

return {
    default = snap {
        name = "playwright-cli",
        version = "0.1.20",
        summary = "Playwright CLI - browser automation CLI for AI agents",
        description = [[
            playwright-cli drives a real browser from the command line:
            open pages, take accessibility snapshots, click, type,
            fill forms, extract data, and attach to running sessions —
            designed for AI agents, with bundled skills describing the
            workflow. Runs on playwright-core; the browser is supplied
            by the host (system/flatpak Chrome or Chromium via channel
            config), not by this package. The npm dependency closure is
            declared via deps.npm against a recipe-local
            package-lock.json and fetched as a content-hashed pod-store
            entry (ADR-0017).
        ]],
        license = "Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://registry.npmjs.org/@playwright/cli/-/cli-0.1.20.tgz",
            sha256 = "877a33d75831ad6ab4e30ed358e19c178747f14834d5fa6e5dc2a294787c06d2",
        },

        deps = {
            npm = { lock = "recipe/package-lock.json" },
        },

        -- Registry tarball root flattens into $SRC. Stage the package
        -- payload into lib/node_modules/@playwright/cli (scoped layout
        -- mirrors `npm i -g @playwright/cli`; the bin shim resolves
        -- ./skillCheck.js and playwright-core relative to it) and
        -- tar-copy the node_modules closure next to it (agentmemory
        -- pattern). App command points at the payload-relative
        -- playwright-cli.js; the farm emitter resolves the store path
        -- and the pod's node at emit time.
        build = table.concat({
            "pkg=$STAGE/usr/lib/node_modules/@playwright/cli",
            'mkdir -p "$pkg"',
            'cp -r $SRC/package.json $SRC/playwright-cli.js $SRC/skillCheck.js $SRC/skills "$pkg/"',
            'tar -C "$SHUTTLE_DEPS_DIR" -cf - node_modules | tar -C "$pkg" -xf -',
        }, " && "),

        type = "source",
        requires = { "glibc", "node" },

        apps = {
            ["playwright-cli"] = app {
                command = "usr/lib/node_modules/@playwright/cli/playwright-cli.js",
                interpreter = "node",
            },
        },
    },
}
