-- firecrawl: Firecrawl CLI — turn websites into AI-ready datasets
-- (scrape, crawl, map, search) against the Firecrawl API.
--
-- Cheap-tier flake port (issue #20): the upstream linux-x64 release
-- tarball is fetched, sha256-pinned, and the Bun-compile binary is
-- staged into usr/bin. Never strip/patchelf Bun-compiled binaries:
-- they embed their JS bytecode and corrupt under ELF rewriting.
-- (Upstream publishes no LICENSE file; the flake's meta claims ISC.)

return {
    default = snap {
        name = "firecrawl",
        version = "1.23.3",
        summary = "Firecrawl CLI - turn websites into AI-ready datasets",
        description = [[
            firecrawl is the official CLI for the Firecrawl web
            scraping API: scrape single pages, crawl whole sites,
            discover URLs, and search — returning clean markdown or
            structured data ready for LLM consumption.
        ]],
        license = "ISC",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/firecrawl/cli/releases/download/v1.23.3/firecrawl-linux-x64.tar.gz",
            sha256 = "4ce1c0cdcac79208e4c80395f9738914f608eefa0433f5d3241bb8e25ebe5e76",
        },

        -- Flat stripped tarball root: single binary named after the
        -- Node-style asset; renamed to the package name on stage.
        build = table.concat({
            "install -Dm755 firecrawl-linux-x64 $STAGE/usr/bin/firecrawl",
        }, " && "),

        type = "source",
        -- Bun-compile binary: only the glibc family (libc, ld-linux,
        -- libpthread, libdl, libm) in DT_NEEDED.
        requires = { "glibc" },

        apps = {
            firecrawl = app {
                command = "usr/bin/firecrawl",
            },
        },
    },
}
