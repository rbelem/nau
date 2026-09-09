-- strix: open-source AI pentesting tool — autonomous security
-- research agent that scans targets, enumerates vulnerabilities, and
-- produces reports.
--
-- Cheap-tier flake port (issue #20): the upstream linux-x86_64
-- release tarball is fetched, sha256-pinned, and the self-contained
-- binary is staged into usr/bin. The ELF needs only the glibc family
-- (libc/libdl/libpthread) plus libz.so.1.

return {
    default = snap {
        name = "strix",
        version = "1.6.2",
        summary = "Open-source AI pentesting agent",
        description = [[
            strix is an autonomous AI security agent: point it at a
            target and it runs reconnaissance, vulnerability scanning,
            and exploitation workflows, producing a findings report.
            Ships as a self-contained release binary; LLM credentials
            come from the environment at run time.
        ]],
        license = "Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/usestrix/strix/releases/download/v1.6.2/strix-1.6.2-linux-x86_64.tar.gz",
            sha256 = "f3f29fa64bee420bf64f8911fb9f38e20270d406f6df44cc2436252c2af0bc81",
        },

        -- Flat stripped tarball root: single binary named after the
        -- release artifact; renamed to the package name on stage.
        build = table.concat({
            "install -Dm755 strix-1.6.2-linux-x86_64 $STAGE/usr/bin/strix",
        }, " && "),

        type = "source",
        requires = { "glibc", "zlib" },

        apps = {
            strix = app {
                command = "usr/bin/strix",
            },
        },
    },
}
