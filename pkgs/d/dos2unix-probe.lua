-- dos2unix-probe: throwaway diagnostics payload (farm cc/gawk staging
-- mystery, 2026-10-03). Same build_deps as dos2unix; the build dumps
-- the sandbox state instead of compiling anything.
return {
    default = snap {
        name = "dos2unix-probe",
        version = "7.5.5",
        summary = "sandbox staging probe",
        description = "diagnostics only",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        build_deps = { "gcc", "make" },
        requires = { "glibc" },
        source = {
            url = "https://downloads.sourceforge.net/project/dos2unix/dos2unix/7.5.5/dos2unix-7.5.5.tar.gz",
        },
        build = table.concat({
            "echo === PATH: $PATH",
            "echo === prefix: $(ls /nau-build-prefix/usr/bin 2>&1 | head -20)",
            "echo === cc?: $(command -v cc || echo MISSING) make?: $(command -v make || echo MISSING)",
            "echo === stage root: $(ls $STAGE 2>&1 | head -5)",
            "exit 1",
        }, " && "),
    },
}
