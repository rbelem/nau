-- strace: System call tracer for Linux
--
-- Source: https://strace.io/
-- Provides the strace diagnostic and debugging utility.

return {
    default = snap {
        name = "strace",
        version = "6.12",
        summary = "System call tracer for Linux",
        description = [[
            strace is a diagnostic and debugging tool for Linux. It
            intercepts and records the system calls made by a process
            and the signals received. It can be used to trace the
            execution of programs, diagnose problems, and learn about
            system call interfaces.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://github.com/strace/strace/releases/download/v6.12/strace-6.12.tar.xz",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
