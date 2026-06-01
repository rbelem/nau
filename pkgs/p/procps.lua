-- procps: /proc filesystem utilities (ps, top, free, etc.)
--
-- Source: https://gitlab.com/procps-ng/procps
-- Provides process management and system monitoring utilities.

return {
    default = snap {
        name = "procps",
        version = "4.0",
        summary = "/proc filesystem utilities (ps, top, free, etc.)",
        description = [[
            procps provides a set of system utilities that use the /proc
            filesystem. Includes ps for process listing, top for
            real-time process monitoring, free for memory usage, vmstat
            for virtual memory statistics, uptime, w, pgrep, pkill,
            pmap, pwdx, slabtop, sysctl, and watch.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        source = {
            url = "https://gitlab.com/procps-ng/procps/-/archive/v4.0.5/procps-v4.0.5.tar.gz",
        },
        build = "./configure --prefix=/usr --disable-kill && make && make install DESTDIR=$STAGE",
    },
}
