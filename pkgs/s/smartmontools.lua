-- smartmontools: S.M.A.R.T. monitoring tools for hard drives
--
-- Source: https://www.smartmontools.org/
-- Provides smartctl and smartd for disk health monitoring.

return {
    default = snap {
        name = "smartmontools",
        version = "7.4",
        summary = "S.M.A.R.T. monitoring tools for hard drives",
        description = [[
            smartmontools contains utilities that control and monitor
            computer storage systems using the Self-Monitoring, Analysis,
            and Reporting Technology (S.M.A.R.T.) system built into most
            modern ATA/SATA, SCSI/SAS and NVMe disks. Includes smartctl
            for one-shot queries and smartd for continuous monitoring.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://downloads.sourceforge.net/smartmontools/smartmontools-7.4.tar.gz",
        },
        -- Build via the autotools plugin (expands to exactly the original
        -- `./configure --prefix=/usr --sysconfdir=/etc && make && make
        -- install DESTDIR=$STAGE`, VPATH-style).
        parts = {
            tools = {
                plugin = "autotools",
                options = { args = { "--sysconfdir=/etc" } },
            },
        },
        -- smartctl for one-shot queries; smartd as a snapd-managed daemon.
        apps = {
            smartctl = app { command = "usr/sbin/smartctl" },
            smartd = app {
                command = "usr/sbin/smartd",
                daemon = "simple",
                plugs = { "hardware-observe" },
            },
        },
        -- smartd inspects storage hardware directly (SMART ioctls, NVMe).
        plugs = {
            ["hardware-observe"] = "hardware-observe",
        },
        -- smartd persists state under /var/lib/smartmontools, which a
        -- strict snap cannot write; bind it to snap data.
        layout = {
            ["/var/lib/smartmontools"] = { bind = "$SNAP_DATA/var/lib/smartmontools" },
        },
        -- Seed the state directory on install/config change.
        hooks = {
            configure = "pkgs/s/smartmontools-hooks/configure",
        },
    },
}
