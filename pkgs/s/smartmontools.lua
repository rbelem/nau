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
        build = "./configure --prefix=/usr --sysconfdir=/etc && make && make install DESTDIR=$STAGE",
    },
}
