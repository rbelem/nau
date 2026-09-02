-- smartmontools: S.M.A.R.T. monitoring tools for hard drives
--
-- Source: https://www.smartmontools.org/
-- Provides smartctl and smartd for disk health monitoring.

return {
    default = snap {
        name = "smartmontools",
        -- adopt-info end-to-end: version/summary/description are extracted
        -- at build time from the adopted part (configure.ac AC_INIT gives
        -- the version). Nothing is hardcoded here — the real version lands
        -- in snap.yaml and the output filename, and `shuttle check` shows
        -- the identity as adopted-at-build.
        adopt_info = "tools",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://downloads.sourceforge.net/smartmontools/smartmontools-7.4.tar.gz",
        },
        -- Build via the autotools plugin in-source (expands to exactly the
        -- original `cd $SRC && ./configure --prefix=/usr --sysconfdir=/etc
        -- && make && make install DESTDIR=$STAGE` — see the in_source note
        -- below for why VPATH does not work for this package).
        parts = {
            tools = {
                plugin = "autotools",
                options = {
                    args = { "--sysconfdir=/etc" },
                    -- smartmontools' automake depfile bootstrapping fails
                    -- under the plugin's VPATH layout (config.status
                    -- "bootstrapping makefile fragments"); it builds
                    -- in-source, as the pre-plugin command did.
                    in_source = true,
                },
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
