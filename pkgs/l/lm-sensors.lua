-- lm-sensors: Hardware monitoring sensors tools
--
-- Source: https://github.com/lm-sensors/lm-sensors
-- Provides sensors, sensord, and libsensors for hardware monitoring.
--
-- Built via the make plugin: lm-sensors' Makefile spells the install root
-- lowercase `prefix` (build-time spelling, so it belongs in `variables`
-- where it reaches both commands).

return {
    default = snap {
        name = "lm-sensors",
        version = "3.6",
        summary = "Hardware monitoring sensors tools",
        description = [[
            lm-sensors provides tools for monitoring temperatures,
            voltages, fan speeds, and other hardware health metrics on
            Linux systems. Includes the sensors command for displaying
            sensor readings, sensord for logging, and the libsensors
            library for applications to access sensor data.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://github.com/lm-sensors/lm-sensors/archive/refs/tags/V3-6-1.tar.gz",
        },
        parts = {
            lm_sensors = {
                plugin = "make",
                options = { variables = { prefix = "/usr" } },
            },
        },
    },
}
