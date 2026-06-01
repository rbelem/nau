-- modemmanager: Mobile broadband modem management daemon
--
-- Source: https://gitlab.freedesktop.org/mobile-broadband/ModemManager
-- Provides a unified API for controlling mobile broadband devices.

return {
    default = snap {
        name = "modemmanager",
        version = "1.24",
        summary = "Mobile broadband modem management daemon",
        description = [[
            ModemManager provides a unified high-level API for communicating
            with mobile broadband modems. It supports a wide range of
            modems and protocols including GSM/UMTS, CDMA/EVDO, LTE/5G,
            and satellite modems. Works with NetworkManager for seamless
            mobile connectivity.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        source = {
            url = "https://gitlab.freedesktop.org/mobile-broadband/ModemManager/-/archive/1.24.2/ModemManager-1.24.2.tar.gz",
        },
        build = "meson setup build --prefix=/usr && ninja -C build && DESTDIR=$STAGE ninja -C build install",
    },
}
