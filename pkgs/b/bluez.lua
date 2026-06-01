-- bluez: official Linux Bluetooth protocol stack
--
-- Source: https://www.bluez.org/
-- Provides bluetoothd daemon, bluetoothctl, and kernel protocol support.
-- Required for Bluetooth device pairing and audio streaming.

return {
    default = snap {
        name = "bluez",
        version = "5.82",
        summary = "Official Linux Bluetooth protocol stack",
        description = [[
            BlueZ provides support for the core Bluetooth layers and
            protocols. Includes the bluetoothd daemon, bluetoothctl
            command-line configuration tool, and plugins for audio,
            input, and networking profiles.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://mirrors.edge.kernel.org/pub/linux/bluetooth/bluez-5.82.tar.xz",
        },
        build = "./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --enable-library && make && make install DESTDIR=$STAGE",
    },
}
