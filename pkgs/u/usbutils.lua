-- usbutils: Linux USB utilities
--
-- Source: https://mirrors.edge.kernel.org/pub/linux/utils/usb/usbutils/
-- Provides lsusb, usb-devices, and the USB device database.

return {
    default = snap {
        name = "usbutils",
        version = "018",
        summary = "Linux USB utilities",
        description = [[
            usbutils contains utilities for inspecting the devices
            connected to the USB bus. Includes lsusb for listing USB
            devices, usb-devices for detailed device information, and
            usbhid-dump for dumping HID reports from USB HID devices.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://mirrors.edge.kernel.org/pub/linux/utils/usb/usbutils/usbutils-018.tar.xz",
        },
        build = "meson setup build --prefix=/usr && ninja -C build && DESTDIR=$STAGE ninja -C build install",
    },
}
