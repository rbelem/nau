-- polkit: Authorization Manager for privilege escalation
--
-- Source: https://gitlab.freedesktop.org/polkit/polkit
-- Provides the PolicyKit authorization framework.

return {
    default = snap {
        name = "polkit",
        version = "126",
        summary = "Authorization Manager for privilege escalation",
        description = [[
            PolicyKit (polkit) is an application-level toolkit for defining
            and handling the policy that allows unprivileged processes to
            speak to privileged processes. It is a framework for centralizing
            the decision making process for user privilege escalation.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        source = {
            url = "https://gitlab.freedesktop.org/polkit/polkit/-/archive/127/polkit-127.tar.gz",
        },
        build = "meson setup build --prefix=/usr -Dsession_tracking=libsystemd-login && ninja -C build && DESTDIR=$STAGE ninja -C build install",
    },
}
