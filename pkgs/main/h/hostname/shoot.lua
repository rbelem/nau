-- hostname: Utility to set or print the name of the current host
--
-- Source: https://github.com/debian/hostname
-- Provides the hostname and dnsdomainname utilities.

return {
    default = snap {
        name = "hostname",
        version = "3.25",
        summary = "Utility to set or print the name of the current host",
        description = [[
            The hostname package provides a simple command-line utility
            to show or set the system's host name, as well as
            dnsdomainname and domainname for showing parts of the
            fully qualified domain name.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        source = {
            url = "https://github.com/debian/hostname/releases/download/debian/3.25/hostname_3.25.tar.gz",
        },
        build = "make && make install DESTDIR=$STAGE",
    },
}
