-- bind: ISC BIND DNS server and client tools
--
-- Source: https://www.isc.org/bind/
-- Provides the BIND DNS server, dig, nslookup, and host utilities.

return {
    default = snap {
        name = "bind",
        version = "9.20",
        summary = "ISC BIND DNS server and client tools",
        description = [[
            BIND (Berkeley Internet Name Domain) is the most widely used
            DNS software on the Internet. This package provides the named
            DNS server and client utilities including dig, nslookup, and
            host for querying DNS servers.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://ftp.isc.org/isc/bind9/9.20.7/bind-9.20.7.tar.xz",
        },
        build = "./configure --prefix=/usr --sysconfdir=/etc/bind && make && make install DESTDIR=$STAGE",
    },
}
