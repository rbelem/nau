# hello (golden parity port of pkgs/h/hello.lua)
# Definitions contain NO imports and NO contract annotations: the host wraps
# every definition with the prelude and applies the schema contracts.

{
  default = snap {
    name = "hello",
    version = "2.10",
    summary = "GNU Hello, the \"hello world\" snap",
    description = "            GNU hello prints a friendly greeting.\n            This is part of the snapcraft tour at https://snapcraft.io/\n        ",
    license = "GPL-3.0-or-later",
    grade = "stable",
    confinement = "strict",
    source = "http://ftp.gnu.org/gnu/hello/hello-2.10.tar.gz",
    stage = "./stage/",
    architectures = ["amd64", "arm64"],
    type = "source",
    requires = ["glibc"],
    apps = {
      hello = app {
        command = "bin/hello",
      },
    },
  },
}
