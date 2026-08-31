# system-base (golden parity port of pkgs/s/system-base.lua)
# Exercises the host-function seam: index("pc-gadget") is served from the
# package index the host injected (in-process) or fetched over the parent<->child
# IPC pipe (subprocess model).

{
  "system-base" = image {
    name = "system-base",
    version = "1.0.0",
    kernel = merge (pin "pc-kernel" null) {
      params = [
        "quiet",
        "console=ttyS0,115200",
        "earlyprintk=ttyS0",
        "printk.devkmsg=on",
        "panic=-1",
        "net.ifnames=0",
        "biosdevname=0",
      ],
      modules = [
        "virtio",
        "virtio_balloon",
        "virtio_console",
        "virtio_input",
        "virtio_net",
        "virtio_rng",
      ],
    },
    gadget = index "pc-gadget",
    bootloader = {
      type = "systemd-boot",
      timeout = 1,
    },
    base = pin "systemd" null,
    snaps = [
      (pin "glibc" null),
      (pin "bash" null),
      (pin "coreutils" null),
      (pin "shadow" null),
      (pin "linux-pam" null),
      (pin "kmod" null),
      (pin "util-linux" null),
      (pin "procps" null),
      (pin "toolchain" null),
      (pin "build-deps" null),
    ],
    disk = {
      label = "gpt",
      partitions = [
        {
          name = "esp",
          size = "256M",
          fs = "vfat",
          mount = "/boot",
        },
        {
          name = "root",
          size = "0",
          fs = "ext4",
          mount = "/",
          options = ["noatime"],
        },
      ],
    },
    sysctl = [
      "vm.swappiness=10",
      "kernel.kptr_restrict=2",
    ],
  },
}
