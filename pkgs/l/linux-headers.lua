-- linux-headers: Linux kernel uapi headers (Debian linux-libc-dev 6.12.38)
--
-- FETCH strategy, the same trade gcc.lua made (#164/#24): the previous
-- recipe ran kernel.org 7.0 `make headers_install` from source, which
-- needs HOSTCC (scripts/basic/fixdep) — and declaring gcc as that
-- build_dep (4cc944f) closed a genuine bootstrap cycle with the #174
-- ownership rule: gcc requires linux-headers, linux-headers build_dep
-- gcc. The cycle stayed masked while a cached gcc snap existed
-- (ensure_pod_dep_payload early-returns on the downloads hit and never
-- walks the dep prefix) and fired the first time gc pruned the cached
-- snap. The deb payload needs no build at all, is generated from the
-- same snapshot.debian.org timestamp as the farm gcc debs, and keeps
-- uapi ownership exactly where #174 put it: linux-libc-dev ships the
-- uapi trees (asm/, linux/, asm-generic/, drm/, rdma/, ...); gcc's deb
-- set still excludes them (asserted at its build).

return {
    default = snap {
        name = "linux-headers",
        version = "6.12.38",
        summary = "Kernel uapi headers for Linux 6.12 (Debian linux-libc-dev)",
        description = [[Linux kernel uapi headers as shipped in Debian's
linux-libc-dev — the interface between the Linux kernel and userspace.
Consumed by glibc and every gcc consumer in merged build prefixes; sole
owner of the uapi subtrees per the #174 rule.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        requires = {},
        sources = {
            ["linux-libc-dev"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/l/linux/linux-libc-dev_6.12.38-1_all.deb",
                sha256 = "85b85662ef28e31364d6b00b041fade0ebcf649a368cc3e7899c2e2b87b77a46",
            },
        },
        build = table.concat({
            -- busybox dpkg-deb is the sandbox's only deb unpacker (the
            -- sync env's busybox, same as gcc.lua's payload stage).
            "dpkg-deb -x \"$SRC/linux-libc-dev\" \"$STAGE\"",
            -- Debian multiarch: the per-arch uapi asm/ lives under
            -- usr/include/<triplet>/ (arch-all deb ships every triplet);
            -- the classic flat include/asm path is what kernel uapi
            -- consumers (glibc's bits/errno.h -> linux/errno.h ->
            -- asm/errno.h) resolve. Same content, Debian's own x86_64
            -- asm tree.
            "ln -s x86_64-linux-gnu/asm \"$STAGE/usr/include/asm\"",
        }, " && "),
    },
}
