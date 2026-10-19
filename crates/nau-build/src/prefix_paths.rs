//! The merged build prefix's search paths: the linker's `-L`/`LIBRARY_PATH`
//! list, the loader's `LD_LIBRARY_PATH` list, and the `GCONV_PATH` dirs.
//!
//! Split out of `snap` (the 464 KB file is unreadable in one pass) and
//! kept together because the two lists differ by ONE directory, and the
//! difference is load-bearing: the loader's list omits the prefix's root
//! `lib64`, the glibc payload's runtime slibdir, while the linker's list
//! carries it. Read the loader list's doc comment before changing
//! either.

/// The lib dirs the LINKER searches for the merged prefix: the gcc
/// payload's cc shims turn these into `-L` flags (gcc.lua shim
/// contract), so link-time searches — libgcc_s.so.1, libc_nonshared.a,
/// crt files — resolve against the prefix the same way loader-time
/// searches do (#180 item 2b). Includes the prefix's root `lib64` — the
/// glibc payload's slibdir (runtime) half, see `snap::build_prefix_env`
/// (#180 follow-up: the linker's `libc.so` script resolves to a bare
/// `libc.so.6` only a listed dir can satisfy).
///
/// Foreign-arch caveat (#209 watch item): the triplet dirs are listed
/// unconditionally, in a FIXED order (x86_64, aarch64, armhf), and the
/// order is load-bearing the day a payload populates a dir it does not
/// belong to. Today it is inert — a payload stages only its own arch's
/// set (gcc.lua selects one deb set per build on
/// `$CONFIGURE_TARGET`/`uname -m`), so at most one triplet dir exists.
/// But the loader and the linker both take the FIRST dir carrying a
/// soname: if a future payload ever stages a foreign arch's libs (or
/// several arches at once), this amd64-first list would silently prefer
/// x86_64 libraries for an aarch64/armhf link. Re-order or arch-filter
/// this list before shipping such a payload — don't rely on the accident.
pub fn link_library_path(prefix: &str) -> String {
    format!(
        "{}/usr/lib:{}/usr/lib64:{}/lib64:{}/usr/lib/x86_64-linux-gnu:{}/usr/lib/aarch64-linux-gnu:{}/usr/lib/arm-linux-gnueabihf",
        prefix, prefix, prefix, prefix, prefix, prefix
    )
}

/// The lib dirs the LOADER searches for the merged prefix.
///
/// The prefix's root `lib64` — the glibc payload's slibdir (runtime)
/// half, holding `ld-linux`, `libc.so.6`, `libm.so.6` — is deliberately
/// NOT here, even though the LINKER list ([`link_library_path`]) carries
/// it.
///
/// glibc 2.44's `libc.so.6` references `__pointer_chk_guard` as
/// `UND@GLIBC_PRIVATE`: the symbol moved into the dynamic linker, so
/// only a matching glibc 2.44 loader can satisfy it. A loader from
/// another build cannot, and every fortify-compiled binary in the build
/// dies at once with "symbol lookup error: .../libc.so.6: undefined
/// symbol: __pointer_chk_guard, version GLIBC_PRIVATE" — measured
/// 2026-10-19 with nixpkgs' own glibc 2.44 AND with a source-built
/// 2.44, so it is a glibc-2.44 property, not a payload defect. The
/// victims are exactly the tools a deb-seam or toolchain build needs:
/// `ar`, `as`, `ld`, `strip`, `dpkg-deb`, `gcc`, `patchelf`.
///
/// The cost, stated plainly: a program the build links against the
/// prefix's `libc.so.6` resolves that libc at RUN time to the HOST's
/// loader's libc, not the prefix's. The link is unchanged (the linker
/// still finds the prefix's `libc.so.6` through `LIBRARY_PATH` and
/// `LDFLAGS`).
pub fn ld_library_path(prefix: &str) -> String {
    format!(
        "{}/usr/lib:{}/usr/lib64:{}/usr/lib/x86_64-linux-gnu:{}/usr/lib/aarch64-linux-gnu:{}/usr/lib/arm-linux-gnueabihf",
        prefix, prefix, prefix, prefix, prefix
    )
}

/// The gconv module dirs `GCONV_PATH` exposes for the merged prefix:
/// the slibdir layout the glibc payload stages (`usr/lib64/gconv` — the
/// same root-lib64 half the LD list covers) plus the Debian-style
/// `usr/lib/gconv` other payloads may ship. glibc searches each dir for
/// its gconv-modules cache and ignores missing ones, so listing both
/// layouts unconditionally is safe.
pub fn gconv_dirs(prefix: &str) -> String {
    format!("{}/usr/lib64/gconv:{}/usr/lib/gconv", prefix, prefix)
}

/// The `-L` list `LDFLAGS` exposes for the merged prefix: one flag per
/// dir of [`link_library_path`], same order. Configure, meson, and
/// libtool link probes read `LDFLAGS` directly — without the multiarch
/// entries a link line that bypasses the gcc cc shim's
/// LIBRARY_PATH→-L translation searched `{prefix}/usr/lib` only and
/// missed the deb payloads' multiarch-staged libs (#209 watch item).
/// The first flag is unchanged (`usr/lib` keeps priority), so existing
/// consumers' search order only widens.
pub fn ld_flags(prefix: &str) -> String {
    link_library_path(prefix)
        .split(':')
        .map(|dir| format!("-L{dir}"))
        .collect::<Vec<_>>()
        .join(" ")
}
