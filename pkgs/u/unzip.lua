-- unzip: extraction utility for .zip archives (Info-ZIP UnZip 6.0).
--
-- Ported from the devbox global profile as a source build: the Debian
-- orig tarball (identical to the info-zip unzip60.tgz release; the
-- info-zip FTP server is flaky) is fetched, sha256-pinned, and built
-- with the generic unix makefile target in the build sandbox; the
-- unzip binary is staged into usr/bin.

return {
    default = snap {
        name = "unzip",
        version = "6.0",
        summary = "List, test, and extract ZIP archives",
        description = [[
            UnZip is an extraction utility for archives compressed in
            the zip format (created by zip/Info-ZIP/WinZip/PKZIP). It
            lists, tests, and extracts files from zip archives,
            preserving directory hierarchies and (optionally)
            timestamps and permissions.
        ]],
        license = "Info-ZIP",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://deb.debian.org/debian/pool/main/u/unzip/unzip_6.0.orig.tar.gz",
            sha256 = "036d96991646d0449ed0aa952e4fbe21b476ce994abc276e49d30e686708bd37",
        },

        build = table.concat({
            -- UnZip 6.0 vs modern toolchain fixes (same as current distro
            -- patch sets): (1) drop K&R gmtime/localtime declarations that
            -- conflict with modern glibc prototypes; (2) unix/configure's
            -- closedir conftest relies on an implicit function declaration,
            -- a hard error since GCC 14, so detection "fails" and defines
            -- NO_DIR (breaking unix.c) — teach the conftest to include
            -- <dirent.h>.
            "sed -i 's/struct tm \\*gmtime(), \\*localtime();//' unix/unxcfg.h",
            "sed -i 's,^int main() { return closedir,#include <dirent.h>\\nint main() { return closedir,' unix/configure",
            "make -f unix/Makefile generic -j$(nproc)",
            "install -Dm755 unzip $STAGE/usr/bin/unzip",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            unzip = app {
                command = "usr/bin/unzip",
            },
        },
    },
}
