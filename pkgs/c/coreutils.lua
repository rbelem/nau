-- coreutils: Basic file, shell, and text manipulation utilities
--
-- Source: https://ftp.gnu.org/gnu/coreutils/
-- Provides essential commands like ls, cp, mv, rm, cat, echo, and more.

return {
    default = snap {
        name = "coreutils",
        version = "9.11",
        summary = "Basic file, shell, and text manipulation utilities",
        description = [[
            GNU Coreutils includes all of the basic command-line text and
            file manipulation tools expected in a POSIX system. These are
            the core utilities: arch, base64, basename, cat, chcon, chgrp,
            chmod, chown, chroot, cksum, comm, cp, csplit, cut, date, dd,
            df, dir, dircolors, dirname, du, echo, env, expand, expr,
            factor, false, fmt, fold, groups, head, hostid, id, install,
            join, link, ln, logname, ls, md5sum, mkdir, mkfifo, mknod,
            mktemp, mv, nice, nl, nohup, nproc, numfmt, od, paste, pathchk,
            pinky, pr, printenv, printf, ptx, pwd, readlink, realpath, rm,
            rmdir, runcon, seq, sha1sum, sha224sum, sha256sum, sha384sum,
            sha512sum, shred, shuf, sleep, sort, split, stat, stdbuf,
            stty, sum, sync, tac, tail, tee, test, timeout, touch, tr,
            true, truncate, tsort, tty, uname, unexpand, uniq, unlink,
            users, vdir, wc, who, whoami, and yes.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://ftp.gnu.org/gnu/coreutils/coreutils-9.11.tar.xz",
        },
        build = "./configure --prefix=/usr --without-selinux && make && make install DESTDIR=$STAGE",
    },
}
