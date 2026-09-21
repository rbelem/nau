#!/usr/bin/env python3
"""Throttling payload server for the #86 stranded-slot proof (#80 harness).

Drop-in stand-in for `python3 -m http.server` that delays the BODY of any
artifact whose name contains the STRAND_ARTIFACT needle (default:
`verity-hash_`). The transfer ordering guarantees the root partition
(50-root.transfer) finalizes before the verity-hash transfer
(50-verity.transfer) begins — so letting the guest's download die while it
waits on the delayed body leaves the deterministic mid-transaction strand:
slot B root carries the new version label (with a masked placeholder type
GUID), the hash slot matches neither its flavor type nor `_empty`, and no
UKI was ever installed. The next `systemd-sysupdate update` then refuses
with "already acquired and partially installed. Vacuum it to try
installing again." — the strand #86 reclaims.

Env:
  STRAND_ARTIFACT    substring selecting the artifact to throttle
                     (default "verity-hash_")
  STRAND_DELAY_SECS  how long to sleep before sending the body
                     (default 3600 — past every realistic read timeout)

Usage: strand-server.py [DIR] [PORT]   (defaults: . 8123, host loopback —
the guest reaches it through QEMU SLIRP as 10.0.2.2)
"""

import os
import sys
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

DELAY = float(os.environ.get("STRAND_DELAY_SECS", "3600"))
NEEDLE = os.environ.get("STRAND_ARTIFACT", "verity-hash_")


class StrandHandler(SimpleHTTPRequestHandler):
    def copyfile(self, source, output_file):
        # copyfile is the body-send path of GET: headers are already gone
        # out, the client is waiting on exactly the bytes the transfer
        # needs. Sleeping here parks systemd-sysupdate mid-transaction,
        # after the root partition is finalized. The fetcher's read
        # timeout eventually kills the transfer (EAGAIN) — the "deadline
        # kill" of the issue text.
        if NEEDLE in self.path:
            sys.stderr.write(f"strand-server: throttling {self.path} for {DELAY}s\n")
            sys.stderr.flush()
            time.sleep(DELAY)
        return super().copyfile(source, output_file)

    def log_message(self, fmt, *args):
        sys.stderr.write(
            "strand-server: %s - %s\n" % (self.address_string(), fmt % args)
        )


if __name__ == "__main__":
    directory = sys.argv[1] if len(sys.argv) > 1 else "."
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8123
    os.chdir(directory)
    sys.stderr.write(
        f"strand-server: serving {directory} on 127.0.0.1:{port} "
        f"(throttling *{NEEDLE}* by {DELAY}s)\n"
    )
    sys.stderr.flush()
    ThreadingHTTPServer(("127.0.0.1", port), StrandHandler).serve_forever()
