#!/usr/bin/env python3
"""Auth-exempt S3-shaped stub for the nau-cache-publish e2e test.

Test infrastructure for ticket #270 — deliberately does NOT validate
SigV4 (the signature math is cross-checked by the test script against
an independent python implementation; S3 dialect behavior needs the
real rustfs endpoint, which is blocked on the zet checklist steps 0-1).

Semantics:
  HEAD/GET/PUT on /<bucket>/<key>, stored under --data (auth-exempt).
  key containing ".403"     -> HEAD/GET answer 403 (PUT still allowed;
                               proves 403-is-a-miss publisher semantics)
  key containing ".failput" -> PUT answers 500 (fail-loud path)
Every request appends one JSON line to --log:
  {"method","path","status","content_type","authorization"}
"""

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DATA = None
LOG = None


def store_path(path: str) -> str:
    # path is "/<bucket>/<key>"; refuse traversal, keep it dumb.
    parts = [p for p in path.split("/") if p]
    if len(parts) < 2 or any(p in (".", "..") for p in parts):
        raise ValueError(path)
    return os.path.join(DATA, *parts)


class StubHandler(BaseHTTPRequestHandler):
    def log_message(self, *_a):  # silence request spam
        pass

    def _log(self, status: int) -> None:
        if LOG is None:
            return
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(
                json.dumps(
                    {
                        "method": self.command,
                        "path": self.path,
                        "status": status,
                        "content_type": self.headers.get("Content-Type"),
                        "authorization": self.headers.get("Authorization"),
                        "x_amz_date": self.headers.get("x-amz-date"),
                    }
                )
                + "\n"
            )

    def _reply(self, status: int, body: bytes, ctype: str = "text/plain") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _deny(self) -> bool:
        return ".403" in self.path

    def do_HEAD(self) -> None:
        try:
            p = store_path(self.path)
        except ValueError:
            self._reply(400, b"bad path")
            self._log(400)
            return
        if self._deny():
            status = 403
        elif os.path.isfile(p):
            status = 200
        else:
            status = 404
        body = b""
        if status == 200:
            with open(p, "rb") as f:
                body = f.read()
        self._reply(status, body)
        self._log(status)

    do_GET = do_HEAD  # same routing; _reply skips the body for HEAD

    def do_PUT(self) -> None:
        try:
            p = store_path(self.path)
        except ValueError:
            self._read_body()
            self._reply(400, b"bad path")
            self._log(400)
            return
        body = self._read_body()
        if ".failput" in self.path:
            self._reply(500, b"stub forced failure")
            self._log(500)
            return
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(body)
        self._reply(200, b"")
        self._log(200)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""


def main() -> int:
    global DATA, LOG
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--data", required=True)
    ap.add_argument("--log", default=None)
    ap.add_argument("--portfile", required=True)
    args = ap.parse_args()
    DATA = args.data
    LOG = args.log
    os.makedirs(DATA, exist_ok=True)
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), StubHandler)
    with open(args.portfile, "w", encoding="utf-8") as f:
        f.write(str(srv.server_address[1]))
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
