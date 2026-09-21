#!/usr/bin/env bash
# examples/valkey-search-roundtrip.sh — issue #109: PROVE the --loadmodule
# round-trip live.
#
# Boots the shuttle-built valkey-server with the shuttle-built valkey-search
# module (libsearch.so from the valkey-search snap payload) and drives real
# commands over a unix socket:
#
#   PING                  — server is responsive
#   MODULE LIST           — the search module is loaded
#   FT.CREATE + HSET +
#   FT.SEARCH + FT.INFO   — a real module command round-trip: index a hash
#                           and query it through the module's engine
#   SHUTDOWN NOSAVE       — clean exit, process gone
#
# The snaps are squashed artifacts; this script unsquashes them into a fresh
# mktemp workdir and runs the binaries through the glibc 2.43 loader with an
# explicit --library-path (no pod, no network listener, no root: --port 0
# disables TCP, the round-trip rides the unix socket). Everything is cleaned
# up on exit, pass or fail.
#
# Requirements: devbox on PATH (unsquashfs rides it when not installed; the
# valkey snap is built through devbox+shuttle when missing) and the artifact
# set from the valkey-search chain build (issue #109).
#
# Usage:
#   examples/valkey-search-roundtrip.sh
#
# Environment overrides:
#   VS_ARTIFACTS     directory holding the built snaps
#                    (default: /tmp/opencode/vsbuild)
#   VS_VALKEY_SNAP   path to the valkey snap; discovered in VS_ARTIFACTS by
#                    default, built from pkgs/v/valkey/init.lua when absent
#   SHUTTLE_BIN      shuttle binary used for the on-demand valkey build
#                    (default: target/release/shuttle, then target/debug)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VS_ARTIFACTS="${VS_ARTIFACTS:-/tmp/opencode/vsbuild}"
VS_VALKEY_SNAP="${VS_VALKEY_SNAP:-}"
if [ -z "${SHUTTLE_BIN:-}" ]; then
    if [ -x "$REPO_ROOT/target/release/shuttle" ]; then
        SHUTTLE_BIN="$REPO_ROOT/target/release/shuttle"
    else
        SHUTTLE_BIN="$REPO_ROOT/target/debug/shuttle"
    fi
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/valkey-roundtrip.XXXXXX")"
SERVER_PID=""
cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

die() { echo "FAIL: $*" >&2; [ -f "$WORK/server.log" ] && tail -30 "$WORK/server.log" >&2; exit 1; }
pass() { echo "PASS: $*"; }

unsquash() { # unsquash <snap> <dest>
    # env -u LD_LIBRARY_PATH: the pod env leak breaks devbox's node
    # (AGENTS.md build commands use the same prefix)
    if command -v unsquashfs >/dev/null 2>&1; then
        unsquashfs -d "$2" -n "$1" >/dev/null 2>&1
    else
        env -u LD_LIBRARY_PATH devbox run -- unsquashfs -d "$2" -n "$1" >/dev/null 2>&1
    fi
}

snap_of() { # snap_of <glob-prefix> — exactly the artifact, no ambiguity
    local hit
    hit="$(find "$VS_ARTIFACTS" -maxdepth 1 -name "$1" | sort | tail -1)"
    [ -n "$hit" ] || die "artifact not found in $VS_ARTIFACTS: $1"
    echo "$hit"
}

# --- resolve the valkey snap (build on demand through the port itself) -----
if [ -z "$VS_VALKEY_SNAP" ]; then
    VS_VALKEY_SNAP="$(find "$VS_ARTIFACTS" -maxdepth 1 -name 'valkey_*.snap' | sort | tail -1 || true)"
fi
if [ -z "$VS_VALKEY_SNAP" ]; then
    echo "no valkey snap in $VS_ARTIFACTS — building from pkgs/v/valkey/init.lua"
    mkdir -p "$WORK/out"
    (cd "$REPO_ROOT" && env -u LD_LIBRARY_PATH devbox run -- "$SHUTTLE_BIN" build \
        --file pkgs/v/valkey/init.lua -A amd64 --output "$WORK/out") \
        >"$WORK/valkey-build.log" 2>&1 || die "shuttle build of valkey failed ($WORK/valkey-build.log)"
    VS_VALKEY_SNAP="$(find "$WORK/out" -maxdepth 1 -name 'valkey_*.snap' | sort | tail -1)"
fi
[ -n "$VS_VALKEY_SNAP" ] && [ -f "$VS_VALKEY_SNAP" ] || die "valkey snap not resolvable"
echo "valkey snap: $VS_VALKEY_SNAP"

# --- resolve module + closure snaps ----------------------------------------
VS_SEARCH_SNAP="$(snap_of 'valkey-search_*.snap')"
GLIBC_SNAP="$(snap_of 'glibc_*.snap')"
STDCPP_SNAP="$(snap_of 'libstdcpp_*.snap')"
LIBGCC_SNAP="$(snap_of 'libgcc_*.snap')"
GRPC_SNAP="$(snap_of 'grpc_*.snap')"
PROTOBUF_SNAP="$(snap_of 'protobuf_*.snap')"
RE2_SNAP="$(snap_of 're2_*.snap')"
OPENSSL_SNAP="$(snap_of 'openssl_*.snap')"
ZLIB_SNAP="$(snap_of 'zlib_*.snap')"

for pair in "$VS_VALKEY_SNAP:valkey" "$VS_SEARCH_SNAP:search" "$GLIBC_SNAP:glibc" \
    "$STDCPP_SNAP:stdcpp" "$LIBGCC_SNAP:gcc" "$GRPC_SNAP:grpc" "$PROTOBUF_SNAP:protobuf" \
    "$RE2_SNAP:re2" "$OPENSSL_SNAP:openssl" "$ZLIB_SNAP:zlib"; do
    mkdir -p "$WORK/root/${pair##*:}"  # unsquashfs won't create intermediates
    unsquash "${pair%%:*}" "$WORK/root/${pair##*:}"
done

# --- payload + loader layout (find, don't assume usr vs usr/usr nesting) ----
LIBSEARCH="$(find "$WORK/root/search" -name libsearch.so | head -1)"
[ -n "$LIBSEARCH" ] && [ -f "$LIBSEARCH" ] || die "libsearch.so not in valkey-search snap payload"
VALKEY_SERVER="$(find "$WORK/root" -name valkey-server -type f | head -1)"
VALKEY_CLI="$(find "$WORK/root" -name valkey-cli -type f | head -1)"
[ -x "$VALKEY_SERVER" ] || die "valkey-server not in valkey snap payload"
[ -x "$VALKEY_CLI" ] || die "valkey-cli not in valkey snap payload"
LOADER="$(find "$WORK/root/glibc" -name ld-linux-x86-64.so.2 | head -1)"
[ -n "$LOADER" ] || die "glibc loader not found"

# --- library path: every lib dir the module's DT_NEEDED closure touches -----
LIBPATH="$(find "$WORK/root" -type d \( -name lib -o -name lib64 \) | tr '\n' ':')"
echo "booting: $VALKEY_SERVER --loadmodule $LIBSEARCH"

"$LOADER" --library-path "$LIBPATH" "$VALKEY_SERVER" \
    --dir "$WORK" --port 0 \
    --unixsocket "$WORK/v.sock" --unixsocketperm 700 \
    --daemonize no --pidfile "$WORK/v.pid" \
    --loadmodule "$LIBSEARCH" \
    >"$WORK/server.log" 2>&1 &
SERVER_PID=$!

cli() { "$LOADER" --library-path "$LIBPATH" "$VALKEY_CLI" -s "$WORK/v.sock" --raw "$@"; }

# --- bounded wait for readiness --------------------------------------------
ready=""
for _ in $(seq 1 150); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        die "valkey-server exited during startup"
    fi
    if [ -S "$WORK/v.sock" ] && [ "$(cli PING 2>/dev/null || true)" = "PONG" ]; then
        ready=1
        break
    fi
    sleep 0.2
done
[ -n "$ready" ] || die "server not ready within 30s"
pass "server up (pid $SERVER_PID), socket $WORK/v.sock"

# --- (a) PING ---------------------------------------------------------------
out="$(cli PING)"
[ "$out" = "PONG" ] || die "PING returned '$out', expected PONG"
pass "PING -> PONG"

# --- (b) MODULE LIST shows the search module --------------------------------
modlist="$(cli MODULE LIST)"
echo "$modlist" | grep -qx "search" || die "MODULE LIST does not show 'search': $(echo "$modlist" | tr '\n' ' ')"
pass "MODULE LIST -> search module loaded"

# --- (c) real module round-trip: index + query ------------------------------
out="$(cli FT.CREATE idx ON HASH PREFIX 1 doc: SCHEMA title TEXT)"
[ "$out" = "OK" ] || die "FT.CREATE returned '$out'"
pass "FT.CREATE idx (HASH, TEXT field) -> OK"

out="$(cli HSET doc:1 title "hello shuttle roundtrip")"
[ "$out" = "1" ] || die "HSET returned '$out'"
pass "HSET doc:1 -> 1"

search_out=""
for _ in $(seq 1 25); do  # index propagation is async on the module side
    search_out="$(cli FT.SEARCH idx "shuttle" DIALECT 2)" || true
    echo "$search_out" | grep -q "doc:1" && break
    sleep 0.2
done
echo "$search_out" | grep -q "doc:1" || die "FT.SEARCH did not return doc:1: $search_out"
pass "FT.SEARCH 'shuttle' -> doc:1 (module indexed and matched)"

info_out="$(cli FT.INFO idx)"
echo "$info_out" | grep -q "idx" || die "FT.INFO returned nothing usable: $info_out"
pass "FT.INFO idx -> index metadata present"

# --- clean shutdown, assert exit --------------------------------------------
cli SHUTDOWN NOSAVE >/dev/null 2>&1 || true
gone=""
for _ in $(seq 1 50); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then gone=1; break; fi
    sleep 0.1
done
[ -n "$gone" ] || die "valkey-server still alive after SHUTDOWN"
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""
pass "SHUTDOWN NOSAVE -> process exited"
[ -S "$WORK/v.sock" ] && rm -f "$WORK/v.sock"

echo "OK: valkey --loadmodule round-trip proven (issue #109)"
