#!/usr/bin/env bash
# #94 gate battery — proves the cutover set on current main from a
# cold-store pilot pod. Every gate runs under the login-shell contract:
# `eval "$(shuttle pod shellenv)"` puts the farm first on PATH and
# exports the #89 loader-lib LD_LIBRARY_PATH — the same env the rc port
# delivers (§4.3). Under it: the parity trio resolves at its bumped
# versions, the dynamic four start bare (no host LD_LIBRARY_PATH help),
# the meson family runs from its #90 merged prefixes, interpreter
# scripts self-locate through the extension tree (#94 tree routing),
# and the pod python imports cross-package modules (mesonbuild).
#
#   examples/cutover/pilot-gates.sh [root] [pod]
#
# Defaults to the #94 pilot root. Exit 1 lists failed gates.
set -u

ROOT="${1:-$HOME/.cache/issue94-pilot/shuttle/pods}"
POD="${2:-pilot94}"
FARM="$ROOT/$POD/current"
SHUTTLE="${SHUTTLE:-$PWD/target/debug/shuttle}"
fail=0

gate() { # gate <name> <command...>
  local name="$1"; shift
  if "$@" >/tmp/opencode/gate.out 2>&1; then
    printf 'ok   %-34s %s\n' "$name" "$(head -1 /tmp/opencode/gate.out)"
  else
    printf 'FAIL %-34s %s\n' "$name" "$(head -2 /tmp/opencode/gate.out | tr '\n' ' ')"
    fail=1
  fi
}

gate_eq() { # gate_eq <name> <expected> <command...>
  local name="$1" want="$2"; shift 2
  local got
  got="$("$@" 2>/dev/null | head -1)"
  if [ "$got" = "$want" ]; then
    printf 'ok   %-34s %s\n' "$name" "$got"
  else
    printf 'FAIL %-34s want %q got %q\n' "$name" "$want" "$got"
    fail=1
  fi
}

[ -d "$FARM" ] || { echo "FAIL no active generation at $FARM — sync first"; exit 1; }

# Login-shell contract: the shellenv prepends the farm to a host base
# PATH (NixOS keeps coreutils in /run/current-system/sw/bin — the gate
# harness itself needs them), then exports the #89 loader-lib
# LD_LIBRARY_PATH. No host module/loader paths leak in; the shellenv
# file is kept for triage.
export PATH="/run/current-system/sw/bin:/usr/bin:/bin"
unset LD_LIBRARY_PATH
unset SHUTTLE_PYTHONPATH
"$SHUTTLE" pod --name "$POD" shellenv --root "$ROOT" > /tmp/opencode/gate-shellenv.sh
# shellcheck disable=SC1091
. /tmp/opencode/gate-shellenv.sh

echo "=== parity bumps (§2 trio) ==="
gate_eq "git 2.55.0"        "git version 2.55.0"   git --version
gate_eq "tmux 3.7"          "tmux 3.7"             tmux -V
gate_eq "python 3.14.7"     "Python 3.14.7"        python3 --version

echo "=== dynamic four (shellenv contract, #89 seam) ==="
gate "git runs"    git --version
gate "tmux runs"   tmux -V
gate "htop runs"   htop --version
gate "tig runs"    tig --version

echo "=== meson family cold-built (#90 merged prefix) ==="
# dconf/secret-tool have no --version flag (verified upstream 0.49);
# their usage text on stderr proves the binary starts and links.
gate "dconf"       bash -c 'dconf 2>&1 | grep -q "Commands:"'
gate "secret-tool" bash -c 'secret-tool 2>&1 | grep -q "usage: secret-tool"'
gate "wl-copy"     wl-copy --version
gate "wtype"       bash -c 'wtype 2>&1 | grep -q "^Usage: wtype"'
gate "luarocks"    luarocks --version
gate "mesonbuild imports on py3.14" python3 -c 'import mesonbuild; print(mesonbuild.__file__)'

echo "=== blesh surface ==="
gate "blesh-share resolves" bash -c '[ -x "$(command -v blesh-share)" ]'
gate "ble.sh present"       bash -c '[ -s "$(blesh-share)/ble.sh" ]'
gate "ble.sh parses"        bash -n "$(blesh-share)/ble.sh"
# NOTE: ble.sh refuses non-interactive sources by design (its loader
# returns 1 when BASH_EXECUTION_STRING is set), so a -c load probe can
# never pass. The interactive attach is proven by the §4.6 fresh-pty
# login sweep (verify-sweep.sh).

echo "=== pod list shows the trio ==="
# pod list prints the table on stderr; capture both streams.
LIST="$("$SHUTTLE" pod --name "$POD" list --root "$ROOT" 2>&1)"
for want in "git" "tmux" "python"; do
  if printf '%s\n' "$LIST" | grep -q "^  $want"; then
    printf 'ok   %-34s %s\n' "pod list: $want" "$(printf '%s\n' "$LIST" | grep "^  $want" | head -1 | xargs)"
  else
    printf 'FAIL %-34s missing from pod list\n' "pod list: $want"
    fail=1
  fi
done

[ "$fail" -eq 0 ] && echo 'GATES: all green' || echo 'GATES: failures above'
exit "$fail"
