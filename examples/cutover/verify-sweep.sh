#!/usr/bin/env bash
# T13 cutover acceptance sweep — checklist §4.6, issues #95/#96.
# Enters a fresh interactive login shell on a pty so ~/.bashrc.d
# (90-shuttle.sh) is sourced and the pod farm, secrets, and venv are live.
#
#   examples/cutover/verify-sweep.sh          # post-cutover: must exit 0
set -u

DAILY="$HOME/.local/share/shuttle/pods/daily"

inner() {
  local rc=0
  # daily tools: first PATH hit must be the pod farm, no devbox hits
  local tools="atuin bw bws bun chezmoi dconf delta difft doggo dos2unix evtest fd file fzf gmc gh ghq git git-credential-manager git-credential-oauth htop jq luarocks node perltidy python3 rg sesh sqlite3 starship statix tig tmux tree tree-sitter unzip uv wl-copy wtype xxd zoxide 7z blesh-share"
  local t hits first
  for t in $tools; do
    hits=$(type -aP "$t" 2>/dev/null)
    first=$(printf '%s\n' "$hits" | head -1)
    if [ -z "$first" ]; then
      printf 'FAIL %-24s not found\n' "$t"; rc=1; continue
    fi
    if printf '%s\n' "$hits" | grep -q '/devbox/'; then
      printf 'FAIL %-24s devbox hit: %s\n' "$t" "$(printf '%s\n' "$hits" | grep /devbox/ | head -1)"; rc=1
    elif [ "${first#"$DAILY"}" != "$first" ]; then
      printf 'ok   %-24s %s\n' "$t" "$first"
    else
      printf 'FAIL %-24s first hit %s\n' "$t" "$first"; rc=1
    fi
  done

  # devbox machinery gone from the environment
  if env | grep -qi devbox; then
    printf 'FAIL devbox env vars: %s\n' "$(env | grep -i devbox | head -1)"; rc=1
  else
    echo 'ok   env is devbox-free'
  fi

  # nix-specific tools dropped per #29
  local nt
  for nt in attic-client nix-search-cli nix-prefetch-git; do
    if command -v "$nt" >/dev/null 2>&1; then
      printf 'FAIL %-24s still resolves: %s\n' "$nt" "$(command -v "$nt")"; rc=1
    else
      echo "ok   dropped: $nt"
    fi
  done

  # fonts surface from the pod
  if fc-match 'Hack Nerd Font' 2>/dev/null | grep -qi 'Hack'; then
    echo "ok   font: $(fc-match 'Hack Nerd Font')"
  else
    echo 'FAIL font: Hack Nerd Font does not resolve'; rc=1
  fi

  # secrets present
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    echo 'ok   GITHUB_TOKEN present'
  else
    echo 'FAIL GITHUB_TOKEN missing (secrets loader)'; rc=1
  fi

  # python venv live against pod python
  if [ -n "${VIRTUAL_ENV:-}" ] && "$VIRTUAL_ENV/bin/python3" -c 'import whichllm' 2>/dev/null; then
    echo "ok   venv: $VIRTUAL_ENV (whichllm imports)"
  else
    echo "FAIL venv: VIRTUAL_ENV=${VIRTUAL_ENV:-unset} / whichllm import failed"; rc=1
  fi

  # interactive line editor attached
  if [ -n "${BLE_VERSION:-}" ]; then
    echo "ok   ble.sh attached (${BLE_VERSION%%.*})"
  else
    echo 'FAIL ble.sh not attached'; rc=1
  fi

  return "$rc"
}

if [ -n "${SHUTTLE_SWEEP_INNER:-}" ]; then
  inner
  rc=$?
  [ "$rc" -eq 0 ] && echo 'INNER: all gates green' || echo 'INNER: gates red'
  exit "$rc"
fi

SELF="$(readlink -f "$0")"
if script -qec "env SHUTTLE_SWEEP_INNER=1 bash -li -c 'source \"$SELF\"'" /dev/null; then
  echo 'SWEEP: all gates green'
  exit 0
else
  echo 'SWEEP: failures above' >&2
  exit 1
fi
