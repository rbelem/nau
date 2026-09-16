# shuttle pod activation — T13 cutover (issue #95), replaces 90-devbox.sh.
# Ported from the devbox-global init-hook; the proven ordering is kept:
# farm first (bws/starship/... resolve from the pod), then secrets, then
# prompt, then venv, then the ble.sh attach.

# Non-interactive short-circuit (same guard as the devbox init-hook)
[ "${-#*i}" == "$-" ] || [ ! -t 0 ] || [ -z "$PS1" ] || [ -n "$TOOLBOX_PATH" ] && return

# Pod farm on PATH. shellenv fails closed on unknown pod / no active
# generation; a broken eval must never take the shell down.
command -v shuttle >/dev/null 2>&1 && eval "$(shuttle pod shellenv --name daily)"

# ── Secrets: Bitwarden SM cache, regenerated from ~/.config/bws/sm.ini ──
# Verbatim port of the devbox init-hook block. The manifest maps secret
# names to env vars; [aliases] maps third-party names (GH_TOKEN) onto
# canonical SM secrets. Cache is fast and regenerable (XDG_RUNTIME_DIR).
XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-}"
_sm_cache="${XDG_RUNTIME_DIR:+"$XDG_RUNTIME_DIR/shuttle-secrets.sh"}"
_sm_manifest="$HOME/.config/bws/sm.ini"
# Legacy pre-bws path (bitw era) — fallback for machines not yet migrated
[ -f "$_sm_manifest" ] || _sm_manifest="$HOME/.config/bitw/sm.ini"

# ble.sh line editor (if terminal input is not working, remove ~/.cache/blesh/)
[ -f "$(blesh-share)/ble.sh" ] && source -- "$(blesh-share)/ble.sh" --attach=none

# Regenerate cache if missing — atomic write, single bws call
if [ -n "$XDG_RUNTIME_DIR" ] && [ ! -f "$_sm_cache" ] && command -v bws >/dev/null 2>&1; then
  if [ ! -f "$_sm_manifest" ]; then
    echo "90-shuttle.sh: SM manifest missing ($HOME/.config/bws/sm.ini) — secrets loading disabled" >&2
  else
    # Ensure BWS_ACCESS_TOKEN is available (libsecret fallback for headless
    # environments). Store via: secret-tool store --label='bws SM token' bitwarden sm-access-token
    if [ -z "${BWS_ACCESS_TOKEN:-}" ] && command -v secret-tool >/dev/null 2>&1; then
      _bws_token="$(secret-tool lookup bitwarden sm-access-token 2>/dev/null || true)"
      [ -n "$_bws_token" ] && export BWS_ACCESS_TOKEN="$_bws_token"
      unset _bws_token
    fi

    if [ -n "${BWS_ACCESS_TOKEN:-}" ]; then
    _sm_tmp="$_sm_cache.$$"
    (
      umask 077
      # Build space-separated list of manifest keys (secrets section only,
      # before [aliases]).
      _sm_keys=""
      _in_secrets=true
      while IFS= read -r _sm_line || [[ -n "$_sm_line" ]]; do
        _sm_line="${_sm_line%%#*}"
        _sm_line="${_sm_line//[[:space:]]/}"
        [ -z "$_sm_line" ] && continue
        [[ "$_sm_line" =~ ^\[aliases\]$ ]] && _in_secrets=false && continue
        [[ "$_sm_line" =~ ^\[ ]] && continue
        $_in_secrets || continue
        # Validate key is alphanumeric/underscore only
        [[ "$_sm_line" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
        _sm_keys="${_sm_keys:+$_sm_keys }$_sm_line"
      done < "$_sm_manifest"
      [ -z "$_sm_keys" ] && exit 1

      # Source bws output directly — --output env is designed for eval.
      # Handles multi-line values (SSH keys, PEM certs) correctly,
      # unlike a line-oriented grep+read pipeline.
      _sm_bws_err="$_sm_tmp.bws.err"
      if ! _sm_env="$(bws secret list --output env 2>"$_sm_bws_err")"; then
        _sm_last="$(tail -n 1 "$_sm_bws_err" 2>/dev/null || true)"
        echo "90-shuttle.sh: bws secret list failed — ${_sm_last:-unknown error}" >&2
        rm -f "$_sm_bws_err"
        exit 1
      fi
      rm -f "$_sm_bws_err"
      eval "$_sm_env"

      # Re-export only manifest keys with safe quoting
      for _k in $_sm_keys; do
        [ -n "${!_k:-}" ] && printf 'export %s=%q\n' "$_k" "${!_k}"
      done
    ) > "$_sm_tmp" && mv -f "$_sm_tmp" "$_sm_cache" || rm -f "$_sm_tmp"
    unset _sm_tmp _sm_keys _in_secrets _sm_bws_err _sm_env _sm_last
  else
    echo "90-shuttle.sh: BWS_ACCESS_TOKEN not found (env or libsecret 'bitwarden sm-access-token') — secrets loading disabled" >&2
  fi
  fi
fi

[ -n "$XDG_RUNTIME_DIR" ] && [ -f "$_sm_cache" ] && . "$_sm_cache"

# ── Post-source aliasing for SM secrets ──
# Maps alias env vars (used by third-party tools like gh, SDKs) to canonical
# SM secrets. Defined in [aliases] section of sm.ini.
# Does NOT override if the alias is already set by the user.
if [ -f "$_sm_manifest" ]; then
  _in_aliases=false
  while IFS= read -r _sm_line || [[ -n "$_sm_line" ]]; do
    [[ "$_sm_line" =~ ^\[aliases\]$ ]] && _in_aliases=true && continue
    [[ "$_sm_line" =~ ^\[ ]] && _in_aliases=false
    $_in_aliases || continue
    _sm_line="${_sm_line%%#*}"           # strip comments
    [[ "$_sm_line" != *"="* ]] && continue
    _alias="${_sm_line%%=*}"
    _canon="${_sm_line#*=}"
    _alias="${_alias//[[:space:]]/}"
    _canon="${_canon//[[:space:]]/}"
    [ -z "$_alias" ] || [ -z "$_canon" ] && continue
    # Don't override if alias already set (e.g., user exported it before init)
    [ -n "${!_alias:-}" ] && continue
    # Only alias if canonical has a value
    [ -n "${!_canon:-}" ] && export "$_alias=${!_canon}"
  done < "$_sm_manifest"
  unset _in_aliases _sm_line _alias _canon
fi

unset _sm_cache _sm_manifest

# ── nix-ld (NixOS hosts) ──
# Cache the dynamic linker path — it only changes when glibc updates.
if uname -v | grep -q 'NixOS'; then
  _nix_ld_cache="${XDG_CACHE_HOME:-$HOME/.cache}/devbox-nix-ld"
  if [ -f "$_nix_ld_cache" ] && [ -x "$(<"$_nix_ld_cache")" ]; then
    export NIX_LD="$(<"$_nix_ld_cache")"
  else
    export NIX_LD=$(nix eval --impure --raw --expr '
let
  pkgs = import <nixpkgs> {};
  NIX_LD = pkgs.lib.fileContents "${pkgs.stdenv.cc}/nix-support/dynamic-linker";
in NIX_LD
')
    [ -d "${XDG_CACHE_HOME:-$HOME/.cache}" ] || mkdir -p "${XDG_CACHE_HOME:-$HOME/.cache}"
    printf '%s\n' "$NIX_LD" > "$_nix_ld_cache"
  fi
  unset _nix_ld_cache
fi

# ── Editor + agent env (interim for the pod env gap, checklist §5.3) ──
export EDITOR=vi VISUAL=vi
export SUDO_EDITOR=vi
export OPENCODE_EXPERIMENTAL_BACKGROUND_SUBAGENTS=1

# ── Prompt and shell UX (binaries resolve from the pod farm) ──
command -v starship >/dev/null 2>&1 && eval "$(starship init bash --print-full-init)"
command -v zoxide   >/dev/null 2>&1 && eval "$(zoxide init bash)" && alias cd='z'
command -v fzf      >/dev/null 2>&1 && source <(fzf --bash)
command -v atuin    >/dev/null 2>&1 && eval "$(atuin init --disable-up-arrow bash)"
set -o vi

# ── Python virtual environment (pod python) ──
# Replaces the devbox VENV_DIR + PYTHONPATH pair: the venv carries the
# python3.14 packages that used to live in the devbox-global profile
# (inventory: examples/cutover/python-freeze.txt).
VENV_DIR="$HOME/.local/share/shuttle/python-venv"
export VENV_DIR
[ -d "$VENV_DIR" ] || python3 -m venv "$VENV_DIR"
[ -f "$VENV_DIR/bin/activate" ] && . "$VENV_DIR/bin/activate"

# ble.sh attach
[[ ! ${BLE_VERSION-} ]] || ble-attach
