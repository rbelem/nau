# T13 cutover checklist — retiring devbox-global (issue #29)

Status: **draft for the owner** — the human runs the cutover; nothing in
this checklist has been applied to the live environment. Every audit step
was read-only; the parity pilot ran under a redirected pod root
(`/tmp/opencode/issue-29-pilot`), never `default`/`work`/`t36`, never the
live store.

## 0. What this is

devbox-global (`~/.local/share/devbox/global/default`, wired in via
`~/.bashrc.d/90-devbox.sh` → `source <(devbox global shellenv --init-hook)`)
is replaced by a shuttle **pod** whose bin farm sits on `PATH` through
`shuttle pod shellenv` (#47). Per #29, the nix-specific tools
(`attic-client`, `nix-search-cli`, `nix-prefetch-git`) are dropped, not
ported.

Preconditions verified before writing this checklist:

- Pod verb surface complete: `add`, `remove`, `sync`, `list`, `shellenv`,
  `update`, `rebuild`, `rollback`, `gc` (parity tickets #19/#20, #24/#38).
- `pod shellenv` landed (#47): eval-safe `export PATH="<farm>:$PATH"`, no
  RC writes, fails closed on unknown pod / no active generation.
- The pool (`pkgs/`) covers the daily tool set (matrix below).
- **Gap fixed in this cutover branch:** font payload packages (the
  `nerd-fonts-*` set) had no activation surface — they declare no `apps`,
  so the farm exposed nothing, and the fonts were only visible through the
  devbox profile's `share/` riding `XDG_DATA_DIRS`. Pods now surface font
  payloads at `$XDG_DATA_HOME/fonts/shuttle-pod-<pod>/…` (the same
  generation-versioned mechanism as desktop launchers), which fontconfig
  scans by default (`<dir prefix="xdg">fonts</dir>`, verified empirically:
  `fc-match 'Hack Nerd Font'` resolves from the pilot surface and falls
  back to DejaVu without it).

## 1. Audit — what devbox-global provides → pod equivalent

Inventory basis: `devbox global list` (91 entries), `devbox.json`
(`env`, `shell.init_hook`, `shell.scripts`), `init-hook`,
`process-compose.yml`, `~/.bashrc.d/90-devbox.sh`, `~/.bashrc.d/10-bit.sh`,
`~/.local/bin/`.

| devbox-global capability | pod equivalent | verdict |
|---|---|---|
| nixpkgs packages (48 named) | pool packages + `shuttle pod add` | covered — matrix §2 |
| ~30 local path flakes (`devbox.d/*`) | pool packages (port per tool) | partial — follow-ups §5.1 |
| PATH activation (`devbox global shellenv`) | `eval "$(shuttle pod shellenv)"` (#47) | covered |
| `env:` block (EDITOR, LOCALE_ARCHIVE, PYTHONPATH, VENV_DIR, …) | none — pods have no env surface (ADR-0016 §7 defers env hooks to `shuttle run`) | **open** §5.3 |
| Secrets: init-hook sources `$XDG_RUNTIME_DIR/devbox-secrets.sh`, regenerated from `~/.config/bws/sm.ini` via `bws` + `BWS_ACCESS_TOKEN` (libsecret fallback) | none needed in shuttle — user-level init snippet | checklist step §4.3 |
| Shell init: ble.sh, starship, zoxide (`cd` alias), fzf bindings, atuin, `set -o vi`, `SUDO_EDITOR`, XDG_DATA_DIRS completions | same init lines in the user's `~/.bashrc.d`, binaries now resolve from the pod farm | checklist step §4.4; ble.sh gap §5.2 |
| Services: process-compose (`valkey`+search module, `bifrost`, `wigolo`) | none — pods have no service verb (ADR-0015 verb set) | **open** §5.4 |
| Scripts: `update-flake`, `upload-flakes`, `config-sync/pull/push`, `setup-*`, `first-install`, `nix-store-gc` | nix/flake-specific → die with devbox-global (per #29) | dropped, §5.5 |
| `~/.local/bin` shims (`bitw`, `jcode`, `iii`, `starship`, `yq`, …) | untouched — not devbox-managed | persists; shadowing note §4.6 |
| Nerd fonts (hack, noto, fira-code) | `nerd-fonts-*` pool packages + **new font surface** | covered by this branch |
| GUI: `.desktop` launchers for pod apps | desktop launcher emit (#7) | covered |
| Rollback of the tool set | `shuttle pod rollback` (flips the pod's `current` only) | covered |

## 2. Version parity matrix (daily set)

devbox-global version → pool version (`pkgs/`), sampled 2026-09-13.
"=" means identical pin.

Identical: atuin 18.19.0, bitwarden-cli 2026.7.0, bws 2.1.0, bun 1.4.2,
chezmoi 2.70.5, dconf 0.49.0, delta 0.19.2, difftastic 0.70.0, doggo 1.3.0,
dos2unix 7.5.5, evtest 1.36, fd 10.4.2, file 5.48, fzf 0.74.3,
geminicommit 0.8.0, gh 2.97.0, ghq 1.10.1, git-credential-manager 2.7.3,
git-credential-oauth 0.17.2, htop 3.5.3, jq 1.8.2, libsecret 0.21.7,
node 26.7.0, ripgrep 15.2.0, sesh 2.28.0, sqlite 3.53.3, starship 1.26.0,
statix 0.5.8, tig 2.6.1, tree 2.3.2, tree-sitter 0.26.9, unzip 6.0,
uv 0.12.3, wl-clipboard 2.3.0, wtype 0.4, xxd 9.0.0609, zoxide 0.10.0,
nerd-fonts 3.5.x.

Pool newer (safe): go 1.27.1 (devbox 1.26.5), rust/cargo 1.98.1 (1.97.1),
luarocks 3.13.0 (3.9.1), p7zip 26.03 (17.06), perltidy 20260826 (20250711).

Pool **behind** — bump before cutover or accept deliberately:

| tool | devbox-global | pool pin |
|---|---|---|
| git (gitFull) | 2.55.0 | 2.47.2 |
| tmux | 3.7 | 3.5a |
| python | 3.14.4 (python314) | 3.12.11 (python) |

Dropped per #29 (not ported): `attic-client`, `nix-search-cli`,
`nix-prefetch-git`, plus devbox/nix machinery itself (`NIX_CONFIG` env,
nix cache block, `nix-store-gc`).

## 3. Pilot evidence (redirected root)

Ran in `/home/rodrigo/.cache/issue29-pilot` (a copy of an earlier
`/tmp/opencode/issue-29-pilot` after the shared `/tmp` filled up), pod
name `pilot`, against this worktree's pool. Re-runnable: §6.

- `shuttle pod --name pilot sync` — green at the third stage: ~60
  packages declared, generation **2** installed, bin farm emitted
  (68 direct symlinks), desktop launchers + font surface re-emitted.
- `shuttle pod list` — versions match the pool pins in §2 (jq 1.8.2,
  ripgrep 15.2.0, gh 2.97.0, node 26.7.0, python 3.12.11, go 1.27.1,
  rust/cargo 1.98.1, bun 1.4.2, git 2.47.2, bws 2.1.0, starship 1.26.0,
  nerd-fonts 3.5.1 ×3, …).
- `PATH=<farm>:$PATH` then `which <tool>` — every daily tool resolves to
  `<root>/pilot/current/<tool>`, a direct store symlink (no shim), and
  runs: `jq-1.8.2`, `ripgrep 15.2.0`, `gh 2.97.0`, `node v26.7.0`,
  `Python 3.12.11`, `go1.27.1`, `cargo 1.98.1`, `bun 1.4.2`,
  `bws 2.1.0`, `bw 2026.7.0`, `sesh 2.28.0`, `statix 0.5.8`,
  `7-Zip 26.03`, `evtest 1.36`, `atuin 18.19.0`, `chezmoi v2.70.5`,
  `zoxide 0.10.0`, `starship 1.26.0`, `xxd`, `sqlite3 3.53.3`, `perl`,
  `go1.27.1`, … (68 farm entries; renamed apps surface as declared:
  `difft`, `gmc`).
- **Fonts**: the pod surface at
  `$XDG_DATA_HOME/fonts/shuttle-pod-pilot/` carries all three nerd
  fonts as store symlinks; `fc-match 'Hack Nerd Font'` and
  `fc-match 'FiraCode Nerd Font'` resolve to the pod's files
  (XDG_DATA_DIRS neutralized), and fall back to DejaVu without the
  surface — the exact regression the font emit fixes.
- **Rollback**: `pod rollback` 2→1 withdraws `nerd-fonts-noto` /
  `nerd-fonts-fira-code` from the user fonts dir (gen 1 doesn't carry
  them) and keeps `hack`; 1→2 restores all three. Fonts follow
  generations exactly like launchers and farm binaries.
- **Dynamic-library findings** (the audit's sharpest result, §5.7):
  statically-linked or self-contained tools all run directly
  (ripgrep, fd, fzf, delta, doggo, chezmoi, atuin, uv, node, bun, go,
  cargo, bws, gh, …). Dynamically-linked single binaries (git →
  libpcre2/libz, tmux → libncursesw/libevent, htop → libncursesw) fail
  at the loader stage *as linked*, because the requires-closure
  libraries are installed under the generation's `extensions/` tree but
  nothing puts that tree on the loader path for unconfined farm apps.
  With `LD_LIBRARY_PATH` over `extensions/<pkg>/usr/usr/lib`, all of
  them run (git 2.47.1, tmux 3.5a, tig 2.6.1, htop 3.5.3 verified) —
  the content is there; the loader seam is the gap.
- Multi-file apps work through the per-package assembly (`python3`
  runs its own payload via `apps/python/usr/bin/…`).

### 3.1 What blocked the meson class (dispositioned, not absorbed)

`dconf`, `libsecret`, `wl-clipboard`, `wtype` (→ `wayland`, → meson →
needs `python3` from the merged build prefix) fail to BUILD from a cold
store with:

```
/shuttle-build-prefix/usr/bin/python3: line 6:
  /shuttle-build-prefix/active/extensions/python/usr/usr/bin/python3.real: No such file or directory
```

This is the **already-recorded ADR-0017-addendum gap**: pod-built
toolchain/payload wrappers cannot serve as merged-prefix `build_deps` —
"a wrapper-aware prefix build is the follow-up." Plus `luarocks`, whose
build script misses its generated `etc/luarocks/config-5.4.lua` under
the same prefix (same family). These five stay devbox-only until that
follow-up lands; they are the only daily-set members not proven in the
pilot.

<!-- EVIDENCE -->

## 4. The cutover (exact commands, ordered)

**Run everything from a shell that does NOT have devbox on PATH when
possible; the cutover is one session, ordered so a failure at any step
leaves the old stack intact (rollback = §4.7).**

### 4.1 Prepare the pod (harmless — nothing on PATH changes yet)

```bash
# One-time: create the daily pod mirroring the audited set.
# (Pool pins for git/tmux/python first bumped per §2 if desired.)
shuttle pod --name daily add <each package from §2 matrix>
shuttle pod --name daily sync

# Parity smoke BEFORE any rc change:
shuttle pod --name daily list
eval "$(shuttle pod shellenv --name daily)"
which jq rg fd fzf gh git tmux bws starship zoxide atuin   # → ~/.local/share/shuttle/pods/daily/current/bin/…
fc-match 'Hack Nerd Font'                                   # resolves from the pod surface
```

### 4.2 Cut the shell over (the actual retirement)

```bash
# Replace the devbox lines in ~/.bashrc.d/90-devbox.sh with:
#   [ ! -t 0 ] || [ -z "$PS1" ] && return
#   eval "$(shuttle pod shellenv --name daily)"
# (no `devbox completion bash`; no `devbox global shellenv --init-hook`)
$EDITOR ~/.bashrc.d/90-devbox.sh

# Start a FRESH shell and confirm the pod farm is the only source:
exec bash -l
type -a jq rg tmux      # every hit from .../pods/daily/current/bin, none from devbox
env | grep -i devbox    # must be empty
```

### 4.3 Secrets (move, don't lose)

The secrets loader lives inside the devbox init-hook today. Keep it
working with a standalone snippet — `~/.bashrc.d/20-secrets.sh`:

```bash
# Secrets: source the SM cache, regenerating from ~/.config/bws/sm.ini
# (bws comes from the pod farm). Mirrors the old devbox init-hook block.
_sm_cache="${XDG_RUNTIME_DIR:+$XDG_RUNTIME_DIR/devbox-secrets.sh}"
if [ -n "$XDG_RUNTIME_DIR" ] && [ ! -f "$_sm_cache" ] && command -v bws >/dev/null 2>&1 \
   && [ -f "$HOME/.config/bws/sm.ini" ] && [ -n "${BWS_ACCESS_TOKEN:-}" ]; then
  while IFS= read -r _k || [ -n "$_k" ]; do
    _k="${_k%%#*}"; _k="$(printf '%s' "$_k" | tr -d '[:space:]')"
    [ -z "$_k" ] || { _sm_secrets=1; break; }
  done < "$HOME/.config/bws/sm.ini"
fi
[ -f "$_sm_cache" ] && . "$_sm_cache"
unset _sm_cache _k
```

(Or the equivalent one-liner the owner prefers; `BWS_ACCESS_TOKEN` already
comes from `~/.bashrc.d/10-bit.sh`, which stays.)

### 4.4 Shell init lines (starship/zoxide/fzf/atuin/vi)

Append to `~/.bashrc.d/30-prompt.sh` (binaries resolve from the pod farm
once §4.2 is in place):

```bash
command -v starship >/dev/null 2>&1 && eval "$(starship init bash --print-full-init)"
command -v zoxide   >/dev/null 2>&1 && eval "$(zoxide init bash)" && alias cd='z'
command -v fzf      >/dev/null 2>&1 && source <(fzf --bash)
command -v atuin    >/dev/null 2>&1 && eval "$(atuin init --disable-up-arrow bash)"
set -o vi
export SUDO_EDITOR=vi
```

### 4.5 Uninstall devbox-global (only after §4.2 is proven)

```bash
devbox global list > ~/devbox-global-inventory-backup.txt   # final record
rm -f ~/.bashrc.d/90-devbox.sh                               # the hook (already emptied in §4.2)
# Then remove the install itself (devbox's own uninstall; ~GBs freed):
devbox global rm --all          # or: rm -rf ~/.local/share/devbox  (owner's call)
# nix store GC to reclaim the closure:
nix store gc
```

### 4.6 Post-cutover checks (acceptance criteria of #29)

- [ ] Fresh shell resolves daily tools from the pod farm only:
      `type -a <tool>` for every tool in the §2 matrix — no
      `/home/rodrigo/.local/share/devbox/...` hits.
- [ ] devbox-global removed from PATH/rc: `env | grep -i devbox` empty;
      `~/.bashrc.d/90-devbox.sh` gone.
- [ ] nix-specific tools dropped: `attic-client`, `nix-search-cli`,
      `nix-prefetch-git` all `command -v` → nothing.
- [ ] Fonts still resolve (`fc-match 'Hack Nerd Font'` → pod surface).
- [ ] Secrets present in a fresh shell (`env | grep GITHUB_TOKEN`).
- [ ] Known shadowing note: `~/.local/bin` still holds real binaries
      (`starship`, `starship-patched`, `yq`, `iii`, `himalaya`,
      `bitw-new`, symlinks `bitw`/`jcode`). The farm is PREPENDED, so
      pod tools now win over these — if `~/.local/bin/starship` was a
      deliberate local build, either remove it or drop `starship` from
      the pod.
- [ ] Gaps filed (§5) — none absorbed silently.

### 4.7 Rollback (any point before §4.5)

```bash
# Revert the rc edit:
cp ~/.bashrc.d/90-devbox.sh.bak ~/.bashrc.d/90-devbox.sh   # take the backup in §4.2
exec bash -l
type -a jq    # back on the devbox profile
```

The pod is inert without the shellenv eval — a failed cutover never
breaks the old stack. After §4.5 the rollback path is restore-from-backup
of `~/.local/share/devbox` (nix store still holds the closures until the
GC in §4.5 — run `nix store gc` only after a full day of cutover).

## 5. Explicitly NOT covered by pods yet (open work, per #29
"filed as follow-up tickets, not silently absorbed")

### 5.1 Pool ports missing (biggest bucket — ~25 personal tools)

`zenity`, `podman`, `jdk21`, `chromium`, `valkey` (+ `valkey-search`
module), `neovim`, `blesh` (see §5.2), `opencode-v2`, `graphify`,
`skills`, `playwright-cli`, `codeburn`, `codegraph`, `llm-verifier`,
`agentmemory`, `impeccable`, `skillspector`, `bifrost`, `deepsec`,
`deepseek-harness`, `pdf-inspector`, `wigolo`, `valkey-search`, `anydoc`,
`tree-sitter-perl`. Most are dep-fetch ecosystem tools (npm/pip) that
ADR-0017 supports — they need packages authored, not new machinery.
**Until ported, these stay devbox-only — cutover is gated on the owner
dispositioning each (port now vs. live without).**

### 5.2 ble.sh has no pool package

The interactive line editor loads from the devbox profile
(`$(blesh-share)/ble.sh`). Either port `blesh` to the pool or accept
plain readline after cutover. Not shadowable by another tool.

### 5.3 Pod env vars (ADR-0016 §7 follow-up)

`EDITOR`/`VISUAL`, `LOCALE_ARCHIVE`, `PYTHONPATH`+`VENV_DIR`,
`OPENCODE_EXPERIMENTAL_BACKGROUND_SUBAGENTS` come from devbox.json's
`env:`. Pods have no env surface (the `shuttle run` env-hook home is
earmarked but unbuilt). Interim: keep the exports in a bashrc.d snippet.
Locale support specifically (LOCALE_ARCHIVE) needs a pod decision:
system locales vs. a pod locale payload.

### 5.4 Pod services

`valkey` (with the valkey-search module), `bifrost`, `wigolo` run under
devbox's process-compose. Pods have no service verb (ADR-0015). Options:
a `shuttle pod service` verb backed by systemd user units, or keep a
standalone process-compose launched from a user unit. None exists today.

### 5.5 Dropped with devbox-global (by design, #29)

`update-flake` / `upload-flakes` / `config-sync` / `config-pull` /
`config-push` / `nix-store-gc` (nix/flake machinery), `setup-*`
(first-install provisioning — one-shot, machine-specific),
`bin/cache` (nix-cache helper).

### 5.6 share/ activation (completions, man pages) — minor

Pods surface `bin/` (farm), desktop launchers, and now fonts — but not a
general `share/` tree, so bash completions and man pages shipped inside
pod payloads stay unreachable. Today the pool packages barely ship any
(only `tree` carries a man page), so nothing daily breaks; revisit if the
pool grows share-heavy packages.

### 5.7 Loader path for requires-closure libraries (NEW, demonstrated)

Unconfined farm apps that dynamically link libraries from OTHER pod
packages (git → pcre2/zlib; tmux/htop → ncurses/libevent) cannot start:
the libraries ARE installed per generation under
`<gen>/extensions/<pkg>/usr/usr/lib`, but nothing puts that tree on the
loader path (farm links are per-file binaries; `$ORIGIN`/RUNPATH point
into per-package assemblies, not across packages). Interim workaround
(proven in the pilot): export `LD_LIBRARY_PATH` over the generation's
extension lib dirs — but a generation-versioned, automatic seam is
required for cutover (options: emit-time wrapper setting LD_LIBRARY_PATH
in the #12 wrapper family, an ld.so.conf.d drop-in per pod, or binding
the extensions tree via the `shuttle run` assembly). Until landed:
cutover keeps git/tmux/htop/tig working only via the devbox profile —
i.e. **this is the one code-level blocker for those four tools**.

### 5.8 Build-time wrappers vs the extension layout (NEW, demonstrated)

Two artifacts authored against the sandbox/extension layout break
elsewhere:

- merged-prefix `build_deps` consumers get a `python3` wrapper resolving
  `usr/usr/bin/python3.real` (doubles the `usr/` component) — blocks
  cold builds of the meson family (§3.1);
- `perltidy`'s farm wrapper shebangs `#!/usr/bin/perl` — the sandbox
  path, nonexistent on the host. The pod installs `perl`; the wrapper
  must exec the store perl instead.

Both are the `#12` wrapper-aware family: fix the wrapper authoring and
the extension-tree layout (`usr/usr` doubling) together.

### 5.9 Host toolchain environment prerequisites (NEW, operational)

The pilot exposed environment traps the cutover session must respect:

- The project devbox env puts **busybox `tar`/`xz`** first on PATH;
  busybox tar cannot drive `.tar.xz` sources ("corrupted data / short
  read") — every `.tar.xz` pool package fails. GNU tar+xz must precede
  it (or fix the project devbox.json ordering).
- Recipes without `build_deps` rely on a compiler reaching the sandbox
  through the mirrored host PATH (today: devbox-global's gcc, via the
  `/nix` bind root). Post-retirement, that source disappears — recipes
  needing a compiler must declare the toolchain in `build_deps`
  explicitly (ADR-0018's explicit-beats-implicit rule) or builds move
  to the pool toolchain meta.
- Transient download flakes (ftp.gnu.org, github) abort a sync; re-run
  is incremental and resumes.

## 6. Pilot reproduction transcript

```bash
cd /home/rodrigo/Workspace/github.com/rbelem/issue-29-cutover
export CARGO_BUILD_JOBS=3
devbox run -- cargo build

# Env fixups (§5.9): GNU tar/xz must precede the project devbox profile's
# busybox variants; the sandboxed builds need a compiler on the mirrored
# PATH (today that is devbox-global's gcc via the /nix bind root).
mkdir -p /tmp/fixbin
ln -sf /run/current-system/sw/bin/xz  /tmp/fixbin/xz
ln -sf /run/current-system/sw/bin/tar /tmp/fixbin/tar
export PATH=/tmp/fixbin:$PWD/.devbox/nix/profile/default/bin:\
$HOME/.local/share/devbox/global/default/.devbox/nix/profile/default/bin:\
/run/current-system/sw/bin:/usr/bin:/bin

ROOT=$HOME/.cache/issue29-pilot/shuttle/pods
mkdir -p "$ROOT/pilot"
cat > "$ROOT/pilot/pod.lua" <<'EOF'
pod { packages = { "jq", "nerd-fonts-hack" } }
EOF
target/debug/shuttle pod --name pilot sync --root "$ROOT"
target/debug/shuttle pod --name pilot list --root "$ROOT"

eval "$(target/debug/shuttle pod --name pilot shellenv --root "$ROOT")"
which jq            # .../issue-29-pilot/shuttle/pods/pilot/current/jq
jq --version

# Font activation through the pilot surface (redirected XDG_DATA_HOME):
env XDG_DATA_HOME="$HOME/.cache/issue29-pilot" XDG_DATA_DIRS=/nonexistent \
  fc-match 'Hack Nerd Font'
# → HackNerdFont-Regular.ttf: "Hack Nerd Font" "Regular"  (from the pod)

# Dynamic-lib note (§5.7): git/tmux/htop need the generation's extension
# lib dirs on LD_LIBRARY_PATH until that seam lands.
```

