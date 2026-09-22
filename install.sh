#!/usr/bin/env bash
# install.sh — user-home installer for shuttle (https://github.com/rbelem/shuttle)
#
# Installs into the user's home, no root-owned files:
#   ~/.local/bin/shuttle          the binary
#   ~/.local/bin/stl              symlink to shuttle (3-key alias)
#   ~/.local/share/shuttle/repo   managed source clone (builds + updates)
#   ~/.cargo, ~/.rustup           rust toolchain, bootstrapped only if cargo is missing
#
# System packages (squashfs-tools, bubblewrap) are installed via the distro
# package manager with sudo — skipped when already present, with --skip-deps,
# or on NixOS (the needed attrs are printed instead).
#
# Usage:
#   curl -fsSL <raw-url>/install.sh | bash          # latest main
#   ./install.sh --ref <tag-or-branch>              # pin a ref
#   ./install.sh --skip-deps --prefix ~/.local      # options
#
# Platform support: Linux first (any distro + NixOS + WSL2). macOS is not
# supported yet — shuttle's sandbox uses bubblewrap and mount namespaces.
set -euo pipefail

PREFIX="${SHUTTLE_PREFIX:-$HOME/.local}"
REF="${SHUTTLE_REF:-main}"
REPO_URL="${SHUTTLE_REPO_URL:-https://github.com/rbelem/shuttle.git}"
SKIP_DEPS=0
DRY_RUN=0

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --ref) REF="$2"; shift 2 ;;
        --prefix) PREFIX="$2"; shift 2 ;;
        --skip-deps) SKIP_DEPS=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) sed -n '2,17p' "${BASH_SOURCE[0]:-$0}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1 (see --help)" ;;
    esac
done

run() {
    if [ "$DRY_RUN" = 1 ]; then printf '  [dry-run] %s\n' "$*"; else "$@"; fi
}

# ── Platform gate ────────────────────────────────────────────────────────
OS="$(uname -s)"
case "$OS" in
    Linux) ;;
    Darwin)
        die "shuttle is Linux-only today: its build sandbox uses bubblewrap and
       mount namespaces, neither of which exists on macOS.
       Track macOS support at https://github.com/rbelem/shuttle/issues" ;;
    *) die "unsupported OS: $OS" ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|aarch64) ;;
    *) die "unsupported architecture: $ARCH (need x86_64 or aarch64)" ;;
esac

# WSL1 has no mount namespaces; WSL2 is a real VM and works.
if grep -qi microsoft /proc/sys/kernel/osrelease 2>/dev/null; then
    if grep -qi 'WSL2\|microsoft-standard' /proc/version 2>/dev/null; then
        log "WSL2 detected"
    else
        die "WSL1 detected: no mount namespaces, shuttle cannot run here.
       Upgrade to WSL2: https://learn.microsoft.com/windows/wsl/install"
    fi
fi

# ── System packages ──────────────────────────────────────────────────────
# Pod surface: mksquashfs/unsquashfs (store payloads), bwrap (build sandbox),
# curl (downloads), tar (sources). Build surface: a C++ compiler for the
# vendored Luau analyzer (image tools like ukify are NOT required).
NEED_PKGS=""
have() { command -v "$1" >/dev/null 2>&1; }
for tool in mksquashfs unsquashfs bwrap curl tar cc c++ ar; do
    have "$tool" || NEED_PKGS="$NEED_PKGS $tool"
done

pkg_for() {
    case "$1" in
        mksquashfs|unsquashfs) echo squashfs-tools ;;
        bwrap) echo bubblewrap ;;
        curl) echo curl ;;
        tar) echo tar ;;
        cc|c++) case "$2" in
            apk) echo gcc ;;
            dnf|zypper) echo gcc-c++ ;;
            *) echo g++ ;;
        esac ;;
        ar) case "$2" in
            apk|alpine) echo binutils ;;
            fedora|rhel|rocky|alma) echo binutils ;;
            *) echo binutils ;;
        esac ;;
    esac
}

if [ -n "$NEED_PKGS" ] && [ -e /etc/nixos ] && grep -q 'id=nixos' /etc/os-release 2>/dev/null; then
    warn "missing tools:$NEED_PKGS"
    warn "NixOS detected — add the equivalents to configuration.nix:"
    warn "  environment.systemPackages = with pkgs; [ squashfsTools bubblewrap curl gnu-tar gcc binutils ];"
    die "install the tools above and re-run this installer"
fi

if [ -n "$NEED_PKGS" ] && [ "$SKIP_DEPS" = 0 ]; then
    if [ -r /etc/os-release ]; then
        . /etc/os-release
        distro="${ID:-}"
    else
        distro=""
    fi
    pkgs=""
    for tool in $NEED_PKGS; do
        p="$(pkg_for "$tool" "$distro")"
        case " $pkgs " in *" $p "*) ;; *) pkgs="$pkgs $p" ;; esac
    done
    log "installing system packages:$pkgs (needs sudo)"
    SUDO=""
    [ "$(id -u)" = 0 ] || SUDO=sudo
    case "$distro" in
        ubuntu|debian|linuxmint|pop) run $SUDO apt-get update && run $SUDO apt-get install -y $pkgs ;;
        fedora|rhel|rocky|alma) run $SUDO dnf install -y $pkgs ;;
        arch|endeavouros|manjaro) run $SUDO pacman -S --needed --noconfirm $pkgs ;;
        opensuse*) run $SUDO zypper install -y $pkgs ;;
        alpine) run $SUDO apk add $pkgs ;;
        *) warn "unknown distro '$distro' — install these packages manually:$pkgs"
           die "then re-run with --skip-deps" ;;
    esac
elif [ -n "$NEED_PKGS" ]; then
    warn "missing tools:$NEED_PKGS (--skip-deps given, continuing)"
fi

# ── Rust toolchain (user home, only if cargo is absent) ──────────────────
if ! have cargo; then
    log "bootstrapping rustup (stable, minimal profile)"
    run curl --proto '=https' --tlsv1.2 -fsSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --profile minimal --no-modify-path
    export PATH="$HOME/.cargo/bin:$PATH"
fi
have cargo || die "cargo still not on PATH after rustup bootstrap"

# ── Source ───────────────────────────────────────────────────────────────
SHUTTLE_HOME="${XDG_DATA_HOME:-$HOME/.local/share}/shuttle"
SRC_DIR="${SHUTTLE_SRC:-$SHUTTLE_HOME/repo}"
if [ -n "${SHUTTLE_SRC:-}" ] && [ -d "$SHUTTLE_SRC" ]; then
    SRC_DIR="$SHUTTLE_SRC"
    log "using source at $SRC_DIR (SHUTTLE_SRC override)"
elif [ -d "$SRC_DIR/.git" ]; then
    log "updating managed clone at $SRC_DIR (ref $REF)"
    run git -C "$SRC_DIR" fetch --depth 1 origin "$REF"
    run git -C "$SRC_DIR" checkout --force FETCH_HEAD
else
    mkdir -p "$SHUTTLE_HOME"
    log "cloning $REPO_URL (ref $REF) into $SRC_DIR"
    run git clone --depth 1 --branch "$REF" "$REPO_URL" "$SRC_DIR" \
        || run git clone --depth 1 "$REPO_URL" "$SRC_DIR"
fi

# ── Build + install ──────────────────────────────────────────────────────
log "building (release) — a few minutes on first run"
run cargo build --release --manifest-path "$SRC_DIR/Cargo.toml"

BIN_DIR="$PREFIX/bin"
log "installing to $BIN_DIR/shuttle"
run mkdir -p "$BIN_DIR"
run install -m 755 "$SRC_DIR/target/release/shuttle" "$BIN_DIR/shuttle"
run ln -sfn shuttle "$BIN_DIR/stl"

# ── Verify ───────────────────────────────────────────────────────────────
if [ "$DRY_RUN" != 1 ]; then
    log "installed: $("$BIN_DIR/shuttle" --version)"
    # Pod-scope readiness (issue #97): doctor --pod gates exactly the pod
    # surface this installer provisions, so its verdict replaces the
    # duplicated bash tool loop. A missing-tool report still warns; a
    # nonzero exit never aborts the install.
    if "$BIN_DIR/shuttle" doctor --pod; then
        log "pod surface verified — ready for 'shuttle pod sync'"
    else
        warn "shuttle doctor --pod failed (report above) — 'shuttle pod sync' will fail until present"
    fi
fi

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) warn "$BIN_DIR is not on PATH. Add it to your shell rc:"
       printf '       export PATH="%s:$PATH"\n' "$BIN_DIR" ;;
esac

log "next steps:"
printf '    shuttle pod --name daily add <package> ...\n'
printf '    shuttle pod --name daily sync\n'
printf '    eval "$(shuttle pod shellenv --name daily)"   # put the farm on PATH\n'
printf '\nDocs: %s\n' "$SRC_DIR/README.md"
