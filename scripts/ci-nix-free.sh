#!/usr/bin/env bash
# ci-nix-free.sh — prototype nix-free CI bootstrap for the shuttle repo.
#
# Lane E1 deliverable (docs/agents/devbox-deprecation-plan.md §P2).
# NOT wired into CI. Four stages, each idempotent and independently
# runnable:
#
#   ./scripts/ci-nix-free.sh --stage install   # (a) apt tools + shuttle binary
#   ./scripts/ci-nix-free.sh --stage payload   # (b) gate pod ← export-tree pull
#   ./scripts/ci-nix-free.sh --stage gate      # (c) the four gate commands
#   ./scripts/ci-nix-free.sh --stage summary   # (d) machine-readable summary
#   ./scripts/ci-nix-free.sh                   # all of the above
#
# No nix, no devbox anywhere. Outbound network only (crates.io, rustup,
# apt, GH artifact); the pull in stage (b) is served from loopback.
set -euo pipefail

REPO="${SHUTTLE_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
POD="${SHUTTLE_GATE_POD:-gate}"
PORT="${SHUTTLE_EXPORT_PORT:-8091}"
ARTIFACT_DIR="${SHUTTLE_EXPORT_DIR:-$REPO/.ci-export}"
STATE_FILE="${SHUTTLE_GATE_STATE:-$REPO/.ci-gate-state.env}"
SHUTTLE="${SHUTTLE_BIN:-$HOME/.local/bin/shuttle}"

log()  { printf '[ci-nix-free] %s\n' "$*"; }
die()  { printf '[ci-nix-free] FATAL: %s\n' "$*" >&2; record "$STAGE" fail; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

STAGE="all"
while [ $# -gt 0 ]; do
    case "$1" in
        --stage)  STAGE="$2"; shift 2 ;;
        --pod)    POD="$2"; shift 2 ;;
        --port)   PORT="$2"; shift 2 ;;
        *) die "unknown arg: $1 (usage: --stage install|payload|gate|summary|all)" ;;
    esac
done

# ── (d) summary bookkeeping ──────────────────────────────────────────────
# One KEY=VALUE line per stage; `summary` prints it as JSON.
record() {  # record <stage> <pass|fail|skip>
    mkdir -p "$(dirname "$STATE_FILE")"
    grep -v "^stage_$1=" "$STATE_FILE" 2>/dev/null >"$STATE_FILE.tmp" || true
    mv "$STATE_FILE.tmp" "$STATE_FILE"
    printf 'stage_%s=%s\n' "$1" "$2" >>"$STATE_FILE"
}

# ═══════════════════════════ (a) install ════════════════════════════════
stage_install() {
    STAGE=install
    log "stage install: distro gate tools"
    # Gate-relevant externals the pool has no recipe for (plan §1a):
    # squashfs-tools (store payloads) + bubblewrap (sandbox). Everything
    # else the gate needs is preinstalled on GH runners
    # (cc/c++/ar, curl, tar, git, python3, readelf, unshare).
    # Idempotent: apt is a no-op when installed. Runners have passwordless
    # sudo; skip gracefully when neither sudo nor root is available.
    if have mksquashfs && have unsquashfs && have bwrap; then
        log "  mksquashfs/unsquashfs/bwrap present — apt skipped"
    elif [ "$(id -u)" = 0 ] || have sudo; then
        SUDO=""; [ "$(id -u)" != 0 ] && SUDO=sudo
        $SUDO apt-get update -qq
        $SUDO apt-get install -y -qq squashfs-tools bubblewrap
    else
        # NOT-VERIFIED: without root this host cannot get mksquashfs/bwrap.
        # The gate stays *green* here (tests skip via bwrap_gate()), but
        # stage_gate's skip-guard will flag the hollow run. Fail loudly
        # instead of silently degrading coverage.
        die "mksquashfs/unsquashfs/bwrap missing and no root to install them"
    fi

    log "stage install: shuttle binary"
    # install.sh: rustup-bootstraps cargo if absent, uses SHUTTLE_SRC to
    # build *this checkout* (no extra clone), --skip-deps continues past
    # missing system packages with a warning (verified: install.sh:136).
    # Idempotent: cargo build is incremental; install overwrites.
    if ! have cargo; then
        log "  bootstrapping rustup (stable, minimal)"
        curl --proto '=https' --tlsv1.2 -fsSf https://sh.rustup.rs \
            | sh -s -- -y --default-toolchain stable --profile minimal --no-modify-path
        export PATH="$HOME/.cargo/bin:$PATH"
    fi
    # NOT-VERIFIED: SHUTTLE_SRC + --skip-deps together on a bare runner —
    # check that the installer does not abort when bwrap/curl are already
    # present (it should not: NEED_PKGS is only filled from `have` probes).
    SHUTTLE_SRC="$REPO" "$REPO/install.sh" --skip-deps --prefix "$HOME/.local"

    log "  $($SHUTTLE --version)"
    # Pod-scope readiness (issue #97 doctor): warnings allowed, this is
    # informational only — a nonzero exit does not abort the bootstrap.
    $SHUTTLE doctor --pod || log "  WARNING: doctor --pod reported gaps (see above)"
    record install pass
}

# ═══════════════════════════ (b) payload ════════════════════════════════
stage_payload() {
    STAGE=payload
    log "stage payload: gate pod ← static export tree"

    # Mechanism (plan §4): a pod-bearing machine runs `shuttle export` and
    # uploads the tree as a GH Actions artifact; here we download it, serve
    # it on loopback, and pull through the farm's signed-manifest protocol.
    if [ ! -f "$ARTIFACT_DIR/index.json" ]; then
        # NOT-VERIFIED: artifact download. Pick ONE of:
        #   gh run download <run-id> --name shuttle-export -D "$ARTIFACT_DIR"
        #   (needs gh auth on the runner — GITHUB_TOKEN suffices), or the
        #   actions/artifact v4 REST API via curl. The publisher lane must
        #   also exist first: `shuttle export --out export-tree/` on a pod
        #   machine + actions/upload-artifact. Until that lane lands, this
        #   stage cannot run end-to-end on CI.
        die "no export tree at $ARTIFACT_DIR — download the GH artifact first (see NOT-VERIFIED above)"
    fi
    # NOT-VERIFIED: `shuttle export` flag spelling (--out vs -o / --dir) —
    # confirm against `shuttle export --help` when wiring the publisher.

    # Serve the tree on loopback (idempotent: kill a stale server first).
    if [ -f "$ARTIFACT_DIR/.server.pid" ] && kill -0 "$(cat "$ARTIFACT_DIR/.server.pid")" 2>/dev/null; then
        kill "$(cat "$ARTIFACT_DIR/.server.pid")" || true
    fi
    ( cd "$ARTIFACT_DIR" && python3 -m http.server "$PORT" --bind 127.0.0.1 \
        >/dev/null 2>&1 & echo $! >"$ARTIFACT_DIR/.server.pid" )
    sleep 1
    # Idempotent re-pull: pull verifies sha256 blobs fail-closed, so a
    # repeat pull of the same content is a cheap verified no-op.
    # NOT-VERIFIED: the per-package URL shape for static trees —
    # `shuttle pull http://127.0.0.1:$PORT/<pkg> --pod "$POD"` is the
    # documented form (src/cli.rs Pull doc: "http(s)://…/<pkg> from a
    # static export tree"), but confirm whether one call stages the whole
    # generation or each package needs its own pull (expect: rust, glibc,
    # libgcc — the rust recipe's `requires` chain). Also confirm the
    # --pod staging flag name on `shuttle pull --help`.
    for pkg in rust glibc libgcc; do
        log "  pull $pkg"
        $SHUTTLE pull "http://127.0.0.1:$PORT/$pkg" --pod "$POD"
    done

    # Reconcile the pod so pulled content becomes the active generation the
    # farm (`current/bin`) points at.
    # NOT-VERIFIED: whether pull-staged content flips `current` directly or
    # a `pod sync` is required to install the staged set (expect sync — the
    # export docstring describes pull as *staging into the pod store*).
    # A sync is harmless either way (reconcile is idempotent) but needs
    # mksquashfs on PATH — stage (a) guarantees that.
    $SHUTTLE pod sync --name "$POD"

    # Smoke: the gate program resolves farm-first.
    SHUTTLE_SYSTEMD=off $SHUTTLE run --pod "$POD" -- cargo --version \
        || die "cargo not resolvable through the pod farm"
    record payload pass
}

# ═══════════════════════════ (c) gate ═══════════════════════════════════
stage_gate() {
    STAGE=gate
    log "stage gate: SHUTTLE_SYSTEMD=off shuttle run -- cargo …"
    export SHUTTLE_SYSTEMD=off
    cd "$REPO"

    $SHUTTLE run --pod "$POD" -- cargo build  --locked
    # The test run's stdout is the skip-guard's evidence: pod tests skip
    # silently when mksquashfs/unsquashfs/curl/tar/bwrap are missing
    # (bwrap_gate() pattern) — green but hollow. Fail on that marker.
    TEST_LOG="$REPO/.ci-gate-test.log"
    $SHUTTLE run --pod "$POD" -- cargo test --locked 2>&1 | tee "$TEST_LOG"
    if grep -q "skipping: mksquashfs/unsquashfs/curl/tar/bwrap unavailable" "$TEST_LOG"; then
        die "skip-guard: pod tests ran with gate tools missing — coverage was hollow"
    fi
    $SHUTTLE run --pod "$POD" -- cargo clippy --locked -- -D warnings
    $SHUTTLE run --pod "$POD" -- cargo fmt --check
    record gate pass
}

# ═══════════════════════════ (d) summary ════════════════════════════════
stage_summary() {
    STAGE=summary
    # Machine-readable: one JSON object on stdout; unknown stages reported
    # as "notrun" so a truncated run is visible, not silent.
    printf '{'
    sep=""
    for s in install payload gate; do
        v="notrun"
        [ -f "$STATE_FILE" ] && v="$(grep "^stage_$s=" "$STATE_FILE" | cut -d= -f2 || true)"
        [ -z "$v" ] && v="notrun"
        printf '%s"%s":"%s"' "$sep" "$s" "$v"
        sep=", "
    done
    printf '}\n'
    record summary pass
}

case "$STAGE" in
    install) stage_install ;;
    payload) stage_payload ;;
    gate)    stage_gate ;;
    summary) stage_summary ;;
    all)     stage_install; stage_payload; stage_gate; stage_summary ;;
    *) die "unknown stage: $STAGE" ;;
esac
