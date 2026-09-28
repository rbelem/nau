#!/usr/bin/env bash
# The formal gate: SHUTTLE_SYSTEMD=off cargo test, clippy -D warnings,
# fmt --check — with the compiler pinned to nixpkgs gcc14.
#
# Why this dance (all three learned the hard way, 2026-09-26):
#
# 1. The toolchain floats. `nixpkgs#gcc` moved from 14 to 15 mid-stream
#    once, and the Luau sources vendored by mlua-sys are sensitive to the
#    compiler/libstdc++ combination in ways the pod shellenv's CPATH leak
#    both masks and complicates. The gcc14 pin is the stable choice.
# 2. The pod puts a gcc shim on PATH, and `devbox run` re-resolves CC/CXX
#    through its own env AFTER a parent-env pin is applied — so the pin
#    must be exported inside the devbox shell, not before it.
# 3. CPATH: BEFORE the mlua 0.12 bump (PR #241), the pod shellenv's
#    CPATH leak was load-bearing — luau663's Compiler.cpp missed
#    `#include <limits>` and the pod's libstdc++ headers papered over
#    it. AFTER the bump, LUAU_CXXFLAGS=-include limits (.cargo/config.toml)
#    handles that explicitly, and the pod CPATH actively BREAKS the
#    vendored Luau under gcc14 (pod gcc-14.2-era headers shadow the
#    compiler's own; isolated repro: gcc14+CPATH 9 errors, gcc14 alone
#    green). So CPATH is stripped, same as the other pod leaks.
#
# Re-exec: the outer invocation enters `nix shell nixpkgs#gcc14`, where
# `command -v gcc` still resolves to the gcc14 wrapper (devbox has not
# run yet), and hands the absolute paths to the inner invocation, which
# exports them inside the devbox shell and runs the check steps.
#
# Gated-tool provisioning (#291): the same outer nix shell carries
# `gnupg` (the real-gpg sysupdate interop) and `cryptsetup`
# (veritysetup, the verify-image suite), so the gated tests RUN in the
# gate instead of skipping silently — the meta-cause that hid the
# trust-slice council's H1. The inner preflight turns any remaining
# tool absence into a loud failure (per-host opt-out:
# SHUTTLE_GATE_ALLOW_SKIP=1), and the loop-device axis (#288), which
# cannot fail-closed on unprivileged hosts, gets an up-front probe so
# its skip is VISIBLE in the gate log.
set -eu

if [[ "${SHUTTLE_GATE_OUTER:-1}" == "1" ]]; then
    CC14="$(nix shell nixpkgs#gcc14 -c bash -c 'command -v gcc' 2>/dev/null | tail -1)"
    CXX14="$(nix shell nixpkgs#gcc14 -c bash -c 'command -v g++' 2>/dev/null | tail -1)"
    case "$CC14$CXX14" in
        *gcc-wrapper-14.*|*gcc-14.*) ;;
        *)
            echo "gate: FAIL — could not resolve the gcc14 wrapper " \
                 "(got: $CC14 / $CXX14). Refusing to run the gate with " \
                 "the wrong compiler." >&2
            exit 2
            ;;
    esac
    SHUTTLE_GATE_OUTER=0 SHUTTLE_GATE_CC="$CC14" SHUTTLE_GATE_CXX="$CXX14" \
        exec nix shell nixpkgs#gcc14 nixpkgs#gnupg nixpkgs#cryptsetup -c env \
        -u LD_LIBRARY_PATH -u COMPILER_PATH -u LIBRARY_PATH -u CPATH \
        devbox run -- bash "$0"
fi

export CC="${SHUTTLE_GATE_CC:?gate: outer invocation must resolve CC}"
export CXX="${SHUTTLE_GATE_CXX:?gate: outer invocation must resolve CXX}"
echo "gate: CC=$CC"
echo "gate: CXX=$CXX"
"$CC" --version | head -1

# ── Gated-suite tool preflight (#291): a tool absent in the gate is a
# FAIL, not a silent skip. The gated tests check SHUTTLE_GATE=1 too, so
# a run that enters here without the outer provisioning still cannot
# skip quietly.
export SHUTTLE_GATE=1
missing=()
for tool in sfdisk veritysetup gpg; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if ((${#missing[@]})); then
    if [[ "${SHUTTLE_GATE_ALLOW_SKIP:-0}" == "1" ]]; then
        echo "gate: WARNING — ${missing[*]} unavailable; the gated suites " \
             "will SKIP, not run (SHUTTLE_GATE_ALLOW_SKIP=1). This gate run " \
             "does NOT prove the sign↔verify round-trip." >&2
    else
        echo "gate: FAIL — ${missing[*]} unavailable; refusing a gate that " \
             "silently skips its gated suites (#291). The outer invocation " \
             "provisions gpg+veritysetup via nix; on a host that cannot " \
             "carry them, set SHUTTLE_GATE_ALLOW_SKIP=1 to proceed with " \
             "visible skips." >&2
        exit 2
    fi
else
    echo "gate: gated-tool axis: sfdisk+veritysetup+gpg present — the gated suites WILL run"
fi

# ── Loop-device axis probe (#288/#291): attaching a loop device needs
# CAP_SYS_ADMIN, which unprivileged gate hosts permanently lack, so
# this axis may never fail-closed — but its skip must be VISIBLE. The
# probe runs here, where the verdict lands in the gate log instead of
# cargo's swallowed test output.
if command -v losetup >/dev/null 2>&1; then
    loop_probe="$(mktemp "${TMPDIR:-/tmp}/gate-loop-probe.XXXXXX")"
    dd if=/dev/zero of="$loop_probe" bs=1M count=4 status=none
    if loop_dev="$(losetup --find --show "$loop_probe" 2>/dev/null)"; then
        losetup -d "$loop_dev" >/dev/null 2>&1 || true
        echo "gate: loop-device axis: attachable — verify_image_verifies_a_real_block_device WILL run"
    else
        echo "gate: loop-device axis: NOT attachable (unprivileged host) — " \
             "verify_image_verifies_a_real_block_device will SKIP (expected, " \
             "visible by policy; the FILE-backed gates still run)"
    fi
    rm -f "$loop_probe"
else
    echo "gate: loop-device axis: losetup absent — verify_image_verifies_a_real_block_device will SKIP (visible by policy)"
fi

SHUTTLE_SYSTEMD=off cargo test
cargo clippy -- -D warnings
cargo fmt --check
echo "gate: ALL AXES GREEN"
