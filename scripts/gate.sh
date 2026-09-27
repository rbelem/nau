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
# 3. CPATH (the pod's include leak) is load-bearing for the Luau build
#    and devbox re-injects it anyway; it is deliberately left alone.
#
# Re-exec: the outer invocation enters `nix shell nixpkgs#gcc14`, where
# `command -v gcc` still resolves to the gcc14 wrapper (devbox has not
# run yet), and hands the absolute paths to the inner invocation, which
# exports them inside the devbox shell and runs the check steps.
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
        exec nix shell nixpkgs#gcc14 -c env \
        -u LD_LIBRARY_PATH -u COMPILER_PATH -u LIBRARY_PATH \
        devbox run -- bash "$0"
fi

export CC="${SHUTTLE_GATE_CC:?gate: outer invocation must resolve CC}"
export CXX="${SHUTTLE_GATE_CXX:?gate: outer invocation must resolve CXX}"
echo "gate: CC=$CC"
echo "gate: CXX=$CXX"
"$CC" --version | head -1

SHUTTLE_SYSTEMD=off cargo test
cargo clippy -- -D warnings
cargo fmt --check
echo "gate: ALL AXES GREEN"
