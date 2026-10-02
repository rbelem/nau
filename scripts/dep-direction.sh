#!/usr/bin/env bash
# Data-driven dependency-direction assertion (ADR-0051 R1, as amended by
# the ADR-0053 council rulings; consumed by scripts/gate.sh and CI).
#
# The crate walls are compiler-enforced, but the ALLOWED edges need an
# explicit policy while the workspace grows (issue #326 acceptance).
# This script encodes the policy as a per-crate allowed-set table and
# checks the RESOLVED graph (`cargo tree`, not the manifest's hopes):
#
#   strict axis  — `cargo tree -e normal,build`: every nau-* name in the
#                  graph must be self or in the crate's allowed row.
#   dev axis     — `cargo tree -e dev`: same, minus names already in the
#                  crate's normal+build closure (a dev-dependency on a
#                  crate you already depend on is not a new edge), minus
#                  the NAMED dev-edge table below.
#
# A workspace member with NO row in the table fails loudly: the policy
# must grow deliberately, never by omission.
#
# Table (ADR-0053 council amendments + issue #326 PR 3 rulings):
#   nau-core   {}                      — the spine depends on nothing
#   nau-infra  {nau-core}              — the mechanism leaf consumes the
#                                        spine (store/assert → SnapRef)
#   nau-chart  {nau-core, nau-infra}   — the eval domain
#   nau-build  {nau-core, nau-infra}   — the build domain; dev-edge:
#              nau-chart (§4 constructors + dsl prelude in tests;
#              expires at the final reconciliation, ADR-0053)
#   nau-image  {nau-core, nau-infra}   — the image domain; dev-edge:
#              nau-chart (§4 image_declaration_from_lua + INIT_LUA in
#              tests; expires at the final reconciliation, ADR-0053)
#   nau-ship   {nau-core, nau-infra}   — the ship domain (no dev-edge:
#              the moved tests are RuntimeStore-fixture tests that stay
#              root; nau-ship's own tests use core + infra only)
#   nau-peer   {nau-core, nau-infra}   — the peer domain (discovery/
#              serve/export; no dev-edge: the serve tests dropped the
#              ship sha256 for the core cache key, and export tests
#              build core literals)
#   nau-pod    {nau-core, nau-infra}   — the pod domain (farm/desktop/
#              fonts emit + confine + secrets resolve + the pod grammar's
#              pure halves; no dev-edge: the eval-coupled verb/test
#              suites stay root, the crate's own tests use core+infra
#              only)
#   nau-runtime {nau-core, nau-infra}  — the on-device runtime (store
#              mutation, install/remove/rollback/gc, activation, slot
#              recovery; no dev-edge: the store-fixture suites are
#              in-crate, the cosign/attest fixtures stay root)
#   nau-trust  {nau-core, nau-infra}   — the ceremony domain (key/CA
#              ceremony, manifest signing/verify, ledger policy; no
#              dev-edge: the schema down-move puts ImageManifest in
#              nau-core::manifest_ir, and the two eval-coupled fixture
#              clusters stay root)
#   nau (root) exempt                  — the root composes everything
set -euo pipefail

fail() {
    echo "dep-direction: FAIL — $1" >&2
    exit 1
}

# ── the policy table ──
# allowed_normal CRATE: echo the space-separated set of workspace crates
# allowed on the normal+build axis; exit non-zero when the crate has no
# row (loud-miss, never a silent pass).
allowed_normal() {
    case "$1" in
        nau-core)   echo "" ;;
        nau-infra)  echo "nau-core" ;;
        nau-chart)  echo "nau-core nau-infra" ;;
        nau-build)  echo "nau-core nau-infra" ;;
        nau-image)  echo "nau-core nau-infra" ;;
        nau-ship)   echo "nau-core nau-infra" ;;
        nau-peer)   echo "nau-core nau-infra" ;;
        nau-pod)    echo "nau-core nau-infra" ;;
        nau-runtime) echo "nau-core nau-infra" ;;
        nau-trust) echo "nau-core nau-infra" ;;
        *)          return 1 ;;
    esac
}

# dev_allowed CRATE: the NAMED dev-edge table — workspace crates allowed
# as dev-dependencies BEYOND the crate's normal+build closure.
dev_allowed() {
    case "$1" in
        # §4 sanctioned entry: the build tests drive the Lua constructors
        # (snap_meta_from_lua_table & friends) and the dsl prelude through
        # nau-chart (orphan rule pins them there). EXPIRES at the final
        # reconciliation PR (ADR-0053).
        nau-build)  echo "nau-chart" ;;
        # §4 sanctioned entry: the image tests drive
        # image_declaration_from_lua + dsl::INIT_LUA through nau-chart.
        # EXPIRES at the final reconciliation PR (ADR-0053).
        nau-image)  echo "nau-chart" ;;
        *) return 1 ;;
    esac
}

# ── the workspace members (cargo metadata: the resolved workspace, not
# a hand-maintained list) ──
members_json="$(cargo metadata --no-deps --format-version 1)" \
    || fail "cargo metadata failed — fix the invocation, never assert an unreadable graph"
members="$(printf '%s' "$members_json" \
    | grep -oE '"name":"[^"]+","version":"[^"]+"' \
    | sed -E 's/"name":"([^"]+)".*/\1/' | sort -u)"
[ -n "$members" ] || fail "cargo metadata yielded no workspace members"

nau_names_from_tree() { # $1 = crate, $2 = edge kinds
    local out
    out="$(cargo tree -p "$1" -e "$2" --prefix none)" \
        || fail "cargo tree -p $1 -e $2 failed — fix the invocation, never trust an empty graph"
    printf '%s\n' "$out" | sed -E 's/^ *//; s/ v.*//' | { grep -E '^nau-' || true; } | sort -u
}

violation_report=0
for crate in $members; do
    # The root `nau` package composes every crate by design: exempt.
    if [ "$crate" = "nau" ]; then
        echo "dep-direction: nau (root): exempt (composes all)"
        continue
    fi

    allowed="$(allowed_normal "$crate")" \
        || fail "no policy row for workspace member '$crate' — add it to the table deliberately (allowed_normal in $0)"

    # Strict axis: normal + build edges ⊆ {self} ∪ allowed row.
    strict="$(nau_names_from_tree "$crate" normal,build)"
    offenders=""
    for dep in $strict; do
        [ "$dep" = "$crate" ] && continue
        case " $allowed " in
            *" $dep "*) ;;
            *) offenders="$offenders $dep" ;;
        esac
    done
    if [ -n "$offenders" ]; then
        echo "dep-direction: FAIL — $crate -> {${offenders# }}: workspace deps must be within {${allowed:-}} (ADR-0051 R1)" >&2
        violation_report=1
    fi

    # Dev axis: dev edges ⊆ {self} ∪ normal+build closure ∪ named dev row.
    dev="$(nau_names_from_tree "$crate" dev)"
    dev_offenders=""
    for dep in $dev; do
        [ "$dep" = "$crate" ] && continue
        case " $strict " in
            *" $dep "*) continue ;;
        esac
        if dev_row="$(dev_allowed "$crate" 2>/dev/null)"; then
            case " $dev_row " in
                *" $dep "*) continue ;;
            esac
        fi
        dev_offenders="$dev_offenders $dep"
    done
    if [ -n "$dev_offenders" ]; then
        echo "dep-direction: FAIL — $crate -> {${dev_offenders# }} (dev axis): dev-only workspace edge outside the named dev-edge table (ADR-0053)" >&2
        violation_report=1
    fi

    if [ "$violation_report" -eq 0 ]; then
        echo "dep-direction: $crate: ok (normal+build within {${allowed:-}}; dev within normal closure + named table)"
    fi
done

[ "$violation_report" -eq 0 ] \
    || fail "dependency-direction violations above — the workspace grows only with a deliberate table row"
echo "dep-direction: all workspace members ok"
