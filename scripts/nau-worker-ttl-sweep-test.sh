#!/usr/bin/env bash
# Test suite for scripts/nau-worker-ttl-sweep against fake provider
# CLIs and a fake curl. No network, no real cloud account — the live
# verify is operator-side per the tickets.
#
# hcloud (#269, T1–T16):
#   - v2 match rules in order: TTL label (epoch) past due → destroy
#     track; label absent/garbage → marker copy decides; both unusable →
#     server-age floor (alert at 48h, destroy at 72h)
#   - any parseable FUTURE value (label or marker) is ALIVE
#   - a destroy NEVER waits on the marker: label-due servers are not
#     ssh'd at all
#   - parsing: epoch strings, garbage labels/markers, CRLF/whitespace
#     tolerance, first-line-wins, empty marker file, unreachable ssh
#   - volume assertion: non-empty or API-failed `volume list` BLOCKS the
#     delete, alert fires
#   - dry-run is the DEFAULT: zero `hcloud server delete` invocations;
#     --dry-run overrides NAU_SWEEP_ENFORCE=1
#   - --enforce / NAU_SWEEP_ENFORCE=1 destroy exactly the
#     destroy-track servers
#   - hcloud API failures (list / describe / volume / delete) → ALERT +
#     hook "$1" + nonzero exit; hook absent → still loud on stderr
#   - empty label set → clean exit 0; unknown flag → usage error (rc 2)
#
# Notifier fan-out (#296, T17–T19):
#   - every configured destination (kuma URLs ×2, ntfy topic, ALERT_CMD
#     hook) fires on each alert; per-destination failures are named and
#     never silence siblings (fan-out isolation)
#   - clean run (rc 0) sends a kuma status=up heartbeat; ntfy is NOT
#     pinged on a clean run
#
# Multi-provider axes (#287, T20–T26): aws/gcp/azure/scw enumerate by the
# exact contract tags the providers stamp at create, share the same v2
# rule engine and dry-run/enforce semantics, mirror each provider's
# destroy + residual warnings, isolate per-axis failures (one axis
# failing never blocks the others), and skip loudly when enabled but
# broken.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SWEEP=$SCRIPT_DIR/nau-worker-ttl-sweep

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

BIN=$TMP/bin
SSH_DIR=$TMP/ssh
SSH_LOG=$TMP/ssh.log
DCD=$TMP/describe   # per-server describe fixtures (NAME or NAME.fail)
VD=$TMP/volumes     # per-server volume-list fixtures (absent = empty)
HOOK_OUT=$TMP/hook.out
DELETE_LOG=$TMP/deletes.log
LIST=$TMP/servers.list
CURL_LOG=$TMP/curl.log
# aws fixtures
AWS_LIST=$TMP/aws-list.json
AWS_VOLUME_DIR=$TMP/aws-volumes
AWS_TERMINATE_LOG=$TMP/aws-terminate.log
AWS_CALLS_LOG=$TMP/aws-calls.log
# gcp fixtures
GCLOUD_LIST=$TMP/gcp-list.json
GCLOUD_DESCRIBE_DIR=$TMP/gcp-describe
GCLOUD_DELETE_LOG=$TMP/gcp-delete.log
# azure fixtures
AZ_VM_LIST=$TMP/az-vms.json
AZ_DISK_DIR=$TMP/az-disks
AZ_NIC_DIR=$TMP/az-nics
AZ_PIP_DIR=$TMP/az-pips
AZ_DELETE_LOG=$TMP/az-delete.log
# scw fixtures
SCW_LIST=$TMP/scw-list.json
SCW_GET_DIR=$TMP/scw-get
SCW_DELETE_LOG=$TMP/scw-delete.log
# Shell command string matching the NAU_SWEEP_ALERT_CMD contract:
# evaluated with the alert summary as "$1".
HOOK_CMD="printf '%s\n' \"\$1\" >>$HOOK_OUT"

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }

assert_eq() { # desc want got
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want: [$2] got: [$3])"; fi
}
assert_contains() { # desc needle haystack
    if grep -qF -- "$2" <<<"$3"; then ok "$1"; else bad "$1 (missing: [$2])"; fi
}
assert_not_contains() { # desc needle haystack
    if grep -qF -- "$2" <<<"$3"; then bad "$1 (unexpected: [$2])"; else ok "$1"; fi
}

mkdir -p "$BIN" "$SSH_DIR" "$DCD" "$VD" \
    "$AWS_VOLUME_DIR" "$GCLOUD_DESCRIBE_DIR" \
    "$AZ_DISK_DIR" "$AZ_NIC_DIR" "$AZ_PIP_DIR" "$SCW_GET_DIR"

# --- fake hcloud -----------------------------------------------------------
cat >"$BIN/hcloud" <<'EOF'
#!/bin/sh
case "$1 $2" in
"server list")
    # The real hcloud names this flag --selector (-l). Refuse the wrong
    # spelling so the suite cannot pass while the sweep breaks live
    # (2026-10-03: the sweep shipped --label-selector; hcloud 1.68 has
    # no such flag and every real run failed the server-list API).
    case "$3" in
    --selector) ;;
    *) echo "hcloud (fake): server list expects --selector, got: $3" >&2; exit 1 ;;
    esac
    case "$*" in
    *noheader*) ;;
    *) echo "hcloud (fake): server list expects -o noheader (the NAME header row parses as a server)" >&2; exit 1 ;;
    esac
    if [ "${HCLOUD_LIST_FAIL:-0}" = "1" ]; then
        echo "hcloud: api failure (fake)" >&2
        exit 1
    fi
    cat "${HCLOUD_LIST:?}"
    ;;
"server describe")
    if [ -f "${HCLOUD_DESCRIBE_DIR:?}/$3.fail" ]; then
        echo "hcloud: server not found (fake)" >&2
        exit 1
    fi
    cat "${HCLOUD_DESCRIBE_DIR:?}/$3"
    ;;
"volume list")
    if [ "${HCLOUD_VOLUME_FAIL_NAME:-}" = "$4" ]; then
        echo "hcloud: api failure (fake)" >&2
        exit 1
    fi
    f="${HCLOUD_VOLUME_DIR:?}/$4"
    if [ -f "$f" ]; then
        cat "$f"
    fi
    exit 0
    ;;
"server delete")
    if [ "${HCLOUD_DELETE_FAIL:-0}" = "1" ]; then
        echo "hcloud: server delete failed (fake)" >&2
        exit 1
    fi
    printf '%s\n' "$3" >>"${HCLOUD_DELETE_LOG:?}"
    ;;
*)
    echo "fake hcloud: unexpected invocation: $*" >&2
    exit 64
    ;;
esac
EOF
chmod +x "$BIN/hcloud"

# --- fake ssh --------------------------------------------------------------
# Fixture map: $SSH_FIXTURE_DIR/<host>.ttl holds the marker text. No file →
# ssh-level failure (rc 255). Present-but-empty file → marker file missing
# in the guest (ssh rc 0, empty output). Every connection logs the host.
cat >"$BIN/ssh" <<'EOF'
#!/bin/sh
host=""
for a in "$@"; do
    case "$a" in *@*) host=${a#*@} ;; esac
done
if [ -z "$host" ]; then
    echo "fake ssh: no user@host in args: $*" >&2
    exit 255
fi
printf '%s\n' "$host" >>"${SSH_LOG:?}"
f="$SSH_FIXTURE_DIR/$host.ttl"
if [ ! -f "$f" ]; then
    echo "fake ssh: connection refused for $host (fake)" >&2
    exit 255
fi
exec cat "$f"
EOF
chmod +x "$BIN/ssh"

# --- fake aws (the sweep's --query output shape: [id, ip, launch, ttl]) ----
cat >"$BIN/aws" <<'EOF'
#!/bin/sh
case "$1 $2" in
"ec2 describe-instances")
    if [ "${AWS_LIST_FAIL:-0}" = "1" ]; then
        echo "aws: api failure (fake)" >&2
        exit 1
    fi
    cat "${AWS_LIST:?}"
    ;;
"ec2 describe-volumes")
    id=$(printf '%s\n' "$*" | sed -n 's/.*,Values=\([^ ]*\).*/\1/p')
    if [ "${AWS_VOLUME_FAIL_ID:-}" = "$id" ]; then
        echo "aws: api failure (fake)" >&2
        exit 1
    fi
    f="${AWS_VOLUME_DIR:?}/$id"
    if [ -f "$f" ]; then cat "$f"; else echo "[]"; fi
    ;;
"ec2 terminate-instances")
    if [ "${AWS_TERMINATE_FAIL:-0}" = "1" ]; then
        echo "aws: terminate failed (fake)" >&2
        exit 1
    fi
    id=$(printf '%s\n' "$*" | sed -n 's/.*--instance-ids \([^ ]*\).*/\1/p')
    printf '%s\n' "$id" >>"${AWS_TERMINATE_LOG:?}"
    ;;
*)
    echo "fake aws: unexpected invocation: $*" >&2
    exit 64
    ;;
esac
EOF
chmod +x "$BIN/aws"

# --- fake gcloud ------------------------------------------------------------
cat >"$BIN/gcloud" <<'EOF'
#!/bin/sh
case "$1 $2 $3" in
"compute instances list")
    if [ "${GCLOUD_LIST_FAIL:-0}" = "1" ]; then
        echo "gcloud: api failure (fake)" >&2
        exit 1
    fi
    cat "${GCLOUD_LIST:?}"
    ;;
"compute instances describe")
    f="${GCLOUD_DESCRIBE_DIR:?}/$4"
    if [ -f "$f.fail" ]; then
        echo "gcloud: describe failed (fake)" >&2
        exit 1
    fi
    cat "$f"
    ;;
"compute instances delete")
    if [ "${GCLOUD_DELETE_FAIL:-0}" = "1" ]; then
        echo "gcloud: delete failed (fake)" >&2
        exit 1
    fi
    printf '%s %s\n' "$4" "$6" >>"${GCLOUD_DELETE_LOG:?}"
    ;;
*)
    echo "fake gcloud: unexpected invocation: $*" >&2
    exit 64
    ;;
esac
EOF
chmod +x "$BIN/gcloud"

# --- fake az -----------------------------------------------------------------
cat >"$BIN/az" <<'EOF'
#!/bin/sh
rg=$(printf '%s\n' "$*" | sed -n 's/.*--resource-group \([^ ]*\).*/\1/p')
case "$1 $2" in
"vm list")
    if [ "${AZ_VM_LIST_FAIL:-0}" = "1" ]; then
        echo "az: api failure (fake)" >&2
        exit 1
    fi
    cat "${AZ_VM_LIST:?}"
    ;;
"disk list")
    f="${AZ_DISK_DIR:?}/$rg"
    if [ "${AZ_DISK_FAIL_RG:-}" = "$rg" ]; then
        echo "az: api failure (fake)" >&2
        exit 1
    fi
    if [ -f "$f" ]; then cat "$f"; else echo "[]"; fi
    ;;
"vm delete")
    if [ "${AZ_DELETE_FAIL:-0}" = "1" ]; then
        echo "az: vm delete failed (fake)" >&2
        exit 1
    fi
    printf '%s %s\n' "$6" "$4" >>"${AZ_DELETE_LOG:?}"
    ;;
"network nic")
    f="${AZ_NIC_DIR:?}/$rg"
    if [ -f "$f" ]; then cat "$f"; else echo "[]"; fi
    ;;
"network public-ip")
    f="${AZ_PIP_DIR:?}/$rg"
    if [ -f "$f" ]; then cat "$f"; else echo "[]"; fi
    ;;
*)
    echo "fake az: unexpected invocation: $*" >&2
    exit 64
    ;;
esac
EOF
chmod +x "$BIN/az"

# --- fake scw ---------------------------------------------------------------
cat >"$BIN/scw" <<'EOF'
#!/bin/sh
case "$1 $2 $3" in
"instance server list")
    if [ "${SCW_LIST_FAIL:-0}" = "1" ]; then
        echo "scw: api failure (fake)" >&2
        exit 1
    fi
    cat "${SCW_LIST:?}"
    ;;
"instance server get")
    f="${SCW_GET_DIR:?}/$4"
    if [ "${SCW_GET_FAIL_ID:-}" = "$4" ]; then
        echo "scw: api failure (fake)" >&2
        exit 1
    fi
    if [ -f "$f" ]; then cat "$f"; else echo "{}"; fi
    ;;
"instance server delete")
    if [ "${SCW_DELETE_FAIL:-0}" = "1" ]; then
        echo "scw: delete failed (fake)" >&2
        exit 1
    fi
    printf '%s\n' "$4" >>"${SCW_DELETE_LOG:?}"
    ;;
*)
    echo "fake scw: unexpected invocation: $*" >&2
    exit 64
    ;;
esac
EOF
chmod +x "$BIN/scw"

# --- fake curl (kuma -G --data-urlencode / ntfy -d POST) --------------------
cat >"$BIN/curl" <<'EOF'
#!/bin/sh
url=
q=
body=
while [ $# -gt 0 ]; do
    case "$1" in
        --data-urlencode) shift; q="$q$1&" ;;
        -d) shift; body="$1" ;;
        -H | -o | -m) shift ;;
        -G | -sS | -s | -S) ;;
        *) url="$1" ;;
    esac
    shift
done
printf 'curl %s\tq=%s\tbody=%s\n' "$url" "${q%&}" "$body" >>"${CURL_LOG:?}"
case "$url" in
    *"$(printf '%s' "${CURL_FAIL_URL:-__nomatch__}")"*)
        echo "curl: connection refused (fake)" >&2
        exit 7
        ;;
esac
EOF
chmod +x "$BIN/curl"

# --- fixtures / runner -----------------------------------------------------

NOW=$(date -u +%s)
H=3600

# write_describe NAME CREATED_EPOCH IP TTL_VALUE — the `server describe
# -o format=...` line: "created ip ttl".
write_describe() {
    printf '%s %s %s\n' "$2" "$3" "${4:-}" >"$DCD/$1"
}
write_marker() { # IP TEXT
    printf '%s' "$2" >"$SSH_DIR/$1.ttl"
}
rm_marker() {
    rm -f "$SSH_DIR/$1.ttl"
}

# Default farm: one server per v2 rule outcome.
#   w-label-due     rule 1: TTL label past due → destroy track
#   w-label-alive   rule 1: TTL label future → alive
#   w-floor-73      rule 3: no label/marker, 73h → destroy track
#   w-floor-50      rule 3: no label/marker, 50h → floor alert, no destroy
#   w-floor-10      rule 3: no label/marker, 10h → alive (young)
#   w-nolabel-due   rule 2: garbage label, marker copy past due → destroy
#   w-nolabel-alive rule 2: no label, marker copy future → alive
#   w-badlabel-young rule 2→3: garbage label + garbage marker, young → alive
write_default_fixtures() {
    cat >"$LIST" <<'EOF'
w-label-due
w-label-alive
w-floor-73
w-floor-50
w-floor-10
w-nolabel-due
w-nolabel-alive
w-badlabel-young
EOF
    write_describe w-label-due "$((NOW - 1 * H))" 10.0.0.1 "$((NOW - 2 * H))"
    write_describe w-label-alive "$((NOW - 1 * H))" 10.0.0.2 "$((NOW + 24 * H))"
    write_describe w-floor-73 "$((NOW - 73 * H))" 10.0.0.3
    write_describe w-floor-50 "$((NOW - 50 * H))" 10.0.0.4
    write_describe w-floor-10 "$((NOW - 10 * H))" 10.0.0.5
    write_describe w-nolabel-due "$((NOW - 2 * H))" 10.0.0.6 garbage
    write_describe w-nolabel-alive "$((NOW - 2 * H))" 10.0.0.7
    write_describe w-badlabel-young "$((NOW - 3 * H))" 10.0.0.8 garbage
    rm_marker 10.0.0.1; rm_marker 10.0.0.2; rm_marker 10.0.0.3
    rm_marker 10.0.0.4; rm_marker 10.0.0.5
    write_marker 10.0.0.6 "$((NOW - 1 * H))"$'\n'
    write_marker 10.0.0.7 "$((NOW + 24 * H))"$'\n'
    write_marker 10.0.0.8 'not-a-timestamp'$'\n'
}

# run_sweep [extra sweep args...] — captures stderr in $TMP/err.log, rc in RC.
run_sweep() {
    NAU_SWEEP_SSH="$BIN/ssh" \
        NAU_SWEEP_HCLOUD="$BIN/hcloud" \
        NAU_SWEEP_SSH_OPTS="-o BatchMode=yes" \
        SSH_FIXTURE_DIR="$SSH_DIR" \
        SSH_LOG="$SSH_LOG" \
        HCLOUD_LIST="$LIST" \
        HCLOUD_DESCRIBE_DIR="$DCD" \
        HCLOUD_VOLUME_DIR="$VD" \
        HCLOUD_DELETE_LOG="$DELETE_LOG" \
        "$SWEEP" "$@" >"$TMP/out.log" 2>"$TMP/err.log"
}

printf 'suite: fake hcloud + fake ssh fixtures in %s\n' "$TMP"

# --- T1: dry-run is the default --------------------------------------------
write_default_fixtures
: >"$DELETE_LOG"; : >"$SSH_LOG"
RC=0
run_sweep || RC=$?
ERR=$(cat "$TMP/err.log")
assert_eq "T1 dry-run default: nonzero exit (floor alert)" "1" "$RC"
assert_eq "T1 dry-run default: zero deletes" "" "$(cat "$DELETE_LOG")"
assert_contains "T1 would-destroy: label past due" "WOULD-DESTROY: w-label-due (TTL label past due)" "$ERR"
assert_contains "T1 would-destroy: 73h floor" "WOULD-DESTROY: w-floor-73 (no usable TTL, age 73h past the 72h floor)" "$ERR"
assert_contains "T1 would-destroy: marker copy past due" "WOULD-DESTROY: w-nolabel-due (no TTL label; marker copy past due)" "$ERR"
assert_contains "T1 alive: label future" "ALIVE: w-label-alive (TTL label in the future)" "$ERR"
assert_contains "T1 alive: young floor" "ALIVE: w-floor-10 (no usable TTL; age 10h below the 48h floor)" "$ERR"
assert_contains "T1 alive: marker copy future" "ALIVE: w-nolabel-alive (no TTL label; marker copy in the future)" "$ERR"
assert_contains "T1 floor alert: 50h" "ALERT: w-floor-50: no usable TTL, age 50h past the 48h alert floor (destroy at 72h)" "$ERR"
assert_contains "T1 label-invalid logged" "LABEL-INVALID: w-nolabel-due" "$ERR"
assert_contains "T1 summary counts" "sweep summary: 8 labeled, 4 alive, 3 destroy-track, 0 destroyed, 0 volume-blocked, 1 floor-alerted, 0 api-failed (mode: dry-run)" "$ERR"
assert_not_contains "T1 no hook fired (none set)" "alert hook" "$ERR"

# --- T2: --enforce destroys exactly the destroy-track servers ---------------
write_default_fixtures
: >"$DELETE_LOG"; : >"$SSH_LOG"
RC=0
run_sweep --enforce || RC=$?
ERR=$(cat "$TMP/err.log")
assert_eq "T2 enforce: nonzero exit (50h floor alert stands)" "1" "$RC"
assert_eq "T2 enforce: exactly the three destroy-track servers" "w-label-due
w-floor-73
w-nolabel-due" "$(cat "$DELETE_LOG")"
assert_contains "T2 destroyed: label past due" "DESTROYED: w-label-due (TTL label past due)" "$ERR"
assert_contains "T2 destroyed: 73h floor" "DESTROYED: w-floor-73" "$ERR"
assert_not_contains "T2 alive server untouched" "DESTROYED: w-label-alive" "$ERR"
assert_not_contains "T2 floor-alerted (50h) NOT destroyed" "DESTROYED: w-floor-50" "$ERR"
assert_not_contains "T2 label-due server never ssh'd" "10.0.0.1" "$(cat "$SSH_LOG")"
assert_contains "T2 no-label server ssh'd for marker" "10.0.0.6" "$(cat "$SSH_LOG")"

# --- T3: NAU_SWEEP_ENFORCE=1 env equals the flag ------------------------
write_default_fixtures
: >"$DELETE_LOG"
RC=0
export NAU_SWEEP_ENFORCE=1
run_sweep || RC=$?
unset NAU_SWEEP_ENFORCE
assert_eq "T3 env enforce: rc" "1" "$RC"
assert_eq "T3 env enforce: deleted set" "w-label-due
w-floor-73
w-nolabel-due" "$(cat "$DELETE_LOG")"

# --- T4: --dry-run overrides the env (flag wins, order is documented) -------
write_default_fixtures
: >"$DELETE_LOG"
RC=0
export NAU_SWEEP_ENFORCE=1
run_sweep --dry-run || RC=$?
unset NAU_SWEEP_ENFORCE
assert_eq "T4 flag beats env: zero deletes" "" "$(cat "$DELETE_LOG")"
assert_contains "T4 flag beats env: mode dry-run" "(mode: dry-run)" "$(cat "$TMP/err.log")"

# --- T5: label epoch boundary — expiry == call-time now → past due ----------
printf 'w-edge\n' >"$LIST"
write_describe w-edge "$NOW" 10.9.0.1 "$NOW"
RC=0
run_sweep || RC=$?
assert_contains "T5 label expiry == now → past due" "WOULD-DESTROY: w-edge (TTL label past due)" "$(cat "$TMP/err.log")"

# --- T6: label/marker garbage never widens into a delete --------------------
# 6a: negative-epoch garbage label, no marker, young → floor (alive).
printf 'w-a\n' >"$LIST"
write_describe w-a "$((NOW - 5 * H))" 10.9.0.1 -5
RC=0
run_sweep || RC=$?
assert_contains "T6a garbage label young → alive via floor" "ALIVE: w-a (no usable TTL; age 5h below the 48h floor)" "$(cat "$TMP/err.log")"
assert_eq "T6a rc (alive only)" "0" "$RC"

# 6b: marker CRLF/whitespace tolerated; first line wins.
write_describe w-a "$((NOW - 5 * H))" 10.9.0.1
write_marker 10.9.0.1 $'\r\n   \t'"$((NOW - 2 * H))"$'  \r\nsecond line junk\n'
run_sweep
assert_contains "T6b CRLF/whitespace marker parsed" "WOULD-DESTROY: w-a (no TTL label; marker copy past due)" "$(cat "$TMP/err.log")"

# 6c: garbage FIRST line wins (strict shape) → falls to the age floor.
write_describe w-a "$((NOW - 73 * H))" 10.9.0.1
write_marker 10.9.0.1 $'junk first line\n'"$((NOW - 2 * H))"$'\n'
RC=0
run_sweep || RC=$?
assert_contains "T6c garbage first line → floor not marker" "WOULD-DESTROY: w-a (no usable TTL, age 73h past the 72h floor)" "$(cat "$TMP/err.log")"
assert_not_contains "T6c garbage first line never deletes on line 2" "marker copy past due" "$(cat "$TMP/err.log")"

# 6d: empty marker file (present, 0 bytes) → floor path.
: >"$SSH_DIR/10.9.0.1.ttl"
write_describe w-a "$((NOW - 73 * H))" 10.9.0.1
run_sweep
assert_contains "T6d empty marker file → 73h floor destroys" "WOULD-DESTROY: w-a (no usable TTL, age 73h past the 72h floor)" "$(cat "$TMP/err.log")"

# 6e: ssh unreachable → floor path.
rm_marker 10.9.0.1
run_sweep
assert_contains "T6e ssh unreachable → floor path" "WOULD-DESTROY: w-a (no usable TTL, age 73h past the 72h floor)" "$(cat "$TMP/err.log")"

# --- T7: age-floor boundaries ----------------------------------------------
printf 'w-72h\nw-48h\nw-71h\n' >"$LIST"
write_describe w-72h "$((NOW - 72 * H))" 10.7.0.1
write_describe w-48h "$((NOW - 48 * H))" 10.7.0.2
write_describe w-71h "$((NOW - 71 * H))" 10.7.0.3
RC=0
run_sweep || RC=$?
ERR=$(cat "$TMP/err.log")
assert_contains "T7 exactly 72h → destroy track" "WOULD-DESTROY: w-72h (no usable TTL, age 72h past the 72h floor)" "$ERR"
assert_contains "T7 exactly 48h → floor alert, no destroy" "ALERT: w-48h: no usable TTL, age 48h past the 48h alert floor (destroy at 72h)" "$ERR"
assert_contains "T7 71h → floor alert" "ALERT: w-71h: no usable TTL, age 71h past the 48h alert floor" "$ERR"
assert_not_contains "T7 48h never destroy-track" "WOULD-DESTROY: w-48h" "$ERR"
assert_contains "T7 summary: 1 due 2 floor" "3 labeled, 0 alive, 1 destroy-track, 0 destroyed, 0 volume-blocked, 2 floor-alerted, 0 api-failed (mode: dry-run)" "$ERR"

# --- T8: volume assertion blocks the delete ---------------------------------
printf 'w-vol\n' >"$LIST"
write_describe w-vol "$((NOW - 1 * H))" 10.8.0.1 "$((NOW - 2 * H))"
printf '12345\n' >"$VD/w-vol"
: >"$DELETE_LOG"; : >"$HOOK_OUT"
export NAU_SWEEP_ALERT_CMD="$HOOK_CMD"
RC=0
run_sweep --enforce || RC=$?
unset NAU_SWEEP_ALERT_CMD
ERR=$(cat "$TMP/err.log")
assert_eq "T8 volumes present: rc" "1" "$RC"
assert_eq "T8 volumes present: NO delete" "" "$(cat "$DELETE_LOG")"
assert_contains "T8 volumes present: alert" "ALERT: w-vol: volume(s) still attached, destroy BLOCKED — detach/delete them first: 12345" "$ERR"
assert_not_contains "T8 volumes present: no DESTROYED" "DESTROYED: w-vol" "$ERR"
assert_contains "T8 volumes present: hook rollup" "1 volume-blocked destroy(s): w-vol — nothing deleted" "$(cat "$HOOK_OUT")"

# --- T9: volume-list API failure blocks too ---------------------------------
: >"$DELETE_LOG"; : >"$HOOK_OUT"
export NAU_SWEEP_ALERT_CMD="$HOOK_CMD" HCLOUD_VOLUME_FAIL_NAME=w-vol
RC=0
run_sweep --enforce || RC=$?
unset NAU_SWEEP_ALERT_CMD HCLOUD_VOLUME_FAIL_NAME
ERR=$(cat "$TMP/err.log")
assert_eq "T9 volume-list fail: rc" "1" "$RC"
assert_eq "T9 volume-list fail: NO delete" "" "$(cat "$DELETE_LOG")"
assert_contains "T9 volume-list fail: alert" "ALERT: hcloud volume list failed for w-vol — destroy BLOCKED (fail loud)" "$ERR"
assert_contains "T9 volume-list fail: hook rollup" "1 sweep API failure(s): w-vol(volume-list)" "$(cat "$HOOK_OUT")"

# --- T10: delete API failure → alert + hook + loud --------------------------
printf 'w-due\n' >"$LIST"
write_describe w-due "$((NOW - 1 * H))" 10.8.0.2 "$((NOW - 2 * H))"
: >"$DELETE_LOG"; : >"$HOOK_OUT"
export NAU_SWEEP_ALERT_CMD="$HOOK_CMD" HCLOUD_DELETE_FAIL=1
RC=0
run_sweep --enforce || RC=$?
unset NAU_SWEEP_ALERT_CMD HCLOUD_DELETE_FAIL
ERR=$(cat "$TMP/err.log")
assert_eq "T10 delete fail: rc" "1" "$RC"
assert_not_contains "T10 delete fail: no false DESTROYED" "DESTROYED: w-due" "$ERR"
assert_contains "T10 delete fail: alert" "ALERT: hcloud server delete failed for w-due" "$ERR"
assert_contains "T10 delete fail: hook rollup" "1 sweep API failure(s): w-due(delete)" "$(cat "$HOOK_OUT")"

# --- T11: list API failure → no server evaluated ----------------------------
write_default_fixtures
: >"$DELETE_LOG"; : >"$HOOK_OUT"
export NAU_SWEEP_ALERT_CMD="$HOOK_CMD" HCLOUD_LIST_FAIL=1
RC=0
run_sweep || RC=$?
unset NAU_SWEEP_ALERT_CMD HCLOUD_LIST_FAIL
assert_eq "T11 list fail: rc" "1" "$RC"
assert_eq "T11 list fail: no deletes" "" "$(cat "$DELETE_LOG")"
assert_contains "T11 list fail: alert" "ALERT: hcloud server list failed — sweep skipped, NO server evaluated" "$(cat "$TMP/err.log")"
assert_contains "T11 list fail: hook fired" "hcloud server list failed" "$(cat "$HOOK_OUT")"

# --- T12: describe API failure for one server → sweep continues -------------
printf 'w-broken\nw-fine\n' >"$LIST"
write_describe w-fine "$((NOW - 1 * H))" 10.8.0.3 "$((NOW + 24 * H))"
touch "$DCD/w-broken.fail"
RC=0
run_sweep || RC=$?
ERR=$(cat "$TMP/err.log")
assert_eq "T12 describe fail: rc" "1" "$RC"
assert_contains "T12 describe fail: alert" "ALERT: hcloud server describe failed for w-broken" "$ERR"
assert_contains "T12 describe fail: sibling still swept" "ALIVE: w-fine (TTL label in the future)" "$ERR"
assert_contains "T12 describe fail: summary" "2 labeled, 1 alive, 0 destroy-track, 0 destroyed, 0 volume-blocked, 0 floor-alerted, 1 api-failed" "$ERR"

# --- T13: empty label set → clean exit --------------------------------------
: >"$LIST"
RC=0
run_sweep || RC=$?
assert_eq "T13 empty label set: rc" "0" "$RC"
assert_contains "T13 empty label set: message" "no servers labeled nau-worker — nothing to sweep" "$(cat "$TMP/err.log")"

# --- T14: unknown flag → usage error ----------------------------------------
write_default_fixtures
RC=0
run_sweep --destroy-everything || RC=$?
assert_eq "T14 unknown flag: rc 2" "2" "$RC"
assert_contains "T14 unknown flag: usage" "usage error: unknown argument: --destroy-everything" "$(cat "$TMP/err.log")"

# --- T15: hook failure does not mask the alert ------------------------------
write_default_fixtures
export NAU_SWEEP_ALERT_CMD="exit 3"
RC=0
run_sweep || RC=$?
unset NAU_SWEEP_ALERT_CMD
assert_eq "T15 hook failure: rc still 1" "1" "$RC"
assert_contains "T15 hook failure: reported" "ALERT: alert hook (NAU_SWEEP_ALERT_CMD) exited nonzero" "$(cat "$TMP/err.log")"

# --- T16: hook absent → still loud; hook receives the alert message ---------
write_default_fixtures
: >"$HOOK_OUT"
RC=0
run_sweep || RC=$?
assert_contains "T16 no hook: alert still loud on stderr" "ALERT: w-floor-50: no usable TTL, age 50h past the 48h alert floor" "$(cat "$TMP/err.log")"
export NAU_SWEEP_ALERT_CMD="$HOOK_CMD"
RC=0
run_sweep || RC=$?
unset NAU_SWEEP_ALERT_CMD
assert_contains "T16 hook receives floor alert as \$1" "w-floor-50: no usable TTL, age 50h past the 48h alert floor (destroy at 72h)" "$(cat "$HOOK_OUT")"

# ── #296 notifier fan-out + #287 axes --------------------------------------
# iso EPOCH → the LaunchTime/creationTimestamp shape the CLIs print.
iso() { date -u -d "@$1" +"%Y-%m-%dT%H:%M:%S+00:00"; }

# run_sweep_extra [sweep args...] — run_sweep plus the EXTRA_ENV array
# (KEY=VALUE pairs) for axis/notifier fixtures.
EXTRA_ENV=()
run_sweep_extra() {
    NAU_SWEEP_SSH="$BIN/ssh" \
        NAU_SWEEP_HCLOUD="$BIN/hcloud" \
        NAU_SWEEP_SSH_OPTS="-o BatchMode=yes" \
        SSH_FIXTURE_DIR="$SSH_DIR" \
        SSH_LOG="$SSH_LOG" \
        HCLOUD_LIST="$LIST" \
        HCLOUD_DESCRIBE_DIR="$DCD" \
        HCLOUD_VOLUME_DIR="$VD" \
        HCLOUD_DELETE_LOG="$DELETE_LOG" \
        env "${EXTRA_ENV[@]}" \
        "$SWEEP" "$@" >"$TMP/out.log" 2>"$TMP/err.log"
}

# single-alive farm: the minimal clean-run fixture (one future-TTL server).
write_single_alive() {
    printf 'w-clean\n' >"$LIST"
    write_describe w-clean "$((NOW - 1 * H))" 10.6.0.1 "$((NOW + 24 * H))"
}

# --- T17: fan-out — every configured destination fires on an alert ---------
write_default_fixtures
: >"$CURL_LOG"; : >"$HOOK_OUT"
EXTRA_ENV=(
    NAU_SWEEP_CURL="$BIN/curl"
    NAU_SWEEP_KUMA_URLS="https://kuma1.example/api/push/T1 https://kuma2.example/api/push/T2"
    NAU_SWEEP_NTFY_URLS="https://ntfy.example/nau-workers"
    NAU_SWEEP_ALERT_CMD="$HOOK_CMD"
    CURL_LOG="$CURL_LOG"
)
RC=0
run_sweep_extra || RC=$?
unset EXTRA_ENV; EXTRA_ENV=()
ERR=$(cat "$TMP/err.log")
CL=$(cat "$CURL_LOG")
FLOOR_MSG="w-floor-50: no usable TTL, age 50h past the 48h alert floor (destroy at 72h)"
assert_eq "T17 fan-out: rc (floor alert)" "1" "$RC"
assert_eq "T17 fan-out: 3 destination HTTP calls (2 kuma + 1 ntfy)" "3" "$(grep -c '^curl ' <<<"$CL")"
assert_contains "T17 fan-out: kuma1 got status=down" "curl https://kuma1.example/api/push/T1	q=status=down&msg=$FLOOR_MSG" "$CL"
assert_contains "T17 fan-out: kuma2 got status=down" "curl https://kuma2.example/api/push/T2	q=status=down&msg=$FLOOR_MSG" "$CL"
assert_contains "T17 fan-out: ntfy got the message as body" "curl https://ntfy.example/nau-workers	q=	body=$FLOOR_MSG" "$CL"
assert_contains "T17 fan-out: ALERT_CMD got the same alert" "$FLOOR_MSG" "$(cat "$HOOK_OUT")"
assert_not_contains "T17 fan-out: no up-heartbeat on a failing run" "status=up" "$CL"

# --- T18: fan-out isolation — one dead destination never silences the rest --
write_default_fixtures
: >"$CURL_LOG"; : >"$HOOK_OUT"
EXTRA_ENV=(
    NAU_SWEEP_CURL="$BIN/curl"
    NAU_SWEEP_KUMA_URLS="https://kuma1.example/api/push/T1 https://kuma2.example/api/push/T2"
    NAU_SWEEP_NTFY_URLS="https://ntfy.example/nau-workers"
    NAU_SWEEP_ALERT_CMD="$HOOK_CMD"
    CURL_LOG="$CURL_LOG"
    CURL_FAIL_URL="kuma1.example"
)
RC=0
run_sweep_extra || RC=$?
unset EXTRA_ENV; EXTRA_ENV=()
ERR=$(cat "$TMP/err.log")
CL=$(cat "$CURL_LOG")
assert_eq "T18 isolation: rc (floor + failed destination)" "1" "$RC"
assert_contains "T18 isolation: kuma1 failure named" "notify: kuma destination failed: https://kuma1.example/api/push/T1 — other destinations still fired" "$ERR"
assert_contains "T18 isolation: kuma2 STILL fired" "status=down&msg=$FLOOR_MSG" "$(grep kuma2 <<<"$CL")"
assert_contains "T18 isolation: ntfy STILL fired" "body=$FLOOR_MSG" "$(grep ntfy <<<"$CL")"
assert_contains "T18 isolation: hook STILL fired" "$FLOOR_MSG" "$(cat "$HOOK_OUT")"
assert_contains "T18 isolation: rollup counted" "1 notify destination(s) failed: kuma(https://kuma1.example/api/push/T1)" "$ERR"

# --- T19: clean run → kuma up-heartbeat only (ntfy stays silent) ------------
write_single_alive
: >"$CURL_LOG"
EXTRA_ENV=(
    NAU_SWEEP_CURL="$BIN/curl"
    NAU_SWEEP_KUMA_URLS="https://kuma1.example/api/push/T1"
    NAU_SWEEP_NTFY_URLS="https://ntfy.example/nau-workers"
    CURL_LOG="$CURL_LOG"
)
RC=0
run_sweep_extra || RC=$?
unset EXTRA_ENV; EXTRA_ENV=()
CL=$(cat "$CURL_LOG")
assert_eq "T19 clean run: rc" "0" "$RC"
assert_eq "T19 clean run: exactly one HTTP call (the kuma heartbeat)" "1" "$(grep -c '^curl ' <<<"$CL")"
assert_contains "T19 clean run: kuma status=up" "q=status=up&msg=sweep ok (mode: dry-run)" "$CL"
assert_not_contains "T19 clean run: ntfy NOT pinged" "ntfy" "$CL"

# --- T20: aws axis — v2 rules, dry-run/enforce, volume residual warn --------
write_aws_fixtures() {
    printf 'w-clean\n' >"$LIST"
    write_describe w-clean "$((NOW - 1 * H))" 10.6.0.1 "$((NOW + 24 * H))"
    cat >"$AWS_LIST" <<EOF
[
  ["i-due", "10.20.0.1", "$(iso $((NOW - 3 * H)))", "$((NOW - 2 * H))"],
  ["i-alive", "10.20.0.2", "$(iso $((NOW - 3 * H)))", "$((NOW + 24 * H))"],
  ["i-noip", "", "$(iso $((NOW - 3 * H)))", "$((NOW - 1 * H))"]
]
EOF
    printf '["vol-keep"]\n' >"$AWS_VOLUME_DIR/i-due"
}
write_aws_fixtures
: >"$AWS_TERMINATE_LOG"; : >"$CURL_LOG"
EXTRA_ENV=(
    NAU_SWEEP_AWS=1 NAU_SWEEP_AWS_BIN="$BIN/aws"
    AWS_LIST="$AWS_LIST" AWS_VOLUME_DIR="$AWS_VOLUME_DIR" AWS_TERMINATE_LOG="$AWS_TERMINATE_LOG"
)
RC=0
run_sweep_extra || RC=$?
ERR=$(cat "$TMP/err.log")
assert_eq "T20 aws dry-run: rc (clean otherwise)" "0" "$RC"
assert_contains "T20 aws dry-run: due instance WOULD-DESTROY (shared engine, tag wording)" "WOULD-DESTROY: i-due (TTL tag past due) — dry-run, no action" "$ERR"
assert_eq "T20 aws dry-run: zero terminates" "" "$(cat "$AWS_TERMINATE_LOG")"
assert_contains "T20 aws dry-run: no-ip instance still rule-1 decided" "WOULD-DESTROY: i-noip (TTL tag past due)" "$ERR"
assert_contains "T20 aws axis summary" "axis aws: 3 labeled, 1 alive, 2 destroy-track, 0 destroyed, 0 volume-blocked, 0 floor-alerted, 0 api-failed" "$ERR"

write_aws_fixtures
: >"$AWS_TERMINATE_LOG"
RC=0
run_sweep_extra --enforce || RC=$?
unset EXTRA_ENV; EXTRA_ENV=()
ERR=$(cat "$TMP/err.log")
assert_eq "T20 aws enforce: rc" "0" "$RC"
assert_eq "T20 aws enforce: exactly the due instances terminated" "i-due
i-noip" "$(cat "$AWS_TERMINATE_LOG")"
assert_contains "T20 aws enforce: surviving volume named, terminate proceeds" "i-due: 1 attached volume(s) will NOT vanish with termination (DeleteOnTermination=false keeps billing) — terminating anyway" "$ERR"
assert_contains "T20 aws enforce: DESTROYED" "DESTROYED: i-due (TTL tag past due)" "$ERR"

# --- T21: aws enumerate failure isolates — hcloud keeps sweeping ------------
write_aws_fixtures
write_default_fixtures   # AFTER: resets the hcloud farm (LIST + fixtures)
: >"$DELETE_LOG"; : >"$AWS_TERMINATE_LOG"
EXTRA_ENV=(
    NAU_SWEEP_AWS=1 NAU_SWEEP_AWS_BIN="$BIN/aws"
    AWS_LIST="$AWS_LIST" AWS_VOLUME_DIR="$AWS_VOLUME_DIR" AWS_TERMINATE_LOG="$AWS_TERMINATE_LOG"
    AWS_LIST_FAIL=1
)
RC=0
run_sweep_extra --enforce || RC=$?
unset EXTRA_ENV; EXTRA_ENV=()
ERR=$(cat "$TMP/err.log")
assert_eq "T21 cross-axis isolation: rc" "1" "$RC"
assert_contains "T21 cross-axis isolation: aws axis named" "ALERT: aws describe-instances failed — aws axis skipped, NO aws worker evaluated" "$ERR"
assert_contains "T21 cross-axis isolation: hcloud axis unaffected (deletes happened)" "DESTROYED: w-label-due (TTL label past due)" "$ERR"
assert_contains "T21 cross-axis isolation: rollup names the aws failure" "1 sweep API failure(s): aws(server-list)" "$ERR"

# --- T22: gcp axis — zone basename rides the delete, disk residual warn -----
write_gcp_fixtures() {
    printf 'w-clean\n' >"$LIST"
    write_describe w-clean "$((NOW - 1 * H))" 10.6.0.1 "$((NOW + 24 * H))"
    cat >"$GCLOUD_LIST" <<EOF
[
  {"name": "g-due",
   "zone": "https://www.googleapis.com/compute/v1/projects/p/zones/europe-west1-b",
   "creationTimestamp": "$(iso $((NOW - 3 * H)))",
   "labels": {"nau-worker": "true", "nau-worker-ttl": "$((NOW - 2 * H))"},
   "networkInterfaces": [{"accessConfigs": [{"natIP": "10.30.0.1"}]}]},
  {"name": "g-alive",
   "zone": "https://www.googleapis.com/compute/v1/projects/p/zones/europe-west1-b",
   "creationTimestamp": "$(iso $((NOW - 3 * H)))",
   "labels": {"nau-worker": "true", "nau-worker-ttl": "$((NOW + 24 * H))"},
   "networkInterfaces": [{"accessConfigs": [{"natIP": "10.30.0.2"}]}]}
]
EOF
    printf '{"disks": [{"autoDelete": true}, {"autoDelete": false}]}\n' >"$GCLOUD_DESCRIBE_DIR/g-due"
}
write_gcp_fixtures
: >"$GCLOUD_DELETE_LOG"
EXTRA_ENV=(
    NAU_SWEEP_GCP=1 NAU_SWEEP_GCP_BIN="$BIN/gcloud"
    GCLOUD_LIST="$GCLOUD_LIST" GCLOUD_DESCRIBE_DIR="$GCLOUD_DESCRIBE_DIR" GCLOUD_DELETE_LOG="$GCLOUD_DELETE_LOG"
)
RC=0
run_sweep_extra --enforce || RC=$?
unset EXTRA_ENV; EXTRA_ENV=()
ERR=$(cat "$TMP/err.log")
assert_eq "T22 gcp enforce: rc" "0" "$RC"
assert_eq "T22 gcp enforce: delete carries the zone from the listing" "g-due europe-west1-b" "$(cat "$GCLOUD_DELETE_LOG")"
assert_contains "T22 gcp enforce: auto-delete-off disk named" "g-due: 1 disk(s) will NOT be deleted with the instance (auto-delete off — the storage keeps billing) — deleting anyway" "$ERR"
assert_not_contains "T22 gcp enforce: alive instance untouched" "DESTROYED: g-alive" "$ERR"

# --- T23: azure axis — rg delete, disk + orphan residuals, no-age record ----
write_az_fixtures() {
    printf 'w-clean\n' >"$LIST"
    write_describe w-clean "$((NOW - 1 * H))" 10.6.0.1 "$((NOW + 24 * H))"
    cat >"$AZ_VM_LIST" <<EOF
[
  ["a-due", "rg-nau-eu", "10.40.0.1", "$(iso $((NOW - 3 * H)))", "$((NOW - 2 * H))"],
  ["a-noage", "rg-nau-eu", null, null, ""]
]
EOF
    printf '[{"name": "disk-1", "vm": "https://m/virtualMachines/a-due", "del": "Fixed"}]\n' >"$AZ_DISK_DIR/rg-nau-eu"
    printf '["nic-left"]\n' >"$AZ_NIC_DIR/rg-nau-eu"
    printf '["pip-1", "pip-2"]\n' >"$AZ_PIP_DIR/rg-nau-eu"
}
write_az_fixtures
: >"$AZ_DELETE_LOG"
EXTRA_ENV=(
    NAU_SWEEP_AZURE=1 NAU_SWEEP_AZ_BIN="$BIN/az"
    AZ_VM_LIST="$AZ_VM_LIST" AZ_DISK_DIR="$AZ_DISK_DIR" AZ_NIC_DIR="$AZ_NIC_DIR" AZ_PIP_DIR="$AZ_PIP_DIR" AZ_DELETE_LOG="$AZ_DELETE_LOG"
)
RC=0
run_sweep_extra --enforce || RC=$?
unset EXTRA_ENV; EXTRA_ENV=()
ERR=$(cat "$TMP/err.log")
assert_eq "T23 azure enforce: rc (no-age record fails loud)" "1" "$RC"
assert_contains "T23 azure enforce: delete carries the rg" "a-due rg-nau-eu" "$(cat "$AZ_DELETE_LOG")"
assert_contains "T23 azure enforce: deleteOption disk named" "a-due: 1 attached disk(s) will NOT be deleted with the VM (deleteOption is not Delete — the storage keeps billing) — deleting anyway" "$ERR"
assert_contains "T23 azure enforce: NIC + public-ip orphans named" "a-due deleted, but 1 unattached network interface(s) and 2 unassociated public IP(s) remain in resource group 'rg-nau-eu' — public IPs keep billing; delete them by hand" "$ERR"
assert_contains "T23 azure enforce: no-age record loud, NO destroy" "azure a-noage: no usable TTL and no parseable creation time — cannot age-check; NO destroy decision (stamp the TTL tag or fix the provider CLI)" "$ERR"
assert_not_contains "T23 azure enforce: no-age never destroyed" "DESTROYED: a-noage" "$ERR"

# --- T24: scw axis — string tags parse, volumes warn, strangers ignored -----
write_scw_fixtures() {
    printf 'w-clean\n' >"$LIST"
    write_describe w-clean "$((NOW - 1 * H))" 10.6.0.1 "$((NOW + 24 * H))"
    cat >"$SCW_LIST" <<EOF
{"servers": [
  {"id": "uuid-1", "name": "s-due", "creation_date": "$(iso $((NOW - 3 * H)))",
   "tags": ["nau-worker=true", "nau-worker-ttl=$((NOW - 2 * H))"],
   "public_ip": {"address": "10.50.0.1"}},
  {"id": "uuid-2", "name": "s-other", "creation_date": "$(iso $((NOW - 3 * H)))",
   "tags": ["some-other-tag"], "public_ip": null}
]}
EOF
    printf '{"volumes": {"0": {}}}\n' >"$SCW_GET_DIR/uuid-1"
}
write_scw_fixtures
: >"$SCW_DELETE_LOG"
EXTRA_ENV=(
    NAU_SWEEP_SCW=1 NAU_SWEEP_SCW_BIN="$BIN/scw"
    SCW_LIST="$SCW_LIST" SCW_GET_DIR="$SCW_GET_DIR" SCW_DELETE_LOG="$SCW_DELETE_LOG"
)
RC=0
run_sweep_extra --enforce || RC=$?
unset EXTRA_ENV; EXTRA_ENV=()
ERR=$(cat "$TMP/err.log")
assert_eq "T24 scw enforce: rc" "0" "$RC"
assert_eq "T24 scw enforce: exactly the tagged server deleted" "server-id=uuid-1" "$(cat "$SCW_DELETE_LOG")"
assert_contains "T24 scw enforce: attached volumes named" "uuid-1: 1 attached volume(s) — a delete only DETACHES them (they keep billing) — deleting anyway" "$ERR"
assert_contains "T24 scw enforce: DESTROYED with tag wording" "DESTROYED: uuid-1 (TTL tag past due)" "$ERR"

# --- T25: enabled-but-broken axis → loud skip, run fails, siblings live -----
write_default_fixtures
EXTRA_ENV=(NAU_SWEEP_AWS=1 NAU_SWEEP_AWS_BIN="$TMP/definitely-not-here")
RC=0
run_sweep_extra || RC=$?
unset EXTRA_ENV; EXTRA_ENV=()
ERR=$(cat "$TMP/err.log")
assert_eq "T25 broken axis: rc" "1" "$RC"
assert_contains "T25 broken axis: named skip" "aws axis skipped: NAU_SWEEP_AWS=1 but a required binary was not found ($TMP/definitely-not-here) — NO aws worker evaluated" "$ERR"
assert_contains "T25 broken axis: hcloud still swept" "WOULD-DESTROY: w-label-due (TTL label past due)" "$ERR"
assert_contains "T25 broken axis: rollup" "1 enabled axis(es) skipped: aws — no worker from them was evaluated" "$ERR"

# --- T26: axes rollup — hcloud on, others named not-enabled -----------------
write_default_fixtures
RC=0
run_sweep || RC=$?
ERR=$(cat "$TMP/err.log")
assert_eq "T26 axes rollup: rc" "1" "$RC"
assert_contains "T26 axes rollup: enabled/not-enabled line" "axes: enabled: hcloud; not enabled: aws gcp azure scw" "$ERR"
assert_contains "T26 axes rollup: per-axis line" "axis hcloud: 8 labeled" "$ERR"

printf '\nsuite: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
