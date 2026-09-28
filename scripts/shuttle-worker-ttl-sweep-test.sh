#!/usr/bin/env bash
# Test suite for scripts/shuttle-worker-ttl-sweep (ticket #269, v2 rules:
# .planning/server-infra-plan.md decision 6) against fake `hcloud` and
# fake `ssh` binaries. No network, no real hcloud account — the live
# verify is operator-side per the ticket.
#
# Proves:
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
#     --dry-run overrides SHUTTLE_SWEEP_ENFORCE=1
#   - --enforce / SHUTTLE_SWEEP_ENFORCE=1 destroy exactly the
#     destroy-track servers
#   - hcloud API failures (list / describe / volume / delete) → ALERT +
#     hook "$1" + nonzero exit; hook absent → still loud on stderr
#   - empty label set → clean exit 0; unknown flag → usage error (rc 2)

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SWEEP=$SCRIPT_DIR/shuttle-worker-ttl-sweep

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
# Shell command string matching the SHUTTLE_SWEEP_ALERT_CMD contract:
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

mkdir -p "$BIN" "$SSH_DIR" "$DCD" "$VD"

# --- fake hcloud -----------------------------------------------------------
cat >"$BIN/hcloud" <<'EOF'
#!/bin/sh
case "$1 $2" in
"server list")
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
    SHUTTLE_SWEEP_SSH="$BIN/ssh" \
        SHUTTLE_SWEEP_HCLOUD="$BIN/hcloud" \
        SHUTTLE_SWEEP_SSH_OPTS="-o BatchMode=yes" \
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

# --- T3: SHUTTLE_SWEEP_ENFORCE=1 env equals the flag ------------------------
write_default_fixtures
: >"$DELETE_LOG"
RC=0
export SHUTTLE_SWEEP_ENFORCE=1
run_sweep || RC=$?
unset SHUTTLE_SWEEP_ENFORCE
assert_eq "T3 env enforce: rc" "1" "$RC"
assert_eq "T3 env enforce: deleted set" "w-label-due
w-floor-73
w-nolabel-due" "$(cat "$DELETE_LOG")"

# --- T4: --dry-run overrides the env (flag wins, order is documented) -------
write_default_fixtures
: >"$DELETE_LOG"
RC=0
export SHUTTLE_SWEEP_ENFORCE=1
run_sweep --dry-run || RC=$?
unset SHUTTLE_SWEEP_ENFORCE
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
export SHUTTLE_SWEEP_ALERT_CMD="$HOOK_CMD"
RC=0
run_sweep --enforce || RC=$?
unset SHUTTLE_SWEEP_ALERT_CMD
ERR=$(cat "$TMP/err.log")
assert_eq "T8 volumes present: rc" "1" "$RC"
assert_eq "T8 volumes present: NO delete" "" "$(cat "$DELETE_LOG")"
assert_contains "T8 volumes present: alert" "ALERT: w-vol: volume(s) still attached, destroy BLOCKED — detach/delete them first: 12345" "$ERR"
assert_not_contains "T8 volumes present: no DESTROYED" "DESTROYED: w-vol" "$ERR"
assert_contains "T8 volumes present: hook rollup" "1 volume-blocked destroy(s): w-vol — nothing deleted" "$(cat "$HOOK_OUT")"

# --- T9: volume-list API failure blocks too ---------------------------------
: >"$DELETE_LOG"; : >"$HOOK_OUT"
export SHUTTLE_SWEEP_ALERT_CMD="$HOOK_CMD" HCLOUD_VOLUME_FAIL_NAME=w-vol
RC=0
run_sweep --enforce || RC=$?
unset SHUTTLE_SWEEP_ALERT_CMD HCLOUD_VOLUME_FAIL_NAME
ERR=$(cat "$TMP/err.log")
assert_eq "T9 volume-list fail: rc" "1" "$RC"
assert_eq "T9 volume-list fail: NO delete" "" "$(cat "$DELETE_LOG")"
assert_contains "T9 volume-list fail: alert" "ALERT: hcloud volume list failed for w-vol — destroy BLOCKED (fail loud)" "$ERR"
assert_contains "T9 volume-list fail: hook rollup" "1 hcloud API failure(s): w-vol(volume-list)" "$(cat "$HOOK_OUT")"

# --- T10: delete API failure → alert + hook + loud --------------------------
printf 'w-due\n' >"$LIST"
write_describe w-due "$((NOW - 1 * H))" 10.8.0.2 "$((NOW - 2 * H))"
: >"$DELETE_LOG"; : >"$HOOK_OUT"
export SHUTTLE_SWEEP_ALERT_CMD="$HOOK_CMD" HCLOUD_DELETE_FAIL=1
RC=0
run_sweep --enforce || RC=$?
unset SHUTTLE_SWEEP_ALERT_CMD HCLOUD_DELETE_FAIL
ERR=$(cat "$TMP/err.log")
assert_eq "T10 delete fail: rc" "1" "$RC"
assert_not_contains "T10 delete fail: no false DESTROYED" "DESTROYED: w-due" "$ERR"
assert_contains "T10 delete fail: alert" "ALERT: hcloud server delete failed for w-due" "$ERR"
assert_contains "T10 delete fail: hook rollup" "1 hcloud API failure(s): w-due(delete)" "$(cat "$HOOK_OUT")"

# --- T11: list API failure → no server evaluated ----------------------------
write_default_fixtures
: >"$DELETE_LOG"; : >"$HOOK_OUT"
export SHUTTLE_SWEEP_ALERT_CMD="$HOOK_CMD" HCLOUD_LIST_FAIL=1
RC=0
run_sweep || RC=$?
unset SHUTTLE_SWEEP_ALERT_CMD HCLOUD_LIST_FAIL
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
assert_contains "T13 empty label set: message" "no servers labeled shuttle-worker — nothing to sweep" "$(cat "$TMP/err.log")"

# --- T14: unknown flag → usage error ----------------------------------------
write_default_fixtures
RC=0
run_sweep --destroy-everything || RC=$?
assert_eq "T14 unknown flag: rc 2" "2" "$RC"
assert_contains "T14 unknown flag: usage" "usage error: unknown argument: --destroy-everything" "$(cat "$TMP/err.log")"

# --- T15: hook failure does not mask the alert ------------------------------
write_default_fixtures
export SHUTTLE_SWEEP_ALERT_CMD="exit 3"
RC=0
run_sweep || RC=$?
unset SHUTTLE_SWEEP_ALERT_CMD
assert_eq "T15 hook failure: rc still 1" "1" "$RC"
assert_contains "T15 hook failure: reported" "ALERT: alert hook (SHUTTLE_SWEEP_ALERT_CMD) exited nonzero" "$(cat "$TMP/err.log")"

# --- T16: hook absent → still loud; hook receives the alert message ---------
write_default_fixtures
: >"$HOOK_OUT"
RC=0
run_sweep || RC=$?
assert_contains "T16 no hook: alert still loud on stderr" "ALERT: w-floor-50: no usable TTL, age 50h past the 48h alert floor" "$(cat "$TMP/err.log")"
export SHUTTLE_SWEEP_ALERT_CMD="$HOOK_CMD"
RC=0
run_sweep || RC=$?
unset SHUTTLE_SWEEP_ALERT_CMD
assert_contains "T16 hook receives floor alert as \$1" "w-floor-50: no usable TTL, age 50h past the 48h alert floor (destroy at 72h)" "$(cat "$HOOK_OUT")"

printf '\nsuite: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
