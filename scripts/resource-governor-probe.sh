#!/usr/bin/env bash
set -uo pipefail

skip() {
    printf 'skip: %s\n' "$1"
    exit 0
}

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    if [[ -n "$on_log" && -f "$on_log" ]]; then
        cat "$on_log" >&2
    fi
    if [[ -n "$off_log" && -f "$off_log" ]]; then
        cat "$off_log" >&2
    fi
    exit 1
}

process_running() {
    local stat state
    [[ -r "/proc/$1/stat" ]] || return 1
    IFS= read -r stat < "/proc/$1/stat" || return 1
    stat=${stat##*) }
    state=${stat%% *}
    [[ "$state" != Z && "$state" != X ]]
}

joined_cgroup() {
    local root_pid=$1 attempt candidate cgroup child stat fields state parent
    for ((attempt = 0; attempt < 400; attempt++)); do
        candidate=$current_cgroup
        while :; do
            cgroup="$candidate/nau-build"
            if [[ -r "$cgroup/cgroup.procs" ]]; then
                while IFS= read -r child; do
                    [[ "$child" =~ ^[0-9]+$ && "$child" != "$root_pid" ]] || continue
                    process_running "$child" || continue
                    fields=$(<"/proc/$child/stat") || continue
                    fields=${fields##*) }
                    read -r state parent _ <<< "$fields"
                    while [[ "$parent" =~ ^[0-9]+$ && "$parent" -gt 1 && "$parent" != "$root_pid" ]]; do
                        fields=$(<"/proc/$parent/stat") || break
                        fields=${fields##*) }
                        read -r state parent _ <<< "$fields"
                    done
                    if [[ "$parent" == "$root_pid" ]]; then
                        printf '%s\n' "$cgroup"
                        return 0
                    fi
                done < "$cgroup/cgroup.procs"
            fi
            [[ "$candidate" == /sys/fs/cgroup ]] && break
            candidate=${candidate%/*}
        done
        process_running "$root_pid" || return 1
        sleep 0.025
    done
    return 1
}

claim_names() {
    [[ -d "$claim_dir" ]] || return 0
    find "$claim_dir" -maxdepth 1 -type f -printf '%f\n' | awk '/^[0-9]+$/ { print }' | sort
}

stat_value() {
    awk -v key="$1" '$1 == key { print $2; found = 1; exit } END { if (!found) exit 1 }' "$2" 2>/dev/null
}

if [[ "${NAU_RESOURCE_GOVERNOR_PROBE:-0}" != 1 ]]; then
    skip "set NAU_RESOURCE_GOVERNOR_PROBE=1 to run the live cgroup acceptance probe"
fi

unset LD_LIBRARY_PATH LD_PRELOAD
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
nau="$repo_root/target/debug/nau"
fixture="$repo_root/test-fixtures/resource-governor-saturation.lua"
[[ -x "$nau" ]] || { printf 'FAIL: build target/debug/nau first\n' >&2; exit 1; }
[[ -f "$fixture" ]] || { printf 'FAIL: missing fixture %s\n' "$fixture" >&2; exit 1; }
for tool in getconf python3 find awk cmp sha256sum mksquashfs; do
    command -v "$tool" >/dev/null || {
        printf 'FAIL: required probe tool is missing: %s\n' "$tool" >&2
        exit 1
    }
done
if ! grep -q '^0::' /proc/self/cgroup || [[ ! -r /sys/fs/cgroup/cgroup.controllers ]]; then
    skip "host does not expose a unified cgroup-v2 hierarchy"
fi
current=$(awk -F: '$1 == "0" { print $3; exit }' /proc/self/cgroup)
current_cgroup="/sys/fs/cgroup${current}"
if [[ ! -r "$current_cgroup/cgroup.controllers" ]] || ! grep -qw cpu "$current_cgroup/cgroup.controllers"; then
    skip "the current cgroup does not expose the cpu controller"
fi
cpus=$(getconf _NPROCESSORS_ONLN)
if [[ "$cpus" != 12 ]]; then
    skip "acceptance host has $cpus online CPUs; this probe asserts the 12-CPU anchor"
fi

uid=$(id -u)
if [[ "$uid" == 0 ]]; then
    claim_dir=/run/nau/governors
elif [[ -d "/run/user/$uid" ]]; then
    claim_dir="/run/user/$uid/nau/governors"
else
    claim_dir="/tmp/nau-governors-$uid"
fi
tmp=$(mktemp -d /tmp/opencode/resource-governor.XXXXXX) || {
    printf 'FAIL: cannot create the probe directory\n' >&2
    exit 1
}
on_log="$tmp/on.log"
off_log="$tmp/off.log"
build_pid=""
cleanup() {
    if [[ -n "$build_pid" ]] && process_running "$build_pid"; then
        kill "$build_pid" 2>/dev/null || true
        wait "$build_pid" 2>/dev/null || true
    fi
    rm -rf -- "$tmp"
}
trap cleanup EXIT

work="$tmp/work"
mkdir -p "$work/stage" "$tmp/on" "$tmp/off"
if ! env -u LD_LIBRARY_PATH -u LD_PRELOAD python3 - "$work/stage" <<'PY'
import hashlib
import os
import sys

payload_dir = os.path.join(sys.argv[1], "payload")
os.makedirs(payload_dir, exist_ok=True)
epoch = 1700000000
for file_index in range(12):
    path = os.path.join(payload_dir, f"payload-{file_index:02}.bin")
    with open(path, "wb") as payload:
        for chunk in range(32):
            seed = (
                b"nau-resource-governor-probe-v1"
                + file_index.to_bytes(4, "little")
                + chunk.to_bytes(4, "little")
            )
            payload.write(hashlib.shake_256(seed).digest(1 << 20))
    os.utime(path, (epoch, epoch))
os.utime(payload_dir, (epoch, epoch))
os.utime(sys.argv[1], (epoch, epoch))
PY
then
    fail "cannot generate the deterministic staged payload"
fi

epoch=1700000000
expected_max="$((cpus * 80 * 1000)) 100000"
probe_error=""
baseline_nr=""
last_nr=""
baseline_usage=""
last_usage=""
baseline_usec=""
last_usec=""
throttled=0
cgroup=""

cd "$work" || fail "cannot enter the probe work directory"
env -u LD_LIBRARY_PATH -u LD_PRELOAD -u COMPILER_PATH -u LIBRARY_PATH -u NAU_RESOURCE_LIMIT \
    SOURCE_DATE_EPOCH="$epoch" "$nau" build --file "$fixture" --output "$tmp/on" \
    >"$on_log" 2>&1 &
build_pid=$!

claim_ready=0
for ((attempt = 0; attempt < 400; attempt++)); do
    if [[ -f "$claim_dir/$build_pid" ]]; then
        claim_ready=1
        break
    fi
    process_running "$build_pid" || break
    sleep 0.025
done
if [[ "$claim_ready" != 1 ]]; then
    probe_error="the default-on nau build did not create its live claim"
else
    mapfile -t claims < <(claim_names)
    if [[ "${#claims[@]}" != 1 || "${claims[0]:-}" != "$build_pid" ]] || ! process_running "$build_pid"; then
        probe_error="expected exactly one live claim for nau PID $build_pid; found ${claims[*]:-none}"
    fi
fi

if [[ "$claim_ready" == 1 ]]; then
    cgroup=$(joined_cgroup "$build_pid" || true)
    if [[ -z "$cgroup" ]]; then
        probe_error="no build child joined the nau-build cgroup"
    elif [[ ! -r "$cgroup/cpu.max" || ! -r "$cgroup/cpu.stat" ]]; then
        probe_error="the joined cgroup does not expose cpu.max and cpu.stat"
    else
        actual_max=$(tr '\n' ' ' < "$cgroup/cpu.max")
        actual_max=${actual_max% }
        if [[ "$actual_max" != "$expected_max" ]]; then
            probe_error="cpu.max was '$actual_max', expected '$expected_max'"
        fi
        baseline_nr=$(stat_value nr_throttled "$cgroup/cpu.stat" || true)
        baseline_usage=$(stat_value usage_usec "$cgroup/cpu.stat" || true)
        baseline_usec=$(stat_value throttled_usec "$cgroup/cpu.stat" || true)
        last_nr=$baseline_nr
        last_usage=$baseline_usage
        last_usec=$baseline_usec
        if [[ -z "$baseline_nr" || -z "$baseline_usage" || -z "$baseline_usec" ]]; then
            probe_error="cpu.stat lacks required counters"
        fi
        while process_running "$build_pid"; do
            if [[ -r "$cgroup/cpu.stat" ]]; then
                last_nr=$(stat_value nr_throttled "$cgroup/cpu.stat" || printf '%s' "$last_nr")
                last_usage=$(stat_value usage_usec "$cgroup/cpu.stat" || printf '%s' "$last_usage")
                last_usec=$(stat_value throttled_usec "$cgroup/cpu.stat" || printf '%s' "$last_usec")
                if [[ -n "$baseline_nr" && "$last_nr" -gt "$baseline_nr" ]] || \
                    [[ -n "$baseline_usec" && "$last_usec" -gt "$baseline_usec" ]]; then
                    throttled=1
                fi
            fi
            sleep 0.05
        done
    fi
fi

if wait "$build_pid"; then
    on_status=0
else
    on_status=$?
fi
on_pid=$build_pid
build_pid=""
if [[ "$on_status" != 0 ]]; then
    probe_error="${probe_error:+$probe_error; }default-on nau build exited with status $on_status"
fi
if [[ -n "$baseline_nr" && "$last_nr" -gt "$baseline_nr" ]] || \
    [[ -n "$baseline_usec" && "$last_usec" -gt "$baseline_usec" ]]; then
    throttled=1
fi
if [[ "$throttled" != 1 ]]; then
    probe_error="${probe_error:+$probe_error; }cpu.stat showed no throttling during the build"
fi

on_claims=$(claim_names)
if [[ -n "$on_claims" ]]; then
    probe_error="${probe_error:+$probe_error; }claims remained after default-on build: $on_claims"
fi

env -u LD_LIBRARY_PATH -u LD_PRELOAD -u COMPILER_PATH -u LIBRARY_PATH -u NAU_RESOURCE_LIMIT \
    SOURCE_DATE_EPOCH="$epoch" "$nau" build --file "$fixture" --output "$tmp/off" \
    --resource-limit off >"$off_log" 2>&1 &
off_pid=$!
off_claim=0
while process_running "$off_pid"; do
    [[ -f "$claim_dir/$off_pid" ]] && off_claim=1
    sleep 0.05
done
if wait "$off_pid"; then
    off_status=0
else
    off_status=$?
fi
if [[ "$off_status" != 0 ]]; then
    probe_error="${probe_error:+$probe_error; }governor-off nau build exited with status $off_status"
fi
if [[ "$off_claim" == 1 ]]; then
    probe_error="${probe_error:+$probe_error; }governor-off build created a claim"
fi

on_snap=$(find "$tmp/on" -maxdepth 1 -type f -name '*.snap' -print -quit)
off_snap=$(find "$tmp/off" -maxdepth 1 -type f -name '*.snap' -print -quit)
if [[ -z "$on_snap" || -z "$off_snap" ]]; then
    probe_error="${probe_error:+$probe_error; }one or both builds did not produce a .snap"
elif ! cmp -s "$on_snap" "$off_snap"; then
    probe_error="${probe_error:+$probe_error; }default-on and governor-off snap bytes differ"
fi

printf 'resource-governor probe: 12 online CPUs\n'
printf 'claims at build start: 1 (PID %s)\n' "$on_pid"
printf 'cpu.max during build: %s\n' "${actual_max:-unreadable}"
printf 'cpu.stat usage_usec: %s -> %s\n' "${baseline_usage:-unreadable}" "${last_usage:-unreadable}"
printf 'cpu.stat nr_throttled: %s -> %s\n' "${baseline_nr:-unreadable}" "${last_nr:-unreadable}"
printf 'cpu.stat throttled_usec: %s -> %s\n' "${baseline_usec:-unreadable}" "${last_usec:-unreadable}"
printf 'default-on build exit: %s\n' "$on_status"
printf 'governor-off build exit: %s\n' "$off_status"
if [[ -n "$on_snap" && -n "$off_snap" ]]; then
    printf 'snap sha256: %s\n' "$(sha256sum "$on_snap" | awk '{print $1}')"
    printf 'snap comparison: %s\n' "$(cmp -s "$on_snap" "$off_snap" && printf identical || printf different)"
fi
if [[ -n "$probe_error" ]]; then
    fail "$probe_error"
fi
printf 'result: PASS\n'
