#!/bin/sh
# nau-publish-cache.sh — push the Decision-10 mirror tree (index.json,
# manifests/, blobs/) to the cache lane on the Nau host: the public
# package mirror at cache.nau.rclb.dev (ticket #275;
# .planning/nau-infra-plan.md decisions 2-3, ADR-0046 re-homing).
#
# RUNBOOK — one command per release:
#
#   NAU_CACHE_TARGET=nauhost scripts/nau-publish-cache.sh \
#       --release-id <pool-release-id> <export-tree>
#
#   NAU_CACHE_TARGET is [user@]host reachable over the tailnet (ssh
#   config carries the alias/key); NAU_CACHE_ROOT defaults to
#   /srv/nau/cache (the Caddy file_server root). A local directory is
#   accepted as the target — that is how the smoke test
#   (nau-publish-cache-test.sh) exercises this script with no Nau host.
#
# Semantics per plan decision 2/3:
#   - rsync -rlt --delete for the rebuildable tree (--delete scoped to
#     blobs/ and manifests/; see docs/nau-cache-publish.md for why
#     index.json is replaced last and root-level extras are untouched).
#   - Order contract (mirrors scripts/nau-cache-publish #270):
#     every blob, then every manifest, index.json LAST as the commit
#     point — in-flight trees never advertise blobs they don't have.
#   - The freshness stamp (freshness.stamp, tree root) is appended
#     AFTER the sync succeeds: one "<timestamp> <release-id>" line per
#     publish, history preserved across publishes. A failed publish
#     never touches the stamp — "stamp lacks the new release-id" is
#     exactly the kuma content-match alert.
#   - Idempotent, secrets-free: rides the tailnet ssh, no credentials
#     beyond the operator's ssh identity.
#
# The kuma monitor spec (HTTP keyword monitor on the stamp) is
# documented in docs/nau-cache-publish.md; applying it to the kuma
# server is an operator step.
#
# NOT proven here (operator-gated): the remote-ssh path and a live
# `nau pull` from https://cache.nau.rclb.dev/ — both unblock when
# the Nau host exists. The smoke test covers the local-target path
# end to end.

set -eu
LC_ALL=C
export LC_ALL
umask 077

PROG=nau-publish-cache
STAMP_NAME=freshness.stamp

die() {
    printf '%s: FAIL: %s\n' "$PROG" "$*" >&2
    exit 1
}

usage() {
    cat <<EOF
usage: $PROG [--dry-run] --release-id ID [--target T] [--root R] [TREE]

Publish a Decision-10 mirror tree (index.json, manifests/, blobs/) to
the cache lane on the Nau host (cache.nau.rclb.dev), then append the
freshness stamp line "<timestamp> <release-id>".

  TREE           export tree to publish (default: current directory)
  --release-id   pool release id recorded in the stamp (required;
                 env NAU_CACHE_RELEASE_ID also accepted);
                 [A-Za-z0-9._-]+ — it is what the kuma monitor greps
  --target T     [user@]host (tailnet ssh) or a local directory;
                 env NAU_CACHE_TARGET. A local directory IS the tree
                 root (--root does not apply to it)
  --root R       tree root on a remote target (default
                 /srv/nau/cache, env NAU_CACHE_ROOT)

Order: blobs/, manifests/, then index.json last (commit point);
freshness.stamp excluded from the sync and appended after success.
--dry-run prints the plan and performs zero writes.

The kuma content-match monitor spec: docs/nau-cache-publish.md
EOF
}

DRY_RUN=0
TREE=
RELEASE_ID=${NAU_CACHE_RELEASE_ID:-}
TARGET=${NAU_CACHE_TARGET:-}
ROOT=${NAU_CACHE_ROOT:-/srv/nau/cache}

while [ $# -gt 0 ]; do
    case $1 in
        --dry-run) DRY_RUN=1 ;;
        --release-id)
            [ $# -ge 2 ] || die '--release-id needs an argument'
            RELEASE_ID=$2
            shift
            ;;
        --target)
            [ $# -ge 2 ] || die '--target needs an argument'
            TARGET=$2
            shift
            ;;
        --root)
            [ $# -ge 2 ] || die '--root needs an argument'
            ROOT=$2
            shift
            ;;
        -h|--help) usage; exit 0 ;;
        -*) die "unknown option: $1 (see --help)" ;;
        *)
            [ -z "$TREE" ] || die 'multiple input directories given'
            TREE=$1
            ;;
    esac
    shift
done

[ -n "$RELEASE_ID" ] || die 'no release id (use --release-id)'
case $RELEASE_ID in
    ''|.*|*[!A-Za-z0-9._-]*) die "bad release id: $RELEASE_ID ([A-Za-z0-9._-]+, no leading dot)" ;;
esac

[ -n "$TARGET" ] || die 'no target (set NAU_CACHE_TARGET or use --target)'
case $TARGET in
    ''|*[!A-Za-z0-9._@/-]*|*:*) die "bad target: $TARGET ([user@]host or a local directory, no colon)" ;;
esac
case $ROOT in
    /*) ;;
    *) die "bad root: $ROOT (must be an absolute path)" ;;
esac
case $ROOT in
    *[!A-Za-z0-9._/-]*|*'..'*|*//*) die "bad root: $ROOT ([A-Za-z0-9._/-], no '..', no '//')" ;;
esac

[ -n "$TREE" ] || TREE=.
[ -f "$TREE/index.json" ] || die "no index.json under $TREE"
[ -d "$TREE/manifests" ] || die "no manifests/ directory under $TREE"
[ -d "$TREE/blobs" ] || die "no blobs/ directory under $TREE"

command -v rsync >/dev/null 2>&1 || die 'rsync not found on PATH'
case $TARGET in
    */*) IS_REMOTE=0 ;; # local directory path — the directory IS the root
    *) IS_REMOTE=1 ;;   # [user@]host
esac
if [ "$IS_REMOTE" -eq 1 ]; then
    command -v ssh >/dev/null 2>&1 || die 'ssh not found on PATH'
    SPEC="$TARGET:$ROOT"
else
    SPEC=$TARGET
fi

# rsync TO DEST EXTRA ARGS — shared flag set: -r -l -t per plan
# decision 3; --dry-run adds -n. One call site per phase keeps the
# plan printable and the order contract reviewable.
rs() {
    _rs_dest=$1
    shift
    if [ "$DRY_RUN" -eq 0 ]; then
        rsync -rlt "$@" "$_rs_dest"
    else
        rsync -rlt -n "$@" "$_rs_dest"
    fi
}

TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)

if [ "$DRY_RUN" -eq 1 ]; then
    printf 'put(dry)  %s/blobs/\nput(dry)  %s/manifests/\nput(dry)  %s/index.json\n' \
        "$SPEC" "$SPEC" "$SPEC"
    printf 'stamp(dry) %s %s -> %s/%s\n' "$TS" "$RELEASE_ID" "$SPEC" "$STAMP_NAME"
    printf '%s: dry-run — no writes performed\n' "$PROG"
    exit 0
fi

# Phase 1-2: content dirs, --delete scoped (plan decision 2 — the tree
# is rebuildable and follows the curated source).
rs "$SPEC/blobs/" --delete "$TREE/blobs/"
rs "$SPEC/manifests/" --delete "$TREE/manifests/"
# Phase 3: index.json LAST — the commit point. Old index + new
# manifests is a torn tree; new index + old anything is not: consumers
# only follow index.json into content it advertises.
rs "$SPEC/index.json" "$TREE/index.json"

# Phase 4: freshness stamp — read current history (missing => empty),
# append this publish, push. Best-effort read: a fresh tree has no
# stamp yet; the push fails loudly if the target is unreachable.
STAMP_TMP=$(mktemp "${TMPDIR:-/tmp}/$PROG.stamp.XXXXXX") || die 'mktemp failed'
trap 'rm -f "$STAMP_TMP"' EXIT INT TERM
# 644: the stamp is a public static file — it must survive the sync
# readable by the Caddy file_server user (umask 077 would push 0600).
chmod 644 "$STAMP_TMP"
if [ "$IS_REMOTE" -eq 1 ]; then
    # Client-side expansion is the point: $ROOT/$STAMP_NAME are
    # charset-validated above; they form the remote path (SC2029).
    # shellcheck disable=SC2029
    ssh "$TARGET" "cat '$ROOT/$STAMP_NAME' 2>/dev/null" >"$STAMP_TMP" || :
else
    cat "$SPEC/$STAMP_NAME" >"$STAMP_TMP" 2>/dev/null || :
fi
printf '%s %s\n' "$TS" "$RELEASE_ID" >>"$STAMP_TMP"
# -p: carry the 644 (rsync without --perms is under no obligation to).
rsync -p "$STAMP_TMP" "$SPEC/$STAMP_NAME"

printf '%s: published %s -> %s (stamp %s %s)\n' \
    "$PROG" "$TREE" "$SPEC" "$TS" "$RELEASE_ID"
