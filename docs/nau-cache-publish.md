# Nau cache lane: publish wrapper, freshness stamp, kuma monitor spec

Ticket #275 (cache lane of `cache.nau.rclb.dev`),
`.planning/nau-infra-plan.md` decisions 2-3 and 6, ADR-0046 re-homing.
Owns: `scripts/nau-publish-cache.sh` + smoke test
(`scripts/nau-publish-cache-test.sh`). Sibling lanes own the export
itself (lane D) and signed-manifest verification (lane E).

## One command per release

```bash
NAU_CACHE_TARGET=<nauhost> scripts/nau-publish-cache.sh \
    --release-id <pool-release-id> <export-tree>
```

| Setting | Meaning | Default |
|---|---|---|
| `NAU_CACHE_TARGET` / `--target` | `[user@]host` over the tailnet (ssh config carries alias + key), or a local directory (test mode — the directory is then the tree root) | required |
| `NAU_CACHE_ROOT` / `--root` | tree root on the remote host (Caddy `file_server` root) | `/srv/nau/cache` |
| `NAU_CACHE_RELEASE_ID` / `--release-id` | pool release id recorded in the stamp; `[A-Za-z0-9._-]+` | required |
| `--dry-run` | print the plan, zero writes | off |

The wrapper is secrets-free: rsync over the tailnet ssh, exactly the
channel `secrets-apply` already trusts (plan decision 2). No locking —
run one publish at a time.

## Publish semantics

- `rsync -rlt` per plan decision 3, `--delete` scoped to the rebuildable
  content dirs per decision 2.
- Order contract (mirrors the #270 transport: manifest is the commit
  point): `blobs/` first, `manifests/` second, `index.json` LAST.
  In-flight trees never advertise blobs they don't carry, because
  consumers only follow `index.json` into advertised content.
- Documented deviation from a whole-tree `--delete`: root-level extras
  (anything besides `index.json`, `manifests/`, `blobs/`,
  `freshness.stamp`) are left alone. The deletion passes are scoped to
  the two content dirs; trading root-level tidiness for the
  index-last commit point was deliberate.
- `freshness.stamp` is excluded from the tree sync and written only
  after every rsync succeeds. A failed publish never touches the stamp.

## Freshness stamp

`freshness.stamp` at the tree root
(`https://cache.nau.rclb.dev/freshness.stamp`), one line per publish,
appended — history preserved:

```
<YYYY-MM-DDTHH:MM:SSZ> <release-id>
```

e.g. `2026-09-27T22:14:03Z pool-gen121`. Timestamps are UTC
(`date -u`); the release-id must be the pool release id the tree was
exported from — the stamp asserts "this tree carries release R", so a
mislabeled id is a lie the monitor cannot catch (curation/export
determinism is lane D's guarantee; tamper detection is lane E's).

File mode is forced 644: the Caddy `file_server` user must read it.

## Kuma content-match monitor spec (operator)

Plan decision 3: content-match the stamp, not just status 200 —
otherwise "publish did not run" and "publish ran from a stale source"
are indistinguishable. Because the stamp appends history lines, the
keyword must name the release that SHOULD be live, not a past one.

| Field | Value |
|---|---|
| Monitor name | `nau cache mirror — stamp release` |
| Type | HTTP(s) - Keyword |
| URL | `https://cache.nau.rclb.dev/freshness.stamp` |
| Method | GET |
| Accepted status codes | `200` only |
| Keyword | the currently expected pool release-id (e.g. `pool-gen121`) |
| Invert keyword | off |
| Retries / interval | kuma defaults |

What the monitor greps: the response body must contain the keyword as
a substring (end of the newest line, `$2` of the last line).

Operator workflow at each pool release — two commands, in order:

1. `scripts/nau-publish-cache.sh --release-id <new-id> …`
2. Update the kuma monitor's keyword to `<new-id>` (the same release
   runbook step that updates `index.json` expectations).

Alert semantics: firing means the stamp does not yet carry the
expected release — publish failed, never ran, or ran from an
unreleased source. A past release-id in the history lines does NOT
satisfy the check because the keyword is the new id. Complementary
monitor from plan decision 6: plain HTTP monitor, `GET /index.json`,
accept 200 only. The stamp monitor is the one that catches a silent
stale tree; the index monitor only catches a dead origin.

## Not proven yet (operator-gated)

- The remote-ssh path (`[user@]host` targets): unblocks with the Nau
  host; the smoke test drives the identical local-directory path.
- Live `shuttle pull https://cache.nau.rclb.dev/` on a clean machine:
  pending the Nau host existing. Do not attempt before that.
- Caddy vhost, DNS record, kuma server application: documented here,
  applied operator-side (plan execution checklist steps 1-2, 5).
