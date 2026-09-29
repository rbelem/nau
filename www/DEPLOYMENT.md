# Nau www — operator deployment notes

Lane: `www.nau.rclb.dev` (+ the sibling `download` / `cache` vhosts it links to).
Everything here is **operator-side**: this file ships the serving config contract
for the static tree in this directory; nothing in `www/` executes at deploy time.

Sources: `.planning/nau-infra-plan.md` decisions 1-2, 5-6;
`docs/nau-ops-runbook.md` §2-§4 (the authoritative execution pack — this note
only restates what concerns the www tree); ADR-0046 (lanes re-homed onto the Nau
deployment; the blocks below are placement-agnostic and ride whatever terminator
the deployment lands).

## 1. Caddy vhosts

Stock Caddy, per-host HTTP-01 certificates, no plugins, no wildcard (plan
decision 1). Roots follow the plan's `/srv/nau/{www,download,cache}` layout;
`file_server` gives native Range support (resumable multi-GB pulls, sysupdate
transfers) and sendfile. `browse` stays off everywhere — directory listings
never leak (plan decision 6).

```caddyfile
# ── www ──────────────────────────────────────────────────────────────
www.nau.rclb.dev {
	root * /srv/nau/www
	file_server

	# Security headers (plan decision 6). The CSP mirrors the <meta> tag
	# baked into every page — serving it as a header means browsers that
	# ignore the meta (e.g. inside frames) still get it. www needs no
	# third-party anything: fonts, patch, noise tile are all local.
	header {
		Content-Security-Policy "default-src 'self'; script-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
		X-Content-Type-Options "nosniff"
		Referrer-Policy "strict-origin-when-cross-origin"
		Permissions-Policy "camera=(), microphone=(), geolocation=()"
		-Server
	}
	# HSTS: PLAN decision 6 holds it until every consumer is confirmed
	# https-capable. sysupdate is; old `nau pull` versions must be
	# checked first. Flip only then:
	#	Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
}

# ── download ─────────────────────────────────────────────────────────
download.nau.rclb.dev {
	root * /srv/nau/download
	file_server
	# No browse (plan decision 6). Append-only is a PUBLISH policy, not
	# vhost config (plan decision 2): released mission dirs are never
	# deleted by a publish run.
	#
	# No long cache lifetimes here: clients checksum what they fetch, and
	# SHA256SUMS must always be fresh bytes. Leave Caddy's default
	# Last-Modified/ETag validation in charge.
	header {
		Content-Security-Policy "default-src 'none'; frame-ancestors 'none'"
		X-Content-Type-Options "nosniff"
		-Server
	}
}

# ── cache ────────────────────────────────────────────────────────────
cache.nau.rclb.dev {
	root * /srv/nau/cache
	file_server
	# index.json is the commit point of a publish (docs/nau-cache-publish.md
	# order contract) — it must never be served stale from an intermediary:
	header {
		Content-Security-Policy "default-src 'none'; frame-ancestors 'none'"
		Cache-Control "no-cache"  # revalidate every index.json fetch
		X-Content-Type-Options "nosniff"
		-Server
	}
}

# OPTIONAL — only if the apex DNS record exists (plan decision 1):
nau.rclb.dev {
	redir https://www.nau.rclb.dev{uri} 308
}
```

TLS, HTTP→HTTPS redirect, and HTTP/2 are inherited from Caddy's automatic
HTTPS. DNS is one DNS-only (grey-cloud) wildcard A record per
`docs/nau-ops-runbook.md` §2 — do not proxy `download`/`cache` through
Cloudflare (plan decision 5: origin serves bytes, honest bandwidth accounting;
multi-GB `.img` through the free-plan cache is unverified and not assumed).

## 2. www caching

The tree is tiny and fingerprint-free, so:

- `/css/*`, `/fonts/*`, `/assets/*` — content-addressed by release: serve with
  `Cache-Control: max-age=31536000, immutable` (they change only when the
  publish replaces them, and the publish is `rsync --delete` from the repo).
- `/*.html`, `/robots.txt`, `/sitemap.xml` — `Cache-Control: no-cache` (ETag
  revalidation); a mission going live must not wait for a cache expiry.

With stock Caddy the simplest honest route is matching on file extension:

```caddyfile
www.nau.rclb.dev {
	root * /srv/nau/www
	file_server

	@assets path /css/* /fonts/* /assets/*
	handle @assets {
		header Cache-Control "max-age=31536000, immutable"
		file_server
	}
	handle {
		header Cache-Control "no-cache"
		file_server
	}
	# …security headers as above, on both handles…
}
```

## 3. Post-deploy assertions (from the runbook §3 checklist)

```bash
curl -sI https://www.nau.rclb.dev/ | head -1                    # HTTP/2 200
# no directory listing — index file or 404, never a listing:
curl -s https://download.nau.rclb.dev/missions/cassini/ -o /dev/null -w '%{http_code}\n'
# Range works (resumable downloads):
curl -s -r 0-0 -o /dev/null -w '%{http_code}\n' https://download.nau.rclb.dev/missions/cassini/SHA256SUMS   # → 206 once content exists
```

Kuma monitors ride the runbook §4 list (www landing 200; per-mission HEAD on
`SHA256SUMS` **and** `SHA256SUMS.gpg` — the second one pages on a vanished
signature, the monitor-green-while-channel-dead trap).

## 4. Publishing www

`rsync -rlt --delete` from this directory over the tailnet ssh, the same
channel `secrets-apply` already trusts (plan decision 3). The tree is
rebuildable from the repo — `--delete` is safe here, unlike the download lane.
