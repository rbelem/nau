# recipes/tools — provisioned floor tool builds

Builds the five binaries shuttle self-provisions (issue #101, disposition
(c)): `mksquashfs` + `unsquashfs` (squashfs-tools), `bwrap`, `tar`, `curl` —
musl-static, x86_64, shipped attached to shuttle releases with a sha256
manifest.

## Files

| File | Role |
|---|---|
| `pins.conf` | Single source of truth: tools_version, per-tool version/URL/sha256, Alpine builder digest |
| `build-tool.sh` | Downloads (sha256-verified) + builds one tool in the pinned Alpine container; gates: static (`file`+`ldd`), strip, exec smoke |
| `gen-manifest.sh` | Generates `tools-manifest.toml` from built artifacts + pins |

Builder choice: pinned-digest Alpine 3.20 container (runner Docker, musl
`-static` packages), not nix `pkgsStatic` — see the header comment in
`build-tool.sh`.

## How to run a release build

Normally automatic: **publishing a release runs
`.github/workflows/tools-artifacts.yml`**, which builds all five binaries,
generates `tools-manifest.toml`, packages the source-offer bundle, and
attaches everything to the release (`gh release upload`, GITHUB_TOKEN — no
repo secrets). `workflow_dispatch` runs the same pipeline without the
release attach (manifest URL prefix names the `tools-v<N>` convention).

Locally, one tool at a time (requires Docker, x86_64):

```sh
recipes/tools/build-tool.sh curl /tmp/downloads /tmp/out
recipes/tools/gen-manifest.sh 1 /tmp/out /tmp/tools-manifest.toml \
    https://github.com/rbelem/shuttle/releases/download/vX.Y.Z
```

`build-tool.sh fetch <dir>` downloads and verifies all four pinned source
tarballs (what the source-offer bundle ships).

## Version bumps

Bump pins in `pins.conf`; **bump `TOOLS_VERSION` in the same change** — it
must be monotonic (doctor's stale detection compares it) and it keys the
atomic `tools/<tools_version>/` provision directory (#101).

## Source-offer obligation

Every release carries, per tool, the upstream source tarball **and** this
build recipe (bundled as `tools-source-offer-v<N>.tar.gz`). Mere
aggregation keeps the GPL/LGPL no-embedding position (squashfs-tools
GPL-2.0+, bwrap LGPL-2.1+, tar GPL-3.0+, curl: curl license) — provenance
without the recipe is theater (the ABE lesson).

## Pinned versions

| Tool | Version | License | Precedence |
|---|---|---|---|
| squashfs-tools (mksquashfs, unsquashfs) | 4.7.5 | GPL-2.0-or-later | provisioned_first |
| bubblewrap | 0.11.2 | LGPL-2.1-or-later | provisioned_first |
| GNU tar | 1.35 | GPL-3.0-or-later | provisioned_first |
| curl | 8.20.0 | curl | **path_first** |

## Caveats

- **curl is PATH-fallback only.** Host curl wins (precedence `path_first`):
  it honors corporate NSS/LDAP certificate directories and custom CA
  bundles. The provisioned musl-static curl ignores `nsswitch.conf` and
  ships no NSS; it bakes the standard ca-certificates bundle path plus
  OpenSSL fallback-dir. nghttp2/brotli/idn2/libpsl/ssh2/ldap are trimmed —
  the floor owes plain HTTP(S) fetches only.
- **bwrap static is the community musl path** (upstream ships no static
  artifacts). This recipe proves the bytes are static and self-report the
  pinned version; the **release gate is the functional sandbox probe**
  (`bwrap --ro-bind / / /bin/true` + xattr round-trip), owned by the doctor
  lane (#101 AC-2) — a CI-built bwrap that fails the probe fails the gate.
