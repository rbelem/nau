# Kernel snaps must declare the image's base

## Status

Accepted (2026-09-08). Grounded in a `/grill-with-docs` session; empirical basis is the
2026-09-08 unprivileged-image E2E (commits `8719fd7`, `08d07bf`).

## Context

`pin("pc-kernel")` in a core22 `image()` resolved store revision 3720 — a Xenial 4.4 ESM
kernel. Its initramfs (dissected) carries no virtio drivers, no `dm-verity` module, no
`veritysetup`, and its snapd boot logic enforces the UC18 contract (`LABEL=writable`
partition, `snap_core=`/`snap_kernel=` command line). The image assembled perfectly —
GPT, ESP, UKI, verity all verified, and the kernel booted in QEMU — but the payload was
incompatible with the base it was paired with. Kernel snaps declare their intended base
in snap metadata, so shuttle can check; today it does not, and the failure surfaces only
at boot, on real hardware, as a bricked image.

## Decision

When resolving a kernel snap for an `image()`, shuttle verifies the kernel snap's declared
`base:` matches the image's base. Mismatch is a **build error**, not a warning. An author
who genuinely wants an unmatched kernel overrides explicitly (the escape hatch records the
override in the build output).

## Alternatives considered

- **Warn only.** Rejected: the mismatch class is silent bricking at first boot — exactly
  the failure mode shuttle exists to prevent; a warning ships and is ignored.
- **Author pins exact revisions, no check.** Rejected: correctness should not depend on
  every image author knowing store revision lineage.

## Consequences

**Positive**: core22 images cannot silently pair with a 4.4/UC18 kernel; the failure moves
from boot-on-hardware to build time with a precise message.

**Negative**: legacy kernel lines (the ESM-maintained 4.4 `pc-kernel` revisions) become
unusable for modern bases without an explicit override; the check depends on store
metadata quality — a kernel snap without a `base:` declaration skips the check (and says
so in the build log).
