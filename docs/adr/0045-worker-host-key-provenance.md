# ADR-0045: Worker host-key provenance — mint-and-inject

## Status

Accepted (2026-09-27, operator ratification in a grill session). The
ratified form is plain injection (Decision 1) for v1; the SSH host CA
(Decision 3) is the recorded escalation — adopt it when more than two
providers are live or a standing fleet wider than five machines exists,
whichever comes first. #194-#198 are un-parked for implementation (#271
gates the first real provision). Amended 2026-09-29: Decision 3 adopted
early (#283 — five providers are live in code) — see the amendment below.

## Context

ADR-0040 parked cloud provisioning (#194-#198) on one question it could not
answer: providers do not return SSH host keys, so provisioning would capture
them by `ssh-keyscan` — an unauthenticated, on-path-interceptable channel.
Every worker the farm dispatches to is an SSH endpoint; a wrong host key means
build payloads and results go to an impostor machine that ADR-0040 D7's
fabrication hazard then amplifies.

The framings the rejected options share: they all try to secure the *learning*
step. The council's answer removes the learning step.

## Decision

1. **Provenance by construction: the coordinator mints the worker's host
   keypair at provision time.** `ssh-keygen` behind `CommandRunner` (the
   repo's existing subprocess convention, no new crates). The private half is
   delivered to the instance through cloud-init user-data — the provider's
   TLS-plus-token API, the same authenticated channel and credential that can
   already create and destroy machines — written `0600` to `/etc/ssh` by the
   cloud-init template, which then scrubs the user-data blob after `sshd`
   starts (providers expose user-data to the instance indefinitely through
   the metadata service). The public half is pinned into the appended
   `workers` entry in the same atomic config transaction. `sshd`
   serves the injected key. `ssh-keyscan` is never called; no TOFU path exists.
2. **The trust anchor is the provider API credential** — operator access,
   per ADR-0040 D1. Anyone holding it can already create machines with
   arbitrary `authorized_keys`; mint-and-inject gives them nothing new. The
   host key never crosses an unauthenticated channel because it never crosses
   the network at all.
3. **Scalable form (operator's pick at ratification): a coordinator SSH host
   CA.** One pinned `@cert-authority` line per operator; short-lived host
   certificates minted per provision; the certificate principal binds an
   operator-assigned machine identity plus the provider's instance-identity
   content read by cloud-init. Per-worker injection becomes certificate
   issuance. Same config shape, same refusal rule, no per-worker secrets in
   user-data. The two forms share every mechanism below; this ADR is correct
   under either.
4. **Pins are mandatory config.** Every `workers` entry carries its host key
   (or CA fingerprint); `SshExecutor` drives ssh with
   `StrictHostKeyChecking=yes` against a shuttle-managed `known_hosts` built
   from the pins, and preflight refuses an unpinned worker *by name*. This
   half is transport work and lands in T4 (#192) regardless of provisioning —
   it makes ADR-0040 D5's "pinned, not TOFU" mechanically enforced instead of
   delegated to the ambient `~/.ssh/known_hosts`.
5. **LAN workers keep the same shape**: an operator-minted key pinned
   out-of-band, or CA membership. One grammar for rented and owned machines.
6. **T6 is rewritten against this ADR before implementation**: provision
   mints, injects, and pins atomically; the "prints the host key for the
   operator to pin" flow is deleted (it was TOFU with a print statement).

**Why not the alternatives**

- **WireGuard/Tailscale mesh**: adds a daemon or a root-owned interface on
  every worker and, for Tailscale, a third-party coordination plane — a new
  trust root ADR-0040 never sanctioned — while solving transit, not identity
  binding; a pin step is still required. Recorded as a transport option for
  NAT'd fleets, never as the trust answer.
- **TOFU plus a signed host registry**: a signature over the first capture
  does not authenticate the first capture; a MITM at provision time gets its
  key signed. ADR-0024 and ADR-0033 D7 reject TOFU by name.
- **Cloud metadata attestation alone**: the instance attests itself, per
  provider bespoke, and no provider returns host keys. Its identity documents
  are the right *content* for a CA principal, which is where Decision 3 uses
  them.

**Recorded residual risks**: the provider's hypervisor can impersonate its own
VMs, and provider-API credential holders can read user-data — the same trust
level as creating machines, accepted. Blast radius of a leaked worker private
key is exactly one direction: impersonating that worker *to the coordinator*
(bad job payloads), because the key is server-auth only — it is not a login
credential, and worker login stays the operator's separate user key. A
re-provisioned or re-imaged machine needs a fresh pin; workers are stateless
and TTL'd, so this is the normal path. A compromised worker fabricates content
exactly per ADR-0040 D7; provenance guarantees "the machine you dispatch to is
the machine you provisioned", nothing stronger. Determinism cross-checks
remain the control. The CA form (Decision 3) removes the per-worker private
secret from user-data entirely and is the bounded-exposure choice at scale.

## Consequences

**Positive**: the parking rationale in ADR-0040 (Alternatives, Revisit
triggers) is answered on its own terms; zero new infrastructure or trust
roots; one code path across all five providers; the workers DSL gains one
required field.

**Negative**: host-key lifecycle (rotation, TTL'd certs under the CA form)
becomes operator ceremony alongside ADR-0024's signing key ceremony.

## Addendum (2026-09-28): the Hetzner user-data residual is permanent

Research into the metadata exposure behind Decision 1's scrub (librarian
brief against docs.hetzner.cloud API reference + changelog, 2026-09-28):

- **Lifetime**: the IMDS serves create-time user-data for the life of the
  server. No documented bound exists anywhere; the inference is
  behavior-based (the documented `/hetzner/v1/*` metadata table and the
  removed-after-2026-08 EC2-style `/latest/user-data` route both answered at
  any time, not only during first boot).
- **Rebuild re-delivers**: `POST /servers/{id}/actions/rebuild` now accepts a
  `user_data` override — and **without one, the original user-data is
  re-served to the fresh image**. Rebuild is also the recovery path, i.e.
  the moment you would most want the old key dead is the moment it is
  re-injected.
- **No removal, no hardening**: there is no API to read back, replace, or
  delete user-data on a live server; no per-server disable flag, token
  requirement, or hop-limit control (the Robot dedicated "disable metadata"
  flag has no documented Cloud equivalent). The 2026 EC2-route cleanup
  narrowed the URL surface only.
- **Consequence for Decision 1**: the post-sshd guest scrub removes one local
  copy; it does not touch the Hetzner-side record. The private host key must
  be assumed recoverable by any in-guest process for the life of the server
  and every rebuild. The blast-radius argument still bounds this: the key is
  server-auth-only, pins bind the public half (Decision 4 unaffected), and
  exposure is per-machine — but "scrubbed" would overstate it, and
  render_user_data's docstring now says so.

This addendum strengthens Decision 3's escalation case. The clean
elimination is guest-local key generation with authenticated publication of
the public half (no secret ever ships in user-data); filed as an operator
decision (#283) rather than adopted unilaterally, since it amends the
ratified mint-and-inject mechanism.

## Amendment (2026-09-29, #283 decided): Decision 3 adopted — certificate issuance replaces mint-and-inject

The operator picked the scalable form on the addendum's evidence (user-data
residual permanent, re-delivered on rebuild, no hardening knobs). Decision
3's ratification clause was written for exactly this trigger, and its own
invariant — no per-worker secrets in user-data — decides the mechanism:

- The guest generates its host keypair locally on first boot (cloud-init
  `ssh_genkey` or a first-boot unit); no private half is ever minted
  coordinator-side or shipped through user-data. The mint-and-inject scrub
  step becomes dead code and is removed.
- The guest publishes the PUBLIC half to the coordinator over the
  provisioning channel (the one-time create-time token — the same
  authenticated channel, now carrying public material only). The coordinator
  CA signs a short-lived host certificate whose principals bind the machine
  identity plus the provider's instance-identity content (Decision 3's
  principal rule).
- The trust anchor moves from per-worker pins to ONE pinned
  `@cert-authority` line per operator; Decision 4's refusal-by-name posture
  is unchanged (the mandatory workers-entry field becomes the CA
  fingerprint); `StrictHostKeyChecking=yes` and the shuttle-managed
  `known_hosts` stay.
- Rebuild is clean rotation: a rebuilt machine generates a NEW key and
  re-publishes; the addendum's re-delivery trap is moot because nothing
  sensitive is re-delivered. #283's generate-and-publish property is
  delivered BY the CA form, not adopted separately.
- The CA key ceremony joins ADR-0024's — the CA is the new high-value
  trust root, with rotation/TTL policy recorded there. Implementation epic:
  #295. #281's remaining mint-and-inject hardening items are superseded
  where the CA form deletes their subject (the scrub), rescored where it
  does not.

### Executor shape (#295 sub-task 4)

How "same config shape" enforces a certificate on the coordinator side —
recorded here because the principal/address gap decides the mechanics:

- The workers entry keeps `{ address, host_key }`; `host_key` is the CA
  fingerprint. The entry deliberately does NOT carry the machine
  identity: the config shape stays literally unchanged.
- The executor resolves the pin at preflight: the ceremony CA's public
  half (`~/.config/shuttle/ca/ca.pub`) must fingerprint to EXACTLY the
  pin (`ssh-keygen -lf` behind the command seam), and the provision-time
  machine linkage (`~/.config/shuttle/ca/machines/machine-<slug>.json`,
  recorded next to the config pin transaction) must bind the entry's
  address to its machine identity. Either gap is a named preflight
  refusal naming the worker address — Decision 4's posture unchanged.
- The shuttle-managed known_hosts gains ONE line:
  `@cert-authority <principals> <keytype> <base64>` — the principals
  comma-joined from the issued record, machine identity first (the
  identity alone before issuance: the certificate binds it first). ssh
  runs with `HostKeyAlias=<machine identity>` so the known_hosts match
  AND the host-certificate principal check both happen against the
  identity the coordinator issued the certificate for — verified against
  a real sshd on loopback: an address-based connection to a
  machine-identity cert fails host verification (the principal check),
  and the alias form passes it (the connection reaches authentication).
  Provisioned workers are dialed by address, so the alias is what makes
  the form work end to end.
- First boot picks the certificate up over the same one-time bearer
  channel (GET the publish URL; `/etc/shuttle/publish.env` carries the
  slots): a oneshot systemd unit polls with bounded retries until the
  token TTL closes the window, installs the certificate as
  `/etc/ssh/ssh_host_ed25519_key-cert.pub` beside the guest-generated
  key (sshd serves it automatically), and restarts sshd. Fail-closed: a
  worker whose certificate never arrives serves only its raw host key,
  which the `@cert-authority` pin refuses at host verification — the
  coordinator's preflight reports the worker unreachable, named by
  address.

## Revisit triggers

- Workers crossing trust domains (shared/multi-org pools) — replace the
  shared secret with a real PKI or a WireGuard-layer identity.
- ADR-0040's build-attestation work landing — folds instance identity into
  job-level trust, not just connection trust.

## References

- ADR-0040 (distributed build workers: D1 trust boundary, D5 SSH posture,
  D7 fabrication hazard, Revisit triggers), ADR-0024 (key ceremony), ADR-0033
  D7 (out-of-band anchors, no TOFU), ADR-0044 (adjacent install-path trust
  posture).
- Issues: #262 (ratification ticket, the un-park gate), #194 re-scope,
  #195-#198 stay parked behind #194.
