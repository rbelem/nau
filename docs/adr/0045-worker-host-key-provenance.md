# ADR-0045: Worker host-key provenance — mint-and-inject

## Status

Accepted (2026-09-27, operator ratification in a grill session). The
ratified form is plain injection (Decision 1) for v1; the SSH host CA
(Decision 3) is the recorded escalation — adopt it when more than two
providers are live or a standing fleet wider than five machines exists,
whichever comes first. #194-#198 are un-parked for implementation (#271
gates the first real provision).

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
