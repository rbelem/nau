# Gate pod — P1 dogfood log (devbox-free gate)

Status: **blocked at provisioning.** The `gate` pod cannot be materialized
on this machine yet, so the four `shuttle run --pod gate -- cargo …`
commands do not replace devbox here. All claims come from commands run on
NixOS 26.11, shuttle 0.1.0 (`~/.local/bin/shuttle`).

## What worked

- `shuttle pod --name gate add rust` — records the declaration (`rust
  1.98.1`; `pod.lua` + `shuttle.lock` under `~/.local/share/shuttle/pods/
  gate/`), then reconciles. Without `mksquashfs` on PATH it fails closed
  (`cannot reconcile pod 'gate': mksquashfs/unsquashfs not found on
  PATH`). This is NixOS — no apt — so the distro-tools step became a PATH
  prepend of existing store paths: `…/squashfs-tools-4.7.5/bin`
  (m40v0qhihqkhvs835wp8smqm036x11yn) and `…/91rl324p7yidwakn63rnxwl5ch540mg5-profile/bin` (bwrap).
- `pod --name gate list` → `rust 1.98.1`; `doctor --pod` → all ok except `cc`/`c++` missing (exit 1).

## Where it stopped (verbatim)

1. `pod sync`, attempt 1 — the rust chain (rust → glibc → linux-headers)
   fetches kernel.org headers via the farm curl (daily pod's farm, first
   on caller PATH), which has no CA bundle (fixable via `CURL_CA_BUNDLE`/
   `SSL_CERT_FILE` → `/etc/ssl/certs/ca-certificates.crt`):

       curl: (60) SSL certificate OpenSSL verify result: unable to get local issuer certificate (20)
       Error:   × failed to download https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.0.tar.xz

2. Attempt 2 (TLS fixed) — linux-headers build dies in the sandbox:

       sh: gcc: not found
       Error:   × build command exited with error (in sandbox)

   No C compiler on that PATH (host has none, doctor agrees, pool `gcc`
   is a multi-hour source build).

`shuttle run --pod gate -- cargo build --locked` correctly refuses (`pod
'gate' has not been reconciled yet`). The 1.98.1-vs-1.97.1 clippy/fmt
drift is **not yet observable** — it needs a live pod.

## Gap list to make this the default gate

1. **Prebuilt payload provisioning (blocking).** A fresh pod's store is
   per-pod and empty; `pod sync` builds the full requires chain from
   recipes, and rust drags in glibc (source build, hours). Shuttle 0.1.0
   has no verb carrying prebuilt payloads into a pod: no `export`/`serve`;
   `pull` is OCI-only (no `--pod`); `pod add` takes names only.
2. **CA bundle (blocking).** Pod env should declare `CURL_CA_BUNDLE`/`SSL_CERT_FILE`, or the farm curl should ship one.
3. **Sandbox C compiler (blocking for any C-building recipe).** The
   linux-headers step of the rust chain needs gcc on the sandbox PATH.
4. **`pod declare --file` (plan §6).** `pod.lua` is write-only today
   (`add`/`remove` maintain it); no checked-in `gate/pod.lua` until a verb
   can load one.
5. Minor: `doctor --pod`'s cc hint names apt/dnf only — NixOS needs a
   nixpkgs gcc on PATH instead.

State left behind: gate pod kept for reuse (`8.0K
~/.local/share/shuttle/pods/gate`; declaration + lockfile; `store/`,
`downloads/` empty — no generation).
