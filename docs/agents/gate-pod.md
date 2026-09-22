# Gate pod — P1 dogfood log (devbox-free gate)

Status: **blocked at the sandbox C compiler.** TLS and the kernel.org
download now pass; the rust chain still dies building linux-headers
without gcc in the sandbox. All claims come from commands run on
NixOS 26.11, shuttle 0.1.0.

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

## Round 2 (2026-09-22, shuttle @ a3cc98b, debug build)

1. `pod --name gate sync` with the daily farm first on PATH — still the
   exit-60 CA failure: the farm curl is the daily pod's generation 67,
   built before #138, so it carries neither the wrapper nor a bundle.
   The #138 fix lives in recipes; no installed pod has rebuilt curl yet
   (refresh-path gap → issue filed).
2. Same with `CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt` in the
   caller env — the kernel.org headers tarball downloads and hashes
   (`source hash: bb7f6d80b387c757…`), then the linux-headers build dies
   in the sandbox, unchanged:

        sh: gcc: not found
        Error:   × build command exited with error (in sandbox)

What moved since round 1: #116 shipped `pod add --snap` (prebuilt
payload sideloading — provisioning has a verb now), and #130/#138 fixed
the curl recipes (wrapper + ca-certificates require). Neither has been
exercised on the gate pod yet.

## Gap list to make this the default gate

1. **Sandbox C compiler (blocking).** The linux-headers step of the rust
   chain needs gcc on the sandbox PATH; `doctor --pod` cc/c++ misses
   unchanged. This is now the only blocker for the from-recipe route.
2. **Prebuilt payload provisioning (alternate route, untested).**
   `pod add --snap` (#116) can carry prebuilt payloads into a pod
   without a recipe build. Untested on gate; a requires-carrying payload
   on a collection-less target lands exactly in #132's failure path.
3. **Curl refresh path (filed).** A recipe-only fix (#138) does not
   reach installed pods: curl is not declared in daily, `rebuild`
   reuses the cached closure, `update` no-ops at an unchanged version
   pin. Ambient `CURL_CA_BUNDLE` works meanwhile (never clobbered by
   the wrapper, per #138).
4. **`pod declare --file` (plan §6).** `pod.lua` is write-only today
   (`add`/`remove` maintain it); no checked-in `gate/pod.lua` until a verb
   can load one.
5. Minor: `doctor --pod`'s cc hint names apt/dnf only — NixOS needs a
   nixpkgs gcc on PATH instead.

State left behind: gate pod kept for reuse (`8.0K
~/.local/share/shuttle/pods/gate`; declaration + lockfile; `store/`,
`downloads/` empty — no generation).
