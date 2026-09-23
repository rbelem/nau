# Gate pod — P1 dogfood log (devbox-free gate)

Status: **blocked at a C toolchain payload (cargo build-script layer).**
Round 3 proved the sideload route end to end: the gate pod provisions
from prebuilt `.snap` payloads with zero recipe builds, and pod cargo
runs — it now dies only at the first `cc`-needing build script (see
round 3 and gap 1). TLS and the kernel.org download pass; the from-recipe
route stays blocked at the same compiler, one layer lower. All claims
come from commands run on NixOS 26.11, shuttle 0.1.0.

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

## Round 3 (2026-09-23, shuttle @ 0ab0912, debug build) — sideload route proven

The prebuilt-payload route (gap 2) works end to end. All four payloads
existed as Sep-14 lane artifacts in the repo root (`rust_1.98.1`,
`glibc_2.43`, `libgcc_14.2.0`, `linux-headers_7.0` `.snap` files) — no
export verb needed, no recipe build, no gcc.

1. `pod --name gate remove rust` (cleared the round-1 declaration), then
   four sideloads, leaf-first:

        pod --name gate add --ack-unsigned --snap <file>.snap   # ×4

   Each landed green: generations 1–4, `pod list` shows all four
   packages. Two caveats, both honest:

   - `--ack-unsigned` is required: the Sep-14 artifacts predate the
     #133 signature gate. Rebuilt+signed payloads retire the flag.
   - Their `meta/snap.yaml` carries **no `requires`** (pre-#133 build),
     so preflight had nothing to demand — glibc/libgcc/linux-headers
     are in the store because I sideloaded them explicitly, not
     because a closure contract forced them. A rust payload rebuilt
     with current code would stamp `requires: glibc, libgcc` and #151's
     preflight would demand exactly the other three.

2. `shuttle run --pod gate -- cargo build --locked` **executed**: the
   pod reconciled, the farm exposed cargo, and cargo 1.98.1 (pod, not
   devbox) compiled rust deps of this repo. It died at the first C
   build script:

       warning: zstd-sys@2.1.0+zstd.1.5.7: Compiler family detection failed
       due to error: ToolNotFound: failed to find tool "cc": No such file
       or directory (os error 2)
       error: failed to run custom build command for `zstd-sys v2.1.0+zstd.1.5.7`

   lzma-sys and bzip2-sys queue behind the same miss. The blocker
   moved one layer up: the sandbox C compiler is no longer a recipe
   problem (nothing builds from source now) — it is a **missing
   payload**: the pod has no C toolchain for cargo build scripts.

What moved since round 2: the entire #116 sideload route is now proven
(add/list/run), the #133 signature gate behaves, and the devbox-free
gate needs exactly one more payload — a C toolchain. The clippy/fmt
drift question (pod 1.98.1 vs devbox 1.97.1) stays unobservable until
`cargo build` goes green.

## Gap list to make this the default gate

1. **C toolchain payload (blocking, cargo layer).** `cargo build` needs
   `cc` for build scripts (zstd-sys, lzma-sys, bzip2-sys at minimum);
   `doctor --pod` cc/c++ misses unchanged. Two candidate routes: a
   fetch-strategy gcc recipe (rust.lua precedent — a prebuilt toolchain
   tarball instead of the multi-hour source bootstrap), or completing
   the gcc source chain (binutils/gmp/mpfr/mpc/isl snaps exist from the
   Sep-14 lanes; gcc itself never landed). Filed as an issue.
2. **Sandbox C compiler at the recipe layer (unblocked by sideload,
   still open for from-recipe pods).** Any pod provisioning rust from
   the collection recipe still needs gcc to build the glibc chain.
3. **Curl refresh path (filed).** A recipe-only fix (#138) does not
   reach installed pods: curl is not declared in daily, `rebuild`
   reuses the cached closure, `update` no-ops at an unchanged version
   pin. Ambient `CURL_CA_BUNDLE` works meanwhile (never clobbered by
   the wrapper, per #138). (The sideload round needed no curl at all —
   payloads came from disk.)
4. **`pod declare --file` (plan §6).** `pod.lua` is write-only today
   (`add`/`remove` maintain it); no checked-in `gate/pod.lua` until a verb
   can load one.
5. Minor: `doctor --pod`'s cc hint names apt/dnf only — NixOS needs a
   nixpkgs gcc on PATH instead.

State left behind: gate pod provisioned for reuse (4 packages,
generation 4, `~/.local/share/shuttle/pods/gate`).
