# Gate pod — P1 dogfood log (devbox-free gate)

Status: **gate proven — the devbox-free cargo path works.** Round 4
shipped the C toolchain payload (#164) and the loader-seam changes it
needed; `shuttle run --pod gate -- cargo build` now compiles C build
scripts through the pod's own gcc and runs the output. The clippy/fmt
drift re-test ran in round 5: drift is real — the pod lint axis cannot
replace the devbox gate yet (see Round 5 + gap 2). All claims come from commands
run on NixOS 26.11, shuttle 0.1.0.

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

## Round 4 (2026-09-23, gate pod @ main 370a3b0's #164 payloads) — C toolchain lands

The last blocker fell, and it took one payload plus three loader-seam
fixes — `cc` on PATH alone would not have been enough:

1. **gcc 14.2.0 payload** (#164): pure fetch-merge from 20 Debian
   trixie snapshot debs (`snapshot.debian.org` @ 20250815T000000Z,
   sha256-pinned, NO libc6-dev — the pod's glibc owns libc; Bootlin
   was ruled out because its bundled sysroot collides with the merged
   prefix, zig-cc because its glibc cap 2.40 < pod 2.43). Sandbox
   unpack tooling discovered by probe recipe (`pkgs/s/sandbox-tool-probe`).
   53,436,416 B snap; all 20 fetches logged `source pinned: <hash>`.
2. **glibc rebuild**: GNU ld scripts (`libc.so`, `libm.so`, …) carried
   absolute rootfs paths — `GROUP ( /lib64/libc.so.6 … )` ENOENT'd for
   a payload consumer. The glibc recipe now rewrites ld scripts to bare
   sonames (text "GNU ld script" files only; ELF .so byte-identical).
   Rebuilt snap sideloaded as generation 11; grep-verified zero
   absolute refs.
3. **Loader seam** (farm.rs): loader lib dirs gained Debian multiarch
   (`usr/usr/lib/x86_64-linux-gnu` — cc1's libisl/libmpfr DT_NEEDED)
   and slibdir (`usr/lib64` — bare-soname scripts resolve libc.so.6
   through -L). `usr/lib` deliberately NOT a key (the extension-release
   marker makes it exist in every pod — it would wrap every app; caught
   by three failing tests and dropped). LD wrappers now export
   COMPILER_PATH so gcc/collect2 find as/ld/ar with no host binutils.
4. **confine.rs**: unconfined direct-exec prefers the generation LD
   wrapper and overlays farm-first PATH — a toolchain app's children
   (cc, rustc) must resolve from the pod, not the caller.
5. **snap.rs**: `cp_r` recreates symlinks instead of dereferencing
   (deb trees ship relative driver links like
   `gcc-14 -> x86_64-linux-gnu-gcc-14`; `fs::copy` duplicated or
   ENOENT'd them).

Acceptance (real runs, verbatim): gcc snap sideloaded (generation 16);
`cargo build --locked` with zstd 0.13.3 → `Compiling zstd-sys
v2.1.0+zstd.1.5.7 … Finished dev profile in 3.96s`, binary runs
(`roundtrip: hello zstd`); clean-target rerun identical. Hermeticity:
`command -v cc gcc clang` on the caller PATH → empty — the pod's cc was
the only compiler reachable. ld-wrapper gcc compiles and runs even with
the farm off PATH (COMPILER_PATH independence). Full devbox gate: 1714
passed / 0 failed.

Operational notes: `pod add --snap` refuses same-version blob swaps —
recipe revisions go through `pod remove` → re-add (generation churn on
gate: 5→24). Concurrent snap builds in one checkout must pass explicit
`--stage` (two lanes shared the default stage; a watcher caught the
stage inode flipping mid-build). glibc builds must run inside devbox
(linux-headers' HOSTCC needs the sandbox gcc).

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

## Round 5 (2026-09-23, lint-drift @ 97bdfaa, debug build) — clippy/fmt drift re-test

The round-4-unblocked experiment, executed: both toolchains' lint axis
against this repo, verdicts diffed. Toolchains: devbox = rustc 1.97.1 /
clippy 0.1.97 / rustfmt 1.9.0 / cargo 1.97.0; gate pod = rustc 1.98.1
(`48a229cea 2026-09-01`) / clippy 0.1.98 / rustfmt 1.9.0 (same 1.98.1
build hash).

1. **Exposure gap first.** Vanilla pod-side commands fail — the farm
   bin set (`pods/gate/current`: `cargo`, `rustc`, `rustfmt`, `clippy`,
   plus the gcc payload bins) has no `cargo-clippy`/`cargo-fmt`:

        error: no such command: `clippy`
        help: view all installed commands with `cargo --list`
        help: find a package to install `clippy` with `cargo search cargo-clippy`
        (exit 101)

        error: no such command: `fmt`
        help: a command with a similar name exists: `fix`
        (exit 101)

   The components are *in* the payload —
   `generations/38/apps/rust/usr/bin/{cargo-clippy,cargo-fmt,clippy-driver}`
   all exist; the farm app layer just doesn't surface them (it exposes
   `clippy`, which *is* clippy-driver 0.1.98, and `rustfmt` 1.9.0).
   Note the pod ships the drivers but cargo's subcommand discovery
   wants the `cargo-*` entry points. Workaround for measurement only,
   caller-side, no pod mutation: symlink the three binaries from
   `apps/rust/usr/bin/` into a `/tmp` shim dir and prepend it to PATH
   before `shuttle run` (farm-first overlay keeps pod bins ahead).

2. **Clippy axis — verdicts differ.** Devbox (`devbox run -- clippy`,
   forced fresh with `touch src/**/*.rs` to defeat the warm target/
   fingerprint cache): exit 0, `Checking shuttle v0.1.0`, 0 diagnostics,
   15.1 s wall (deps cached; first clippy-cold run was 1m10s). Pod
   (`shuttle run --pod gate -- cargo clippy -- -D warnings` + shims,
   all 147 dep crates checked fresh under 1.98.1): exit 101, 55.7 s:

        error: useless use of `format!`
          --> src/isolate.rs:1081:37
           |
        1081 |         Err(e) => return fatal(vec![format!("{e}")]),
           |                                     ^^^^^^^^^^^^^^ help: consider using `.to_string()`: `e.to_string()`
           = help: for further information visit https://rust-lang.github.io/rust-clippy/rust-1.98.0/index.html#useless_format
           = note: `-D clippy::useless-format` implied by `-D warnings`

        error: could not compile `shuttle` (lib) due to 1 previous error

   Identical source, identical `-D warnings`: 1.97.1 clean, 1.98.1
   rejects. `useless_format` in 1.98 catches captured-identifier
   `format!("{e}")` that 1.97 did not. Because the lib fails first, the
   pod's verdict on bins/tests past the lib is unknown — but the gate
   verdict is already different, which is all the experiment needed.

3. **Fmt axis — parity.** `cargo fmt --check` through the pod
   (rustfmt 1.9.0, cargo-fmt shimmed): exit 0, empty output, 1.0 s —
   byte-for-byte the same verdict and wall time as devbox
   (`devbox run -- fmt-check`: exit 0, empty, 1.0 s). No drift; both
   sides run rustfmt 1.9.0.

**Verdict:** the pod lint axis cannot replace the devbox gate today.
fmt matches; clippy drifts (one new error on this repo) AND the farm
doesn't expose the cargo-* shims. Until the pod carries pinned 1.97.1
clippy (devbox's nixpkgs still cannot resolve 1.98.x) and the farm
surfaces `cargo-clippy`/`cargo-fmt`, the devbox lint gate stays the
contract. `build-and-test.md`'s devbox-free endgame is unchanged by
this round — no claim upgraded.

## Gap list to make this the default gate

1. ~~**C toolchain payload (blocking, cargo layer).**~~ **CLOSED in
   round 4** (#164): fetch-merge gcc 14.2 payload + loader-seam fixes;
   cargo build scripts compile in the pod.
2. ~~**Clippy/fmt drift re-test (unblocked).**~~ **ANSWERED in round 5:
   drift is real — the pod cannot replace the devbox lint gate yet.**
   Two blockers remain: (a) the farm bin set does not expose
   `cargo-clippy`/`cargo-fmt` (the rust payload *ships* them under
   `apps/rust/usr/bin/`, they are just not on the farm PATH, so
   `cargo clippy`/`cargo fmt` die with `no such command`); (b) pod
   clippy 0.1.98 is stricter than devbox 0.1.97 — it errors on
   `src/isolate.rs:1081` (`format!("{e}")` → `clippy::useless_format`)
   where 1.97.1 accepts the file, so the two gates disagree on
   identical source. Pod-side lint needs the pinned 1.97.1 clippy
   (or a repo decision to adopt 1.98.1's verdict) plus the farm
   exposure fix. The fmt axis (rustfmt 1.9.0 both sides) already
   matches.
3. **Sandbox C compiler at the recipe layer (narrowed).** From-recipe
   provisioning of rust still needs the glibc chain; with the gcc
   payload now a recipe, a pod can declare gcc as a build tool instead
   of needing a host compiler — untested.
4. **Curl refresh path (filed).** A recipe-only fix (#138) does not
   reach installed pods — #142's recipe-hash pin (merged) now sweeps
   recipe drift on `pod sync`; end-to-end verify a wrapped curl reaches
   a farm via a sync (the original #142 acceptance).
5. **`pod declare --file` (plan §6).** `pod.lua` is write-only today
   (`add`/`remove` maintain it); no checked-in `gate/pod.lua` until a verb
   can load one.
6. Minor: `doctor --pod`'s cc hint names apt/dnf only — now it should
   name the gcc payload. Minor: same-version blob-swap refusal forces
   remove/re-add churn on recipe revisions. Minor: default-stage
   sharing between concurrent builds (mitigate with explicit `--stage`).

State left behind: gate pod provisioned with linux-headers, libgcc,
glibc (soname ld scripts), rust 1.98.1, gcc 14.2.0 — generation 22+.
