# Gate pod — P1 dogfood log (devbox-free gate)

Status: **gate proven — the devbox-free cargo path works.** Round 4
shipped the C toolchain payload (#164) and the loader-seam changes it
needed; `shuttle run --pod gate -- cargo build` now compiles C build
scripts through the pod's own gcc and runs the output. The clippy/fmt
drift re-test ran in round 6: drift is real. Round 7 landed the lint
enablers — the farm exposes the cargo subcommand shims and the one
clippy error is fixed — so both toolchains' lint axes now pass this
repo pod-side with no caller shims (see Round 7 + gap 2; the
toolchain-version contract decision stays open). Round 8 re-pinned the
payload: the gate pod now carries 1.97.1 — the pinned toolchain — and
pod/devbox lint verdicts are identical by construction (see Round 8 +
gap 2; what remains of the lint axis is policy documentation in
build-and-test.md, not code). All claims come from commands
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
(linux-headers' HOSTCC needs the sandbox gcc). Pods carrying a gcc
payload built before 77964ae still have the broken `c++`; the fix
reaches them by re-sideload, which b8afa43 makes a same-version blob
swap (no remove/re-add churn). The payload hash changes again with the
review fixes (shim -L guard, gcc routed through the shim), so existing
gate pods need one re-sideload to pick up all three fixes.

## Round 5 — curl refresh path end to end (#142) (2026-09-23, daily pod, shuttle @ 97bdfaa + #138/#142 in tree, debug build)

**Verdict: negative — `pod sync` does not sweep the stranded #138 curl
fix.** The recipe-closure hash pin never fires for it: the migration
clause baselines past drift instead of detecting it, and undeclarable
closure members skip sync outright. The original #142 acceptance (a
wrapped curl reaches a farm via sync) is unreachable on the daily pod;
issue #142 stays open.

1. Recon (before): generations 62–67, active → 67 (built set 21
   23:34). curl 8.20.0 rev 0 is a gen-67 member via git's `requires` —
   undeclarable, absent from `pod.lua` and from `pod list`; the gen-67
   farm exposes **no curl entry** (a caller's `command -v curl` falls
   through to the NixOS system curl). The installed blob is pre-#138:
   a 365 KB ELF at
   `…/generations/67/extensions/curl/usr/usr/bin/curl` (mtime set 17),
   and the generation carries **no ca-certificates member at all** —
   the #138 recipe's new require has never been materialized here.
   Lockfile: 63/63 entries, **zero `recipe_sha256`** (pre-#142 lock).

2. `pod --name daily sync` (`CURL_CA_BUNDLE` exported per the pre-sync
   contract; NixOS squashfs-tools/bwrap store paths prepended per the
   round-1 precedent). Sync did NOT detect curl drift — it started a
   mass content-hold rebuild of declared packages (gen 67 predates two
   days of recipe/payload changes): atuin, bitwarden-cli, bws, bun,
   chezmoi rebuilt green (fetch-merge), then dconf died in the sandbox:

        meson.build:1:0: ERROR: Unknown compiler(s): [['cc'], ['gcc'], ['clang'], …]
        Running `cc --version` gave "[Errno 2] No such file or directory: 'cc'"
        Error:   × build command exited with error (in sandbox)

   Downloads ran through a pod curl whose RUNPATH pins the gen-66-era
   extension tree — `curl:
   …/generations/66/ld-wrappers/../extensions/curl/usr/usr/lib/libcurl.so.4:
   no version information available` — the same pre-#138 blob class;
   TLS succeeded only because of the exported `CURL_CA_BUNDLE`. The
   devbox-HOSTCC retry was deliberately NOT taken: the dconf miss is a
   plain content-hold rebuild unrelated to the curl verdict, and
   completing the 60+-package storm would not change it (the member
   skip below is unconditional). The failed sync left no trace per the
   pins-after-success contract: active still → 67, lock still 0
   stamps, generations unchanged.

3. Root cause (two independent grounds, pod.rs @ this tree):
   - **Migration clause swallows past drift.** `detect_recipe_drift`
     (src/pod.rs:2907-2911): a lock entry without `recipe_sha256`
     stamps the digest **silently, no rebuild**. The stamped digest is
     computed from the *currently resolved* recipes — which already
     contain #138 (fe0f9cc). The first successful post-#142 sync
     therefore writes a baseline that includes the stranded fix; every
     later sync compares equal and drift can never fire. No disk state
     anywhere carries a pre-fe0f9cc baseline (stamps land only on
     successful sync, and none happened between f7cc5ac and fe0f9cc).
   - **Undeclarable members skip sync.** `install_requires_closure`
     (src/pod.rs:3713-3725): `if active_names.contains(&name) &&
     !drifted { continue; }`. Even when git rebuilds (here via plain
     content-hold, not drift), curl — the active generation carries it,
     `recipe_drift_members` is empty — is skipped. No sync path reaches
     the curl recipe without drift firing first.

4. Acceptance (step 4) NOT RUN — moot: no new generation, no wrapped
   curl exists to expose on a farm. TLS without `CURL_CA_BUNDLE` would
   still fail today: the pod's curl is byte-identical pre-#138 content
   with no bundle sibling.

Narrowed gap: #142's mechanism remains valid for FUTURE recipe edits
(post-baseline drift fires → the declared package plus drifted closure
members rebuild, churn-guarded). What it cannot do is retro-sweep a fix
that predates a pod's first post-#142 stamp — exactly the #138
situation it was filed for. Follow-up candidates for the issue (none
attempted here): a one-shot migration rebuild, a `pod refresh` verb, or
the documented remove/re-add churn.

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

## Round 6 (2026-09-23, lint-drift @ 97bdfaa, debug build) — clippy/fmt drift re-test

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

## Round 7 (2026-09-23, lint-enable @ 3f17f55, debug build) — lint enablers land

Both round-6 blockers closed in code, and the drift experiment re-run
for real: after the fixes, BOTH toolchains' lint axes pass this repo
pod-side with no caller shims. Toolchains unchanged from round 6:
devbox = rustc 1.97.1 / clippy 0.1.97 / rustfmt 1.9.0 / cargo 1.97.0;
gate pod = rustc 1.98.1 (`48a229ceae 2026-09-01`) / clippy 0.1.98 /
rustfmt 1.9.0.

1. **Blocker (a) — farm exposure — closed in `farm.rs`.** The emit now
   surfaces a package's cargo external-subcommand entry points: payload
   siblings recorded DIRECTLY beside a declared `cargo` app whose bare
   name is `cargo-*` (`cargo-clippy`, `cargo-fmt` for the rust payload)
   get farm links — exactly what `cargo clippy`/`cargo fmt` PATH-search,
   a mechanism the declared app table cannot express. Same seams as
   every other entry: layer precedence through the shared collision
   map, a name the package already declares as an app is not
   duplicated, `clippy-driver` and other non-`cargo-*` siblings stay
   unexposed, and the drivers run from the full materialized payload
   copy (`extensions/rust/usr/usr/bin/…`) so their `/proc/self/exe`
   sysroot resolution keeps the complete `usr/lib` tree. Landing it
   needed no pod mutation beyond a re-emit: `pod --name gate sync`
   (no-op — all five packages held at their pins, generation 38
   current) re-presents and re-emits the farm of the EXISTING
   sideloaded rust payload:

        $ ls ~/.local/share/shuttle/pods/gate/current | grep cargo
        cargo
        cargo-clippy
        cargo-fmt

2. **Blocker (b) — source drift — dissolved for this repo.**
   `src/isolate.rs:1081` now reads `e.to_string()` where round 6's pod
   clippy errored on `format!("{e}")` (`clippy::useless_format`);
   1.97.1 accepts both forms, so the devbox gate stays green (it did).

3. **Clippy axis — parity, both green, no shims.** Pod-side, from this
   tree, no caller PATH shims:

        $ shuttle run --pod gate -- cargo clippy --version
        clippy 0.1.98 (48a229ceae 2026-09-01)          # exit 0, 0.16 s
        $ time shuttle run --pod gate -- cargo clippy -- -D warnings
          Compiling libc v0.2.189
          … every dep crate checked fresh under 1.98.1, then:
          Checking shuttle v0.1.0 (…/lint-enable)
          Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 07s
        real    1m7.119s
        # exit 0; zero diagnostics

   Devbox (`devbox run -- clippy`): exit 0, 0 diagnostics (10.2 s cold
   after the source edit; 0.2 s warm). Round 6's verdict flips:
   identical source, identical `-D warnings`, both toolchains accept.

4. **Fmt axis — still parity.** Pod `shuttle run --pod gate -- cargo
   fmt --check`: exit 0, empty output, 0.77 s; `cargo fmt --version`
   through the run → `rustfmt 1.9.0-stable (48a229ceae 2026-09-01)`,
   `rustc 1.98.1`, `cargo 1.98.1`. Devbox `devbox run -- fmt-check`:
   exit 0, empty, 0.96 s.

5. **Offline proof for the exposure fix**: `tests/pod_snap_sideload.rs`
   gains `cargo_subcommand_shims_surface_on_the_farm` — it sideloads a
   fake multi-file toolchain payload (only `cargo` declared as an app)
   into a collection-less pod and asserts the farm exposes
   `cargo-clippy`/`cargo-fmt` AND that they execute through the farm
   PATH (the resolution `cargo clippy` performs), while `clippy-driver`
   stays unexposed. Full devbox gate (`devbox run -- check`): exit 0 —
   lib tests 1436 passed / 0 failed, clippy clean, fmt clean.

Honest limits: pod clippy 0.1.98 remains strictly stricter than 0.1.97
in general — this repo now satisfies both, but a future source pattern
could re-split the verdicts (round 6's mechanism is unchanged). The
toolchain-version decision (keep the 1.97.1 pin vs adopt 1.98.1's
stricter verdict as the contract) stays open for the repo owner. The
devbox lint gate remains the default until that call is made — but the
pod-side axis is now runnable and matching, not blocked.

## Round 8 (2026-09-23, pin-1971 @ f5aa68d, debug build) — the pod carries the pinned toolchain

The council-resolved endgame step for the lint axis: the payload must
FOLLOW the devbox pin, not outrun it. Pod clippy 0.1.98 was strictly
stricter than the pinned 0.1.97 — a different verdict set, so the pod
gate could re-split from devbox on future source (round 7's honest
limit). `pkgs/r/rust.lua` is a FETCH recipe — the official
static.rust-lang.org dist tarball — so the older point release is
trivially fetchable (it is devbox's nixpkgs that cannot resolve
1.98.x, never the dist archive). Re-pinned to 1.97.1, payload
rebuilt, sideloaded as a version move (1.98.1 → 1.97.1), drift
experiment re-run: the pod's lint verdicts now MATCH the devbox pin
exactly.

1. **Re-pin.** `version = "1.97.1"`; source URL
   `https://static.rust-lang.org/dist/2026-07-16/rust-1.97.1-x86_64-unknown-linux-gnu.tar.xz`;
   sha256 `88f28fa9af20594179f85d6df67078dfd6fa93e2f6da5e1e9b0ac4997988ca4f`,
   from the signed channel manifest (`channel-rust-1.97.1.toml`,
   `date = "2026-07-16"`,
   `[pkg.rust.target.x86_64-unknown-linux-gnu]` → `xz_hash`) and
   triple-checked by hashing the downloaded 201,303,968-byte tarball
   (`sha256sum` → identical, two independent grounds). The build's own
   fetch gate verified it again:

        ✓ SHA-256 verified: 88f28fa9af205941...

   Component set unchanged — the tarball carries the same
   dist-root layout (cargo/, rustc/ with lib/ + libexec/,
   rust-std-x86_64-unknown-linux-gnu/, clippy-preview/,
   rustfmt-preview/) the build script merges; recipe structure and
   style untouched.

2. **Payload build** (explicit `--stage`,
   `CURL_CA_BUNDLE` exported for the farm-curl fetch):

        ✓ rust_1.97.1_amd64.snap                    (174,718,976 B)
        source pinned: 88f28fa9af20594179f85d6df67078dfd6fa93e2f6da5e1e9b0ac4997988ca4f https://static.rust-lang.org/dist/2026-07-16/rust-1.97.1-x86_64-unknown-linux-gnu.tar.xz

   Two traps hit on the way, both now operational notes: the first
   uncached chain build needs devbox (linux-headers HOSTCC — round 4
   note, unchanged), and the payload leg itself needs a GNU tar/xz
   shim ahead of the documented PATH prepends (busybox tar/xz in the
   bwrap profile dir die on the rust dist tarball's multi-stream xz —
   see operational notes below). `-A amd64` is required: glibc
   declares an arm64 leg the host refuses to cross-build.

3. **Sideload — a version move, accepted by the add path by design**
   (no remove/re-add, no generation churn beyond the one):

        ✓ sideloaded 'rust' (1.97.1) into pod 'gate' (generation 39)

   `--ack-unsigned` as expected (payload built by this recipe; the
   signing ceremony is still pending, ADR-0011 step (e)). Then
   `pod --name gate sync` — held all five packages at their pins
   (`held 'rust' at its pin`), `generation 39 current`, farm
   re-emitted at `generations/39/farm`. `pod list`:

        linux-headers  7.0
        libgcc         14.2.0
        rust           1.97.1
        glibc          2.43
        gcc            14.2.0

   and the farm exposes all six toolchain entries: `cargo`,
   `cargo-clippy`, `cargo-fmt`, `clippy`, `rustc`, `rustfmt`.

4. **The parity proof** — from this tree, raw caller shell, NO shims,
   NO `CURL_CA_BUNDLE` in the run env. Versions through the pod run:

        $ shuttle run --pod gate -- cargo clippy --version
        clippy 0.1.97 (8bab26f4f6 2026-07-14)
        $ shuttle run --pod gate -- rustc --version
        rustc 1.97.1 (8bab26f4f 2026-07-14)
        $ shuttle run --pod gate -- cargo --version
        cargo 1.97.1 (c980f4866 2026-06-30)
        $ shuttle run --pod gate -- cargo fmt --version
        rustfmt 1.9.0-stable (8bab26f4f6 2026-07-14)

   Clippy axis — every dep crate checked fresh under the pod's 1.97.1
   (the official dist build, `8bab26f4f6` — a different rustc binary
   from devbox's nixpkgs build, so cargo fingerprints differ and
   nothing is shared through target/):

        $ time shuttle run --pod gate -- cargo clippy -- -D warnings
          Checking serde_yaml v0.9.34+deprecated
          … (every dep crate, then)
          Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 17s
        real    1m17,744s
        # exit 0; zero diagnostics

   Devbox side (`devbox run -- clippy`): exit 0, zero diagnostics,
   1m13.8s (it rechecked after the pod run — each side rebuilds the
   other's artifacts, but the verdicts are what matter and they are
   identical). Fmt axis: pod `shuttle run --pod gate -- cargo fmt
   --check` exit 0, empty output, 1.3s; devbox `devbox run --
   fmt-check` exit 0, empty, 0.9s.

**Verdict:** the pod lint gate now carries the pinned toolchain; pod
and devbox verdicts are identical — same toolchain (rustc 1.97.1 /
clippy 0.1.97 / rustfmt 1.9.0 on both sides). Round 6's drift
mechanism (a 1.98-only lint rejecting source 1.97 accepts) is
structurally closed: there is no 1.98 in the gate anymore. Gap 2's
code axis is done; what remains of the lint axis is policy —
documenting in build-and-test.md when the pod-side axis may stand in
for the devbox gate (another lane owns that file).

Operational notes (round 8): the documented round-1 PATH prepends
shadow GNU tar/xz with busybox — the bwrap profile dir
(`91rl324p7yidwakn63rnxwl5ch540mg5-profile/bin`) carries its own
`tar` and `xz`, and busybox's decompressor dies on the rust dist
tarball's multi-stream xz stream AFTER the sha256 verify passes (the
bytes on disk are correct; the decompressor, not the archive, is
what fails — three builds were burned finding this):

    xz: corrupted data
    tar: Child returned status 1
    Error:   × failed to extract rust-1.97.1-x86_64-unknown-linux-gnu.tar.xz

Repair is caller-side and one dir: prepend a shim directory holding
GNU tar/xz symlinks (here `/run/current-system/sw/bin/{tar,xz}`)
AHEAD of the two documented prepend dirs. Under devbox the same trap
fires with no prepends at all — devbox's own profile tar IS busybox
(`tar (busybox) 1.37.0`). Separately: `-A amd64` is mandatory for
chain builds here — glibc declares an arm64 leg the host refuses
("refusing to build for 'arm64' on this amd64 host: no cross
toolchain is configured…"). On the gcc c++ shim: the feared stale
payload is already gone — the gate pod's gcc payload as installed in
generation 38 (pre-dating this lane, which touched only rust)
carries the post-77964ae dispatch
(`c++|cxx|g++) exec "$d/x86_64-linux-gnu-g++-14"`), and a C++
compile through the pod succeeds (`shuttle run --pod gate -- c++ -o
… exit 0`, 18,888-byte binary produced). Should a stale gcc payload
ever reappear, the documented repair is a same-version re-sideload
of a rebuilt payload — content hash is the identity since b8afa43;
gcc.lua is another lane's file, untouched here.

## Gap list to make this the default gate

1. ~~**C toolchain payload (blocking, cargo layer).**~~ **CLOSED in
   round 4** (#164): fetch-merge gcc 14.2 payload + loader-seam fixes;
   cargo build scripts compile in the pod.
2. ~~**Clippy/fmt drift re-test (unblocked).**~~ **ANSWERED in round 6;
   enablers LANDED in round 7.** Round 6 measured the drift and named
   two blockers; round 7 closed both: (a) the farm bin set now exposes
   the cargo external-subcommand shims — `cargo-clippy`/`cargo-fmt`
   are emitted from the cargo app's recorded payload siblings, a
   no-op-reconcile re-emit surfaces them on the EXISTING pod, and
   `cargo clippy`/`cargo fmt` run through `shuttle run` with no caller
   PATH shims; (b) the one-line source fix (`src/isolate.rs:1081`,
   `format!("{e}")` → `e.to_string()`) dissolves the divergence for
   this repo — both toolchains' clippy and fmt axes pass, pod-side and
   devbox-side (round 7 evidence). Round 8 removed the last code
   dimension: the payload now follows the devbox pin (rust 1.97.1 in
   the pod, sideloaded as a version move), so pod clippy IS 0.1.97 —
   the "keep the 1.97.1 pin vs adopt 1.98.1's stricter verdict"
   contract question is dissolved in code rather than picked: there is
   no 1.98 verdict set in the gate anymore, and the round-6 re-split
   mechanism is structurally gone (round 8 evidence). REMAINING,
   policy not code: document in build-and-test.md when the pod-side
   axis may substitute for the devbox gate (another lane owns that
   file).
3. **Sandbox C compiler at the recipe layer (narrowed).** From-recipe
   provisioning of rust still needs the glibc chain; with the gcc
   payload now a recipe, a pod can declare gcc as a build tool instead
   of needing a host compiler — untested.
4. ~~**Curl refresh path (filed).**~~ **NEGATIVE in round 5.** #142's
   recipe-hash pin cannot sweep the stranded #138 fix: the migration
   clause (entry without `recipe_sha256` → stamp silently, no rebuild)
   baselines the *current* recipes, so drift that predates the baseline
   — i.e. fe0f9cc itself — is undetectable; and undeclarable closure
   members skip sync unless a drifted declared package names them
   (pod.rs:3722). A wrapped curl reaches no farm via sync on any pod
   whose first post-#142 sync postdates the recipe fix. #142 stays
   open; needs a follow-up (one-shot migration rebuild or refresh
   verb). The pin remains valid for future recipe drift.
5. **`pod declare --file` (plan §6).** `pod.lua` is write-only today
   (`add`/`remove` maintain it); no checked-in `gate/pod.lua` until a verb
   can load one.
6. Minor: default-stage sharing between concurrent builds (mitigate
   with explicit `--stage`). Landed from this list: the doctor cc/c++
   hints now lead with the gcc payload sideload (756fc92) and the
   same-version blob-swap refusal is gone — content hash is the
   identity, replacement runs the full gate chain (b8afa43).

State left behind: gate pod provisioned with linux-headers, libgcc,
glibc (soname ld scripts), rust 1.97.1 (round 8 re-pin), gcc 14.2.0
(post-77964ae c++ shim) — generation 39.

## Round 9 (2026-09-23, post-#174/#171 gcc re-sideload, debug build) — uapi ownership lands pod-side

The gate pod's gcc blob was swapped twice the same day the recipes changed:
`a25b9270…` (pre-#174, carried linux-libc-dev uapi) → `62cf65b8…` (#174 drop +
#171 deb sets, 95cdccb) → `d9b2bffc…` (CPATH shim repair below). Generation 41.
Same-version blob swaps ran the documented content-identity path; rollback
across a swap reactivates content the blob pin no longer names (tool prints
the caveat).

Round-4 acceptance `shuttle run --pod gate -- cargo build --locked` FAILED on
`62cf65b8…`: every C++ TU died with `c++/14/cstdlib:79: fatal error:
stdlib.h: No such file or directory`. Root cause: `#include_next` only
searches dirs AFTER the C++ headers; the #171 shim rewrite dropped the gen-39
shim's CPATH→`-idirafter` translation, so the farm wrapper's CPATH (glibc's
include root among them) entered at `-I` position — unreachable by
include_next. Restored in the gcc.lua shim heredoc (with the empty-segment
guard); rebuild + re-sideload; acceptance green (1m35s) and a C++
cstdlib/string probe compiles, links, and runs pod-side.

Verified on `d9b2bffc…`: gcc payload stages NO uapi (`asm-generic` absent —
single farm-wide owner is linux-headers, so the CPATH-glob ambiguity recorded
in the #174 council review is gone); `<linux/errno.h>` + `<asm/unistd.h>`
compile and run through the pod cc (EAGAIN=11); cc/c++ resolve to the
payload's Debian 14.2.0. The 62cf65b8 finding is a lesson for payload shim
rewrites: any script that touches include-path translation must be exercised
with a C++ TU against libstdc++ before landing — the deb builds in the lane
were pure C and never reached the chain.

## Round 10 (2026-09-26, secrets @ 207021f, debug build) — pod secrets live, values never print

The #182-#186 secret-sources series went live on the gate pod: one real
Bitwarden reference declared, resolved through `bws` host-side, and the
whole round's transcripts carry zero value bytes. Executed 2026-09-26,
shuttle built from this repo at 207021f (the secrets series landed);
issue #187's dogfood leg.

1. **Declaration.** `gate`'s `pod.lua` gained one reference:

       secrets = { GH_TOKEN = { source = "bitwarden", id = "378c3347-1667-4341-8312-b49f01887394" } }

2. **Sync — references only.** `shuttle pod --name gate sync`
   re-presented generation 41 with all pins held (a secrets edit is
   not a package change). The staging tail wrote
   `generations/41/secrets.json`, mode 0600 — canonical, ref-only
   JSON (the `id` is a reference, not a value):

       {"GH_TOKEN":{"source":"bitwarden","id":"378c3347-1667-4341-8312-b49f01887394"}}

3. **Cache lifecycle.** `pod secrets list` before any resolve → the
   GH_TOKEN row shows `miss`; after the run below it shows `hit`.
   Values never print — the list footer says so verbatim. The cache
   entry landed at `$XDG_RUNTIME_DIR/shuttle/secrets/gate/<decl-hash>.json`
   (0600; the decl-hash is the SHA-256 of the `secrets.json` bytes
   above, and the cache key drops the generation on purpose).

4. **Live resolve (the acceptance).** From this tree:

       $ shuttle run --pod gate -- sh -c 'test -n "$GH_TOKEN" && echo LIVE_RESOLVE_OK'
       LIVE_RESOLVE_OK

   Exit 0, stdout exactly `LIVE_RESOLVE_OK` — the non-empty check
   proves the token arrived without printing it. The bitwarden resolve
   ran host-side through `bws` (the binary lives in the *daily* pod,
   outside the gate pod's state root, so the D4 host-PATH scrub leaves
   it alone), and the token entered only the child process env.

5. **Verbs.** `pod secrets check` → `ok` row for GH_TOKEN, exit 0.
   `pod secrets refresh` reported "dropped 1 cached entry" and
   "resolved 1 secret(s) from [bitwarden=1]" — rotation pickup with no
   new generation, per the ADR-0042 services contract.

6. **Masking assertion.** The sync/run/list/check/refresh transcripts
   carry zero value bytes — the only byte that could be a value is the
   one the run printed, and that is `LIVE_RESOLVE_OK`, not the token.

Honest deviations, both recorded rather than smoothed over:

- **Rotation and rollback re-scope were proven by the landed test
  suite, not a second live pod**: `refresh_busts_the_cache_and_rewrites_the_entry`
  (rotation-without-new-generation), the generation-riding entry body
  plus the cache-key-drops-generation tests (rollback re-scope), and
  `present_active_records_declared_secrets_on_staging` (the ref-only
  record). A fresh-pod live leg was attempted and stalled >10 minutes
  on a cold build queue under session load — an infra flake tracked
  separately, not a secrets defect; the gate pod's own sync was
  unaffected.
- **The INSTALLED shuttle binary (0.1.0, pre-secrets) rejects the new
  declaration** with `unknown field 'secrets'` — correct fail-closed
  behavior for a binary from before the surface existed. The round ran
  the freshly built repo binary; installed fleets pick the surface up
  at their next rebuild.

