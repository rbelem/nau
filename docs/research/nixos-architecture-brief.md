# NixOS Architecture — How It Is Built and How It Works

> **Purpose:** Dense reference on NixOS's system architecture — the store, derivation pipeline, module system, and activation model — as design input for shoot's eval → build pipeline (Lua DSL → snap IR → `.snap`).
> **Sources:** nixos.org (26.05 release notes, Nix manual), official NixOS wiki (wiki.nixos.org), nixpkgs repo structure, snapd-adjacent ecosystem knowledge. Written August 2026; covers NixOS 26.05, Nix 2.2x.
> **Companion reports:** `docs/nix-language-design-lessons.md` (language layer: what to borrow/avoid), `.planning/ubuntu-core-build-brief.md`, `.planning/fedora-silverblue-build-brief.md` (competing declarative systems), `docs/gap-analysis-snapcraft-nix.md` (Snap↔Nix mapping).

---

## 1. The Core Model

NixOS is a **pure function from configuration to a running system**:

```
configuration.nix ──eval──▶ derivations ──build──▶ /nix/store closure ──activate──▶ running OS
```

No package manager mutates `/usr`. The entire OS is an immutable tree of symlinks into one directory (`/nix/store`), and "installing" means building a new tree and flipping one symlink. Atomic upgrades, instant rollbacks, and coexisting versions all fall out of this; none are implemented separately.

## 2. Layer 1 — The Nix Language

Lazy, purely functional expression language whose sole output is **attribute sets** (JSON-like records). See `docs/nix-language-design-lessons.md` for the full design critique. What matters architecturally:

- **Purity by restriction:** expressions can only reference their inputs — no clock, no filesystem, no network. Same inputs → same output, enforced.
- **Laziness:** unused attributes never evaluate. This is how nixpkgs keeps ~80k packages in scope cheaply.
- **Not a build system:** it *describes* builds; the builds run as bash scripts.

## 3. Layer 2 — Derivations and the Store

**Derivation** = the intermediate representation: a `.drv` file in the store specifying inputs, builder script, environment, and output paths. This is the layer that makes remote builds, binary caches, and GC possible — the IR is explicit, serializable, and content-addressed.

**The store** (`/nix/store/`) is the heart of the system:

| Property | Mechanism | Consequence |
|---|---|---|
| Address = hash of inputs | Path is `/nix/store/<hash>-<name>`, digest of derivation inputs | Output path known *before* building; two versions of a package are different directories, never conflict |
| Immutability | Nothing writes into a built store path | Old generations stay valid; rollback is a symlink flip |
| Dependency tracking | Literal path references (ELF `RPATH` → `/nix/store/hash-glibc-.../lib`) | No `LD_LIBRARY_PATH`; garbage collection computes exact reachability |
| Purity | Builds run in kernel-enforced sandbox (namespaces): empty env, restricted PATH, no network | Purity is enforced, not conventional — except fixed-output derivations (see §9) |

**Fixed-output derivations** (`fetchurl` etc.): the only network-permitting builds; their path is addressed by declared content hash instead of inputs. This is the classic purity hole.

## 4. Layer 3 — nixpkgs (the Package Collection)

- **`stdenv` + `mkDerivation`:** standard build harness driving generic phases — `unpack → patch → configure → build → check → install → fixup` — with auto-detection (make/cmake/meson) and setup hooks. A trivial package derivation is ~4 lines.
- **`pkgs/by-name/`:** one directory per package (`pkgs/by-name/fo/foo/package.nix`), auto-discovered. Replaced most of the old monolithic `all-packages.nix`.
- **Overridability:** every package is a function `input-set → derivation`; `hello.override { stdenv = ...; }` rebuilds with different inputs. Composability that purity buys.
- **Cross-compilation:** input set distinguishes `buildPlatform` / `hostPlatform` / `targetPlatform`; downstream adapts automatically.

## 5. Layer 4 — The NixOS Module System

The mechanism that turns user config into a system. Config is never a monolith — it is declared as **options** and **merged configurations**:

```nix
# a module = { options, config }
options.services.nginx.enable = mkOption { type = types.bool; default = false; };
config = mkIf cfg.enable {
  systemd.services.nginx = { ... };
  environment.systemPackages = [ nginx ];
};
```

Evaluation order of operations:

1. Collect all modules (user's + ~2,000 in `nixos/modules/`).
2. Merge every `config` per option via `mkMerge` (typed deep merge); resolve `mkIf` conditionals and `mkOverride` priorities.
3. Type-check the merged option set.
4. Generator functions turn resolved config into derivations: kernel + initrd, systemd unit files, `/etc` contents (`environment.etc`), users, `system-path`.
5. Output: `system.build.toplevel` — **the derivation whose output is a complete bootable OS**.

Key insight for shoot: independent modules contribute to shared options and merge — nobody edits a central config file. This is why NixOS features compose.

## 6. Layer 5 — What `nixos-rebuild switch` Actually Does

1. **Evaluate** `configuration.nix` (or `flake.nix#nixosConfigurations.<host>`) → `toplevel.drv`.
2. **Realise** (build) it. Anything already in the store is reused — usually most of it, hence fast rebuilds.
3. **Activate:** `switch-to-configuration` diffs old vs new systemd units (stop removed, restart changed, start added), then **atomically flips** the profile symlink `/nix/var/nix/profiles/system` → new toplevel. Atomicity = single `rename()`.
4. **Register** a new generation + bootloader entry.

## 7. Generations, Rollback, GC

- `/run/current-system` → profile `system-N` → toplevel closure; bootloader lists every generation.
- **Rollback = boot a previous symlink target.** The old closure still exists untouched in the store, so rollback is instant and total (kernel, initrd, config, packages).
- `nix-collect-garbage` deletes paths unreachable from any GC root (profiles are roots). Exact path-reference tracking makes GC safe while the system runs.

## 8. What the Toplevel Contains (system closure anatomy)

| Component | Producer | Role |
|---|---|---|
| kernel + initrd | `boot.*` options | Boot generations independently of the running system |
| `etc/` tree | `environment.etc` | Conventional `/etc`, but generated and versioned |
| systemd units | `systemd.services.*` et al. | Unit files written per-service, wiring deps |
| `system-path` | `environment.systemPackages` | The user-visible `$PATH` union |
| activation script | generated | Idempotent imperative fix-ups that can't be pure (mkdir /var/lib, perms) |
| `switch-to-configuration` | generated | The diff+restart+symlink-flip driver |

## 9. Reproducibility: Honest Limits

- Inputs-hash → output-path gives **deterministic addressing**, but builds can still be non-reproducible (timestamps, parallelism). Mitigations: `SOURCE_DATE_EPOCH`, `--check` rebuild verification.
- Content-addressed derivations (rolled out through Nix 2.2x): bit-identical outputs get content-hashed paths, so identical builds dedupe even when input hashes differ. Still limited to supported output types.
- FODs (downloads) are trusted by content hash only — supply-chain surface remains.
- Reproducibility is a **runtime/store property, not a language property** (central thesis of `docs/nix-language-design-lessons.md`).

## 10. Ecosystem State (August 2026)

- **NixOS 26.05** is current (May 2026 release).
- **Flakes:** pin every input via `flake.lock`, uniform project layout (`inputs`/`outputs`). Officially still "experimental"; CLI long-stable and the de-facto standard for real infrastructure. `system.nix` added as an alternative entry point (no channel, no flake).
- **Nix:** 2.2x line; content-addressed derivations maturing, parallel/distributed builds supported.
- **Deployment:** colmena, deploy-rs, `nixos-rebuild --target-host` — all ship built closures over SSH; NixOps effectively legacy.

## 11. Relevance to shoot

NixOS's architecture is three decoupled layers — the same shape shoot should keep:

| Nix | shoot |
|---|---|
| Nix language (declarative, functional) | Lua DSL |
| Evaluation → derivations (typed, serializable IR) | Rust core: Lua eval → snap manifest IR |
| Realisation (sandboxed build → store) | mksquashfs + metadata assembly → `.snap` |

**Lessons to steal:**

1. **Explicit serializable IR** — the `.drv` file is why Nix gets remote builds, caching, and GC for free. shoot's manifest IR should be dumpable/diffable (`shoot eval -o manifest.json`) even if v1 only consumes it locally.
2. **Name outputs by content of inputs; never mutate** — Nix never overwrites a store path. For shoot: don't mutate in-progress build dirs across runs; key intermediates by manifest hash.
3. **Merge configs from independent modules** — the option/merge system is why NixOS composes; a monolithic Lua config won't. Lua metatables can implement a `mkMerge`-style deep merge.
4. **Enforce purity by sandboxing, not by trusting the DSL** — the language can't guarantee reproducibility; the runtime constraints do. For shoot: control Lua's `io`/`os` exposure in the eval sandbox, and control mksquashfs inputs to declared sources.
5. **Generations are cheap** — because nothing is mutated. Even shoot-local: keep prior `.snap` outputs keyed by manifest hash; "rollback" is then trivial.

**Divergence to note:** snaps are self-contained artifacts distributed via a central Store with its own lifecycle (refresh, channels, assertions) — shoot must reconcile Nix's local-closure model with Snap's artifact/distribution model. Covered in `docs/gap-analysis-snapcraft-nix.md`.
