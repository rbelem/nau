use clap::{Parser, Subcommand};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::boot_test::Accel;

#[derive(Parser)]
#[command(
    name = "nau",
    version,
    about = "Build Snap packages from Lua declarations",
    long_about = "Build Snap packages from Lua declarations.

Unknown verbs fall through to `nau-<verb>` executables — a sibling of
the nau binary first, then PATH (git-style extensibility).",
    allow_external_subcommands = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Chart: define & resolve (ADR-0049) — the definition lifecycle:
    /// check, eval, lock, lint, audit, search, index, deps, plus the
    /// two internal workers in their revealed forms.
    Chart {
        #[command(subcommand)]
        command: ChartCommand,
    },

    /// Build a snap from a Lua declaration, or manage the binary
    /// package cache (ADR-0049): `nau build snap` is the build,
    /// `nau build cache` the cache verbs. The build's own arguments are
    /// also accepted directly on `build` — the pre-0049 spelling, kept
    /// working beside the namespace.
    Build {
        #[command(flatten)]
        args: BuildArgs,

        #[command(subcommand)]
        command: Option<BuildCommand>,
    },

    /// Build, test, and verify system images (ADR-0049): `nau image
    /// build` builds from pinned snaps, `nau image test` boots one in
    /// QEMU and asserts the boot, `nau image verify` checks a flashed
    /// target against its signed manifest. The build's own arguments are
    /// also accepted directly on `image` — the pre-0049 spelling, kept
    /// working beside the namespace.
    Image {
        #[command(flatten)]
        args: ImageArgs,

        #[command(subcommand)]
        command: Option<ImageCommand>,
    },

    /// Manage the package index (list, add, resolve) — legacy hidden
    /// alias of `chart index` (ADR-0049).
    #[command(subcommand, hide = true)]
    Index(IndexCommand),

    /// Show dependency tree for a package, or fetch dependency closures
    /// for interpreted packages (ADR-0017, issue #13) — legacy hidden
    /// alias of `chart deps` (ADR-0049).
    #[command(subcommand, hide = true)]
    Deps(DepsCommand),

    /// Search available packages by name or keyword — legacy hidden
    /// alias of `chart search` (ADR-0049).
    #[command(hide = true)]
    Search(SearchArgs),

    /// Check system readiness (required tools). The default gates the
    /// full surface; --pod gates only what the pod verbs need (issue #97).
    Doctor {
        /// Gate only the pod surface (pod tools + build toolchain) —
        /// image tools like ukify are not required on pod-only machines.
        /// Takes an optional pod NAME (`--pod work`): with a name, the
        /// doctor additionally scans the pod's recorded units for the
        /// D3 boot story — failed units whose secret envfile died with
        /// the tmpfs — and names `pod secrets refresh` as the fix
        /// (issue #231).
        #[arg(long, value_name = "POD", num_args = 0..=1)]
        pod: Option<Option<String>>,

        /// Provision the floor tools first (issue #101 disposition (c)),
        /// then re-run the pod check section as the post-fix table.
        /// Explicit consent — doctor never auto-provisions without it.
        #[arg(long)]
        fix: bool,

        /// With --fix: provision from a local directory of pre-fetched
        /// artifacts (offline; identical sha256 verify path) instead of
        /// the pinned release URLs.
        #[arg(long)]
        from: Option<String>,
    },

    /// Validate a Lua definition without building: bounded subprocess eval
    /// plus Rust-side schema checks, printing every diagnostic (ADR-0010
    /// Decisions 2-3). The fast AI feedback-loop entry point — legacy
    /// hidden alias of `chart check` (ADR-0049).
    #[command(hide = true)]
    Check(CheckArgs),

    /// Lint declarations: a battery of package/image/pod checks beyond the
    /// leak scan (issue #53). Every finding carries the check name, the
    /// package, a severity, and a one-line fix hint. Exits nonzero only on
    /// errors, never warnings. Fully offline: index/lockfile data only.
    /// Legacy hidden alias of `chart lint` (ADR-0049).
    #[command(hide = true)]
    Lint(LintArgs),

    /// Audit lockfile pins against the OSV vulnerability database (issue
    /// #52). Source and dependency pins are version-matched (confirmed
    /// hits are errors); store snaps are name-only (hits are warnings —
    /// the lockfile pins store revisions, not upstream versions).
    /// Online-first with a local response cache; offline it degrades to a
    /// named stale-database warning, never a hard failure. Exits nonzero
    /// only on confirmed findings. Legacy hidden alias of `chart audit`
    /// (ADR-0049).
    #[command(hide = true)]
    Audit(AuditArgs),

    /// Resolve and refresh all input pins in the lockfile (no build).
    /// Pins each github input to its current branch head and records a
    /// content hash; `path:` inputs are marked local (unlocked).
    /// Legacy hidden alias of `chart lock` (ADR-0049).
    #[command(hide = true)]
    Lock(LockArgs),

    /// Evaluate a definition and emit the image manifest IR (no build).
    /// Deterministic: the same definition + lockfile always produce
    /// byte-identical JSON. Resolution is data-only (definition pins,
    /// lockfile, package index) — fully pinned projects eval offline; the
    /// --offline flag additionally forbids fetching uncached inputs.
    /// Legacy hidden alias of `chart eval` (ADR-0049).
    #[command(hide = true)]
    Eval(EvalArgs),

    /// List upstream versions for a definition's snap outputs via the
    /// eval worker's versions-mode (ADR-0052 Decisions 1-2). A snap
    /// without a versions method is a named skip, not an error.
    /// Legacy hidden alias of `chart versions` (ADR-0049).
    #[command(hide = true)]
    Versions(VersionsArgs),

    /// Generate shell completion scripts
    Completion {
        /// Shell to generate completions for (bash, zsh, fish, powershell, elvish)
        shell: clap_complete::Shell,
    },

    /// Push built artifacts (`.snap`/`.img`) to an OCI registry as one
    /// OCI image manifest bundle (Phase 25). Blobs are sha256-content-
    /// addressed; blobs already in the registry are skipped. Legacy
    /// hidden alias of `ship push` (ADR-0049).
    #[command(hide = true)]
    Push(PushArgs),

    /// Pull an artifact bundle from an OCI registry: fetch the manifest,
    /// download every blob with sha256 verification (fail-closed on any
    /// mismatch), and write the files under their original names.
    ///
    /// Sharing lanes (ADR-0033): a `nau://host[:port]/<pkg>`
    /// reference pulls from a peer and an `http(s)://…/<pkg>` reference
    /// from a static export tree — both verify the signed
    /// PackageManifest fail-closed and stage into the pod named by
    /// `--pod` instead of writing files. Legacy hidden alias of
    /// `ship pull` (ADR-0049).
    #[command(hide = true)]
    Pull(PullArgs),

    /// Serve the pod store to LAN peers over a minimal HTTP/1.1 subset
    /// (ADR-0033 Decisions 4+5): `GET /info`, `GET /manifests/<pkg>`,
    /// `GET /blobs/<sha256>`. Runs in the foreground until interrupted;
    /// unsigned store entries are never served. Binding and announce
    /// policy come from `node {}` in nau.lua — absent `node {}`,
    /// the loopback default applies and nothing is announced. Legacy
    /// hidden alias of `peer serve` (ADR-0049).
    #[command(hide = true)]
    Serve(ServeArgs),

    /// Browse the LAN for announcing nau peers (ADR-0033 Decision
    /// 3): mDNS `_nau._tcp.local.` for a bounded window, printing
    /// every node found. Discovery only, never trust — pulls still
    /// verify every manifest fail-closed (ADR-0033 Decision 7). Legacy
    /// hidden alias of `peer browse` (ADR-0049).
    #[command(hide = true)]
    Peers(PeersArgs),

    /// Export the pod store's shareable content as a static directory
    /// tree any web server can serve (ADR-0033 Decision 10):
    /// `index.json` (the `/info` payload), `manifests/<pkg>.json`
    /// (signed PackageManifests), `blobs/<sha256>`. Upload the directory
    /// to publish — no nau code runs server-side. Legacy hidden alias of
    /// `peer export` (ADR-0049).
    #[command(hide = true)]
    Export(ExportArgs),

    /// Ask a farm server to build a version, and drain the farm's
    /// build-request queue (ADR-0052 Decisions 4+6): `submit` POSTs an
    /// identity (never build text) to a token-gated server; `run` is
    /// the farm-side loop that claims requests, re-evaluates the farm's
    /// own recipes, builds via the worker pool, and releases to the
    /// static tree.
    BuildRequest {
        #[command(subcommand)]
        command: BuildRequestCommand,
    },

    /// Manage the binary package cache — legacy hidden alias of
    /// `build cache` (ADR-0049).
    #[command(subcommand, hide = true)]
    Cache(CacheCommand),

    /// Key ceremony (ADR-0011 step (e), ADR-0024 §4): generate, rotate,
    /// promote, and revoke the update-manifest signing keys. The operator
    /// surface over `~/.config/nau/` (secret-key, secret-key.new,
    /// keys/<id>.pub) and the local `keys/revoked-keys` list. Legacy
    /// hidden alias of `trust key` (ADR-0049).
    #[command(subcommand, hide = true)]
    Key(KeyCommand),

    /// SSH host CA ceremony (ADR-0045 amendment, #283 decided): generate
    /// and introspect the coordinator CA that signs workers' short-lived
    /// host certificates. A trust root DISTINCT from the update-manifest
    /// signing key (`nau key`); the keypair lives under
    /// `~/.config/nau/ca/` (`ca` 0600 private, `ca.pub` public — the
    /// future `@cert-authority` line). Legacy hidden alias of
    /// `trust ca` (ADR-0049).
    #[command(subcommand, hide = true)]
    Ca(CaCommand),

    /// Ship: distribute (ADR-0049) — push and pull OCI artifact
    /// bundles.
    Ship {
        #[command(subcommand)]
        command: ShipCommand,
    },

    /// Peer: LAN sharing (ADR-0049, ADR-0033) — serve the pod store,
    /// browse announcing peers, export a static tree.
    Peer {
        #[command(subcommand)]
        command: PeerCommand,
    },

    /// Trust: the ceremony domain (ADR-0049) — the key-ceremony verbs
    /// flattened one level: keygen, rotate, promote, revoke, list,
    /// verify. `--ca` scopes keygen/list to the SSH host CA ceremony.
    Trust {
        #[command(subcommand)]
        command: TrustCommand,
    },

    /// Pool: the build-worker fleet (ADR-0049, as amended by the #321
    /// council — `pool` replaces ADR-0040's "farm" naming, which already
    /// belongs to the pod bin farm) — provision, destroy, burst, down,
    /// issue, publish, pickup, plus the worker-side probe and job verbs.
    Pool {
        #[command(subcommand)]
        command: PoolCommand,
    },

    /// Manage on-device installs: generations + file-level content store
    /// (ADR-0012 step 5, Phase 24b). Operates on a state root (default
    /// /var/lib/nau) holding generations/, store/ blobs, and the
    /// `active` symlink.
    #[command(subcommand)]
    Runtime(RuntimeCommand),

    /// Manage user-level pods (CONTEXT.md: Pod). `nau pod [--name <n>]
    /// <verb>`: imperative edits to one pod's declaration + lockfile pins,
    /// reconciled into that pod's store, generation chain, and bin farm.
    /// `--name` selects the pod (default: `default`) and is accepted before
    /// or after the verb; `add` initializes an unknown pod, read verbs fail
    /// on unknown pods. Rollback and GC are pod-scoped — system generations
    /// are never touched.
    Pod {
        /// Pod to operate on (default: `default`). Belongs to the `pod`
        /// command itself, so it goes before the verb:
        /// `nau pod --name work add jq`. Every verb also accepts it
        /// after the verb (see `PodTarget`); the two positions must agree.
        #[arg(long, value_name = "POD")]
        name: Option<String>,

        #[command(subcommand)]
        command: PodCommand,
    },

    /// Run an app from a pod (ADR-0016, ticket #11). Two forms,
    /// dispatched declared-app-first:
    ///
    /// Declared app — `nau run [--pod N] <app> [args…]`: resolve the
    /// app's declared grants, set up the sandbox with the chosen backend,
    /// then exec the app — transparent to the user (the pod's `current`/
    /// bin farm symlink points at a wrapper that invokes this). A
    /// `confined` app on a host where the backend is unavailable FAILS
    /// CLOSED (never silently runs unconfined).
    ///
    /// Arbitrary command — `nau run [--pod N] -- <cmd…>` (issue
    /// #102): exec any command with the pod's env overlaid (farm-first
    /// PATH + loader-lib LD_LIBRARY_PATH), no sandbox. Declared-first
    /// order: a name that IS a declared app always wins, so
    /// `nau run -- <declared-app>` runs the declared app (confined),
    /// not the command.
    ///
    /// TRUST BOUNDARY: the command form runs unsandboxed with the
    /// caller's full privileges, and farm names shadow host PATH — it
    /// trusts the pod's content the way the caller trusts their own
    /// `~/.local/bin`. Confinement stays the declared-app path.
    ///
    /// `--pod` selects the pod (default: `default`). Also the future
    /// home for env hooks.
    ///
    /// Hidden under ADR-0049: legacy hidden alias of `pod run` (ADR-0049)
    /// — the spelling keeps working through the window, dispatching to
    /// the identical handler over the shared [`RunArgs`].
    #[command(trailing_var_arg = true, hide = true)]
    Run {
        #[command(flatten)]
        args: RunArgs,
    },

    /// Boot a built disk image in QEMU and assert the boot actually
    /// COMPLETED (issue #84), not merely reached userspace: the programmatic
    /// "did the image boot?" proof behind try-boot/revert — exits non-zero
    /// and archives the serial console as evidence when the assertion fails.
    ///
    /// Success requires no kernel panic, a userspace marker, the
    /// `NAU-INIT: switch-root` line nau's own `/init` prints after it
    /// opens dm-verity and hands PID 1 to systemd, and a COMPLETION signal:
    /// a `Reached target Boot Completion Check` line (A/B images with the
    /// try-boot machinery) or a completed `default.target` (`Reached target
    /// Multi-User System` / `Reached target Graphical Interface`). The
    /// handoff alone is a liveness assertion and passes broken boots —
    /// emergency.target reboots, console-conf stalls, failed oneshots — so a
    /// boot that never reaches a completed target FAILS, including a boot
    /// killed by `--timeout` after the markers were written. Pass
    /// `--allow-no-completion` only for images that legitimately never reach
    /// a completed target.
    ///
    /// `--require` tightens further; for an A/B image the strongest
    /// assertion is `--require "Reached target Boot Completion Check"`.
    ///
    /// `--runs N` boots the image N times in sequence, and
    /// `--expect-counter-seq` asserts the systemd-boot try-boot counters
    /// observed on the ESP before each boot (issue #77).
    ///
    /// Legacy hidden alias of `image test` (ADR-0049).
    #[command(hide = true)]
    Test(TestArgs),

    /// Verify a flashed mission image against its signed manifest
    /// (ADR-0044 D4). Read-only and unprivileged: reads the target's GPT
    /// and dm-verity hash regions, recomputes them against the published
    /// signed image manifest, and refuses by name on any mismatch. This
    /// verb has no write path. Legacy hidden alias of `image verify`
    /// (ADR-0049).
    #[command(hide = true)]
    VerifyImage(VerifyImageArgs),

    /// Internal: evaluation worker process (hidden). Re-executed by the
    /// parent to evaluate untrusted definitions in a bounded subprocess
    /// (ADR-0010 Decisions 4+5). Not part of the public CLI.
    #[command(name = "__eval-worker", hide = true)]
    EvalWorker,

    /// Internal: analyzer worker process (hidden). Re-executed by the parent
    /// to run the strict-analyzer gate over untrusted definitions in a
    /// bounded subprocess (containment parity with `__eval-worker`). Not
    /// part of the public CLI.
    #[command(name = "__check-worker", hide = true)]
    CheckWorker,

    /// Internal: build-farm worker capability probe (hidden). Prints one
    /// JSON capability document (protocol, arch, nproc, RAM, free disk,
    /// tool presence, functioning-sandbox and KVM probes) on stdout, then
    /// exits (ADR-0040 Decision 2). Not part of the public CLI.
    #[command(name = "__worker-cap", hide = true)]
    WorkerCap,

    /// Internal: build-farm worker job executor (hidden). Executes exactly
    /// one job manifest — verifies every payload sha256, then runs the
    /// ordinary offline sandbox build path — and prints one JSON result
    /// document on stdout (ADR-0040 Decision 2). Any refusal exits nonzero
    /// before anything runs. Not part of the public CLI.
    #[command(name = "__worker-job", hide = true)]
    WorkerJob {
        /// Path to the job manifest file.
        job_file: String,
    },

    /// Manage build-farm workers (ADR-0040): provision cloud workers
    /// (mint + inject + pin the host key per ADR-0045) or destroy them.
    /// Legacy hidden alias of `pool` (ADR-0049).
    #[command(hide = true)]
    Workers {
        #[command(subcommand)]
        command: WorkersCommand,
    },

    /// External-subcommand catch-all (ADR-0049 Decision 5): an unknown
    /// verb lands here ONLY after every real variant — the public domain
    /// groups, the hidden legacy spellings, and the hidden `__*` workers
    /// — has had its chance to match. Element 0 is the verb itself; the
    /// rest is the remaining argv, forwarded verbatim to a `nau-<verb>`
    /// executable (exe-dir sibling first, then PATH — never an
    /// environment override). Dispatched by [`run_external`].
    #[command(external_subcommand)]
    External(Vec<OsString>),
}

// ── Domain namespaces (ADR-0049) ────────────────────────────────────
//
// Each legacy top-level command's fields live in one `clap::Args`
// struct, shared verbatim by the legacy hidden spelling (a tuple
// variant of [`Command`]) and the domain namespace's verb. Both
// spellings parse to the same struct; `From<$group> for Command` folds
// the namespace parse onto the legacy variant so main() dispatches
// every command through one match.

/// The `nau build` / `nau build snap` arguments (ADR-0049).
#[derive(clap::Args)]
pub struct BuildArgs {
    /// Path to the Lua config file (default: nau.lua)
    #[arg(short, long, default_value = "nau.lua")]
    pub file: String,

    /// Directory containing pre-built binaries (default: ./stage/).
    /// The default ./stage/ is nau-managed: wiped before every
    /// build phase so stale files cannot leak into a snap. A directory
    /// passed explicitly via --stage is never wiped — it must be empty
    /// (or new), or the build is refused.
    #[arg(short, long)]
    pub stage: Option<String>,

    /// Output directory for the .snap file (default: current dir)
    #[arg(short, long, default_value = ".")]
    pub output: String,

    /// Build only for specific architecture(s). Repeat for multiple.
    /// Default: build for all architectures declared in the config.
    #[arg(short = 'A', long)]
    pub arch: Vec<String>,

    /// Output name to build (from nau.lua outputs table).
    /// Default: build all outputs.
    pub output_name: Option<String>,

    /// Reproducible timestamp for SquashFS (Unix epoch seconds).
    /// Also read from SOURCE_DATE_EPOCH environment variable.
    /// Default: current time (non-reproducible).
    #[arg(long)]
    pub source_date_epoch: Option<String>,

    /// Path to lockfile (default: nau.lock).
    /// Locks source hashes for reproducible builds.
    #[arg(long, default_value = "nau.lock")]
    pub lockfile: String,

    /// Print dependency build order and exit (no build).
    #[arg(long)]
    pub order: bool,

    /// Build all transitive dependencies before building the requested output(s).
    /// Deps are built in topological order and stored in the binary cache.
    /// Use --cache to control where cached builds are stored.
    #[arg(long)]
    pub all: bool,

    /// Binary cache directory for built packages (default: ~/.cache/nau/pkgs).
    /// Cached builds are keyed by source SHA-256, so rebuilds only happen when
    /// source changes. Combine with --all to build full dependency trees efficiently.
    #[arg(long)]
    pub cache: Option<String>,

    /// Maximum cache size (e.g. "500M", "2G"). When exceeded, oldest entries
    /// are pruned automatically. Only applies when --cache is set or --all is used.
    #[arg(long)]
    pub cache_max_size: Option<String>,

    /// Override cross-compilation target for all packages.
    /// Sets the GNU target triplet (e.g. "aarch64-linux-gnu") and exports
    /// CC/CXX/LD/AR environment variables in the build sandbox.
    /// Overrides the `target` field on individual snap() declarations.
    #[arg(long)]
    pub target: Option<String>,

    /// Re-resolve input(s) to their latest branch head and update the
    /// lockfile pins before building. Pass an input name to update one
    /// input; omit the value to update all inputs.
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    pub update: Option<String>,

    /// Use only cached/locked inputs — never touch the network.
    #[arg(long)]
    pub offline: bool,

    /// Output structured JSON instead of human-friendly colored output.
    /// Useful for tooling, CI, or machine parsing.
    #[arg(long)]
    pub json: bool,
}

/// Verbs for `nau build` (ADR-0049).
#[derive(clap::Subcommand)]
pub enum BuildCommand {
    /// Build a snap from a Lua declaration file
    Snap(Box<BuildArgs>),

    /// Manage the binary package cache
    #[command(subcommand)]
    Cache(CacheCommand),
}

/// The `nau image` / `nau image build` arguments (ADR-0049).
#[derive(clap::Args)]
pub struct ImageArgs {
    /// Path to the Lua config file (default: nau.lua)
    #[arg(short, long, default_value = "nau.lua")]
    pub file: String,

    /// Output directory for the .img file (default: current dir)
    #[arg(short, long, default_value = ".")]
    pub output: String,

    /// Target architecture
    #[arg(short, long, default_value = "amd64")]
    pub arch: String,

    /// Snap channel to use for store queries (default: latest/stable)
    #[arg(long, default_value = "latest/stable")]
    pub channel: String,

    /// Cache directory for downloaded snaps (default: ~/.cache/nau/snaps)
    #[arg(long)]
    pub cache: Option<String>,

    /// Maximum cache size (e.g. "500M", "2G"). Auto-prunes oldest entries.
    #[arg(long)]
    pub cache_max_size: Option<String>,

    /// Image output name to build (from nau.lua images table).
    /// Default: build the first image found.
    pub output_name: Option<String>,

    /// Reproducible timestamp for SquashFS (Unix epoch seconds).
    /// Also read from SOURCE_DATE_EPOCH environment variable.
    #[arg(long)]
    pub source_date_epoch: Option<String>,

    /// Release mode (ADR-0044 D5/D8, #266): publish the deterministic
    /// media set — nau-<mission>-<version>-<arch>.img + the SIGNED
    /// .manifest.json + SHA256SUMS, plus the sysupdate transfer
    /// payloads signed into those sums (#274) when the image declares
    /// an update_source — into this ADR-0033 D10 export
    /// tree directory. Requires a pinned SOURCE_DATE_EPOCH, an
    /// explicit --arch, exactly one disk image (--output-name), and
    /// the operator signing key (`nau key keygen`). Replaces
    /// --output as the destination.
    #[arg(long, value_name = "DIR", conflicts_with = "output")]
    pub release: Option<String>,

    /// Path to lockfile (default: nau.lock).
    #[arg(long, default_value = "nau.lock")]
    pub lockfile: String,

    /// Output structured JSON instead of human-friendly colored output.
    #[arg(long)]
    pub json: bool,
}

/// Verbs for `nau image` (ADR-0049).
#[derive(clap::Subcommand)]
pub enum ImageCommand {
    /// Build a system image from pinned snaps
    Build(ImageArgs),

    /// Boot a built disk image in QEMU and assert the boot completed
    /// (the `nau test` harness)
    Test(TestArgs),

    /// Verify a flashed mission image against its signed manifest
    /// (the `nau verify-image` surface)
    Verify(VerifyImageArgs),
}

/// Verbs for `nau chart` (ADR-0049): the definition lifecycle — check,
/// eval, lock, lint, audit, search, index, deps — plus the two internal
/// workers in their revealed forms.
#[derive(clap::Subcommand)]
pub enum ChartCommand {
    /// Validate a Lua definition without building: bounded subprocess eval
    /// plus Rust-side schema checks, printing every diagnostic (ADR-0010
    /// Decisions 2-3). The fast AI feedback-loop entry point.
    Check(CheckArgs),

    /// Evaluate a definition and emit the image manifest IR (no build).
    /// Deterministic: the same definition + lockfile always produce
    /// byte-identical JSON.
    Eval(EvalArgs),

    /// List upstream versions for a definition's snap outputs (ADR-0052
    /// Decisions 1-2): one bounded eval in versions-mode calls each snap
    /// output's `versions()` in-process and prints output / version /
    /// available with the recipe-resolved version marked `latest`. A snap
    /// without a versions method is a named skip, not an error.
    Versions(VersionsArgs),

    /// Advanced: invoked by nau itself. The bounded evaluation worker the
    /// parent re-executes via `current_exe()` to evaluate untrusted
    /// definitions (ADR-0010 Decisions 4+5) — the revealed form of the
    /// hidden `__eval-worker` alias. Not an operator surface.
    EvalWorker,

    /// Advanced: invoked by nau itself. The bounded analyzer worker the
    /// parent re-executes for the strict-analyzer gate (containment
    /// parity with `chart eval-worker`) — the revealed form of the
    /// hidden `__check-worker` alias. Not an operator surface.
    CheckWorker,

    /// Resolve and refresh all input pins in the lockfile (no build).
    /// Pins each github input to its current branch head and records a
    /// content hash; `path:` inputs are marked local (unlocked).
    Lock(LockArgs),

    /// Lint declarations: a battery of package/image/pod checks beyond
    /// the leak scan (issue #53). Exits nonzero only on errors, never
    /// warnings. Fully offline.
    Lint(LintArgs),

    /// Audit lockfile pins against the OSV vulnerability database
    /// (issue #52). Exits nonzero only on confirmed findings.
    Audit(AuditArgs),

    /// Search available packages by name or keyword
    Search(SearchArgs),

    /// Manage the package index (list, add, resolve)
    #[command(subcommand)]
    Index(IndexCommand),

    /// Show dependency tree for a package, or fetch dependency closures
    /// for interpreted packages (ADR-0017, issue #13)
    #[command(subcommand)]
    Deps(DepsCommand),
}

impl From<ChartCommand> for Command {
    fn from(sub: ChartCommand) -> Self {
        match sub {
            ChartCommand::Check(args) => Command::Check(args),
            ChartCommand::Eval(args) => Command::Eval(args),
            ChartCommand::Versions(args) => Command::Versions(args),
            ChartCommand::EvalWorker => Command::EvalWorker,
            ChartCommand::CheckWorker => Command::CheckWorker,
            ChartCommand::Lock(args) => Command::Lock(args),
            ChartCommand::Lint(args) => Command::Lint(args),
            ChartCommand::Audit(args) => Command::Audit(args),
            ChartCommand::Search(args) => Command::Search(args),
            ChartCommand::Index(index) => Command::Index(index),
            ChartCommand::Deps(deps) => Command::Deps(deps),
        }
    }
}

/// Verbs for `nau ship` (ADR-0049): distribute — push and pull OCI
/// artifact bundles.
#[derive(clap::Subcommand)]
pub enum ShipCommand {
    /// Push built artifacts (`.snap`/`.img`) to an OCI registry as one
    /// OCI image manifest bundle (Phase 25).
    Push(PushArgs),

    /// Pull an artifact bundle from an OCI registry: fetch the manifest,
    /// download every blob with sha256 verification (fail-closed on any
    /// mismatch), and write the files under their original names.
    Pull(PullArgs),
}

impl From<ShipCommand> for Command {
    fn from(sub: ShipCommand) -> Self {
        match sub {
            ShipCommand::Push(args) => Command::Push(args),
            ShipCommand::Pull(args) => Command::Pull(args),
        }
    }
}

/// Verbs for `nau peer` (ADR-0049, ADR-0033): LAN sharing — serve the
/// pod store, browse announcing peers, export a static tree.
#[derive(clap::Subcommand)]
pub enum PeerCommand {
    /// Serve the pod store to LAN peers over a minimal HTTP/1.1 subset
    /// (ADR-0033 Decisions 4+5).
    Serve(ServeArgs),

    /// Browse the LAN for announcing nau peers (ADR-0033 Decision 3):
    /// mDNS discovery only, never trust.
    Browse(PeersArgs),

    /// Export the pod store's shareable content as a static directory
    /// tree any web server can serve (ADR-0033 Decision 10).
    Export(ExportArgs),
}

impl From<PeerCommand> for Command {
    fn from(sub: PeerCommand) -> Self {
        match sub {
            PeerCommand::Serve(args) => Command::Serve(args),
            PeerCommand::Browse(args) => Command::Peers(args),
            PeerCommand::Export(args) => Command::Export(args),
        }
    }
}

/// Verbs for `nau build-request` (ADR-0052 Decision 4): the ask-a-farm
/// surface — submit an identity to a token-gated server, and the
/// farm-side drain loop.
#[derive(clap::Subcommand)]
pub enum BuildRequestCommand {
    /// Ask a server to build `<package> <version>`: POST the identity
    /// (never build text) to `<server>/build-requests`, bearer-token
    /// gated, and print the server's request id. Without `--server`,
    /// the `servers` list resolves pod-override-first, then the system
    /// config's list, tried in order (ADR-0052 Decision 6).
    Submit(BuildRequestSubmitArgs),

    /// Run the farm-side drain: claim one queued request, resolve the
    /// recipe under the recipes root, evaluate farm-side with the
    /// requested version as the constraint, build via the worker pool,
    /// release the built snap to the static tree, write the receipt
    /// (manifest/blob urls, or the error), next. Failures are recorded
    /// and the loop continues; `--once` exits after one request.
    Run(BuildRequestRunArgs),
}

/// The `nau build-request submit` arguments (ADR-0052 Decision 4).
#[derive(clap::Args)]
pub struct BuildRequestSubmitArgs {
    /// Server front to ask (the public tree base, e.g.
    /// `https://download.example/nau`). Absent: the `servers` config
    /// resolves (pod override → system list, in order).
    #[arg(long, value_name = "BASE")]
    pub server: Option<String>,

    /// Package to build (`[a-z0-9-]`, the ADR-0032 charset).
    #[arg(long)]
    pub package: String,

    /// Version to build (a plain numeric triple, X.Y.Z).
    #[arg(long)]
    pub version: String,

    /// File carrying the bearer token (its first line, trimmed).
    /// Absent: the token is read from stdin.
    #[arg(long, value_name = "FILE")]
    pub token_file: Option<String>,

    /// Who is asking (an audit label the farm records with the
    /// request; default: this host's kernel hostname).
    #[arg(long, value_name = "SOURCE")]
    pub request_by: Option<String>,

    /// Project Lua declaring the system `servers` list (the resolution
    /// fallback when --server is absent; default: nau.lua).
    #[arg(long, value_name = "FILE")]
    pub file: Option<String>,
}

/// The `nau build-request run` arguments (ADR-0052 Decision 4): the
/// farm-side drain.
#[derive(clap::Args)]
pub struct BuildRequestRunArgs {
    /// Queue directory override (default: the XDG data root's nau dir,
    /// `$XDG_DATA_HOME/nau/build-requests` — the same root
    /// `nau serve --token-file` fills unless overridden there).
    #[arg(long, value_name = "DIR")]
    pub queue_dir: Option<String>,

    /// Recipes root to resolve requests against (default `pkgs/` —
    /// `pkgs/<first-letter>/<name>.lua`, the collection layout).
    #[arg(long, value_name = "ROOT", default_value = "pkgs")]
    pub recipes_root: String,

    /// Process one request (or exit immediately when the queue is
    /// empty) instead of polling forever.
    #[arg(long)]
    pub once: bool,

    /// Update-manifest signing key for the release step (the trust
    /// root the puller verifies against).
    #[arg(long, value_name = "FILE")]
    pub signing_key: Option<String>,

    /// Public static-tree base the release reports its URLs against
    /// (what `nau pull` consumes).
    #[arg(long, value_name = "BASE")]
    pub tree_base: Option<String>,

    /// rustfs (S3 API) endpoint the release uploads to.
    #[arg(long, value_name = "URL")]
    pub s3_endpoint: Option<String>,

    /// Bucket backing the static tree.
    #[arg(long, value_name = "BUCKET")]
    pub s3_bucket: Option<String>,

    /// SigV4 region string (rustfs accepts any consistent value).
    #[arg(long, value_name = "REGION")]
    pub s3_region: Option<String>,

    /// rustfs access key.
    #[arg(long, value_name = "KEY")]
    pub s3_access_key: Option<String>,

    /// rustfs secret key.
    #[arg(long, value_name = "KEY")]
    pub s3_secret_key: Option<String>,
}

/// Verbs for `nau trust` (ADR-0049): the key-ceremony surface
/// flattened one level — keygen, rotate, promote, revoke, list, verify
/// — with `--ca` scoping `keygen`/`list` to the SSH host CA ceremony.
/// Every verb folds onto the existing `KeyCommand`/`CaCommand` handlers.
#[derive(clap::Subcommand)]
pub enum TrustCommand {
    /// Generate the update signing key under `--home` (refuses to
    /// overwrite; installs the public key as a trust anchor). With
    /// `--ca`, generate the SSH host CA keypair instead (ADR-0045):
    /// refuses to overwrite an existing CA without `--force`.
    Keygen(TrustKeygenArgs),

    /// Mint the rotation successor at `<home>/.config/nau/secret-key.new`.
    /// NOT trusted until `trust promote`; the generation chain is
    /// recorded in `keys/ceremony.json` (issue #51), and `--manifest`
    /// is dual-signed under the successor.
    Rotate(TrustRotateArgs),

    /// Promote the pending rotation: `secret-key.new` → `secret-key`,
    /// installing the successor's public key as a trust anchor (the old
    /// anchor stays, dual-trust overlap window).
    Promote(TrustPromoteArgs),

    /// Revoke `key-id`: remove its trust anchor, record it in
    /// `keys/revoked-keys`, and date the revocation in the ledger.
    Revoke(TrustRevokeArgs),

    /// Print the ceremony ledger (`keys/ceremony.json`). With `--ca`,
    /// introspect the SSH host CA instead: which halves are on disk,
    /// the public line, and the fingerprint.
    List(TrustListArgs),

    /// Verify a manifest JSON under the ceremony policy: any signature
    /// from a live trusted key verifies; rotated-out keys past their
    /// overlap window verify with a warning; revoked-only fails.
    Verify(TrustVerifyArgs),
}

impl From<TrustCommand> for Command {
    fn from(sub: TrustCommand) -> Self {
        match sub {
            TrustCommand::Keygen(args) => {
                if args.ca {
                    Command::Ca(CaCommand::Keygen {
                        home: args.home,
                        force: args.force,
                        json: args.json,
                    })
                } else {
                    Command::Key(KeyCommand::Keygen {
                        home: args.home,
                        json: args.json,
                    })
                }
            }
            TrustCommand::Rotate(args) => Command::Key(KeyCommand::Rotate {
                home: args.home,
                manifest: args.manifest,
                window_days: args.window_days,
                json: args.json,
            }),
            TrustCommand::Promote(args) => Command::Key(KeyCommand::Promote {
                home: args.home,
                json: args.json,
            }),
            TrustCommand::Revoke(args) => Command::Key(KeyCommand::Revoke {
                key_id: args.key_id,
                home: args.home,
                json: args.json,
            }),
            TrustCommand::List(args) => {
                if args.ca {
                    Command::Ca(CaCommand::List {
                        home: args.home,
                        json: args.json,
                    })
                } else {
                    Command::Key(KeyCommand::List {
                        home: args.home,
                        json: args.json,
                    })
                }
            }
            TrustCommand::Verify(args) => Command::Key(KeyCommand::Verify {
                manifest: args.manifest,
                home: args.home,
                json: args.json,
            }),
        }
    }
}

/// The `nau trust keygen` arguments: the manifest-key ceremony, or the
/// SSH host CA ceremony with `--ca`.
#[derive(clap::Args)]
pub struct TrustKeygenArgs {
    /// Key-ceremony home (default: $HOME). The secret key lives at
    /// `<home>/.config/nau/secret-key`, anchors under `keys/`; with
    /// `--ca`, the host CA keypair lives at `<home>/.config/nau/ca/`.
    #[arg(long)]
    pub home: Option<String>,

    /// Scope the ceremony to the SSH host CA (ADR-0045) instead of the
    /// update-manifest signing key.
    #[arg(long)]
    pub ca: bool,

    /// Replace an existing CA keypair (`--ca` only). Both halves are
    /// removed before the mint — a failed regeneration can never leave
    /// the old public half paired with a new secret.
    #[arg(long, requires = "ca")]
    pub force: bool,

    /// Output structured JSON instead of human-friendly output.
    #[arg(long)]
    pub json: bool,
}

/// The `nau trust rotate` arguments.
#[derive(clap::Args)]
pub struct TrustRotateArgs {
    /// Key-ceremony home (default: $HOME).
    #[arg(long)]
    pub home: Option<String>,

    /// Manifest JSON to dual-sign under the successor (old signature
    /// kept; provenance re-attached when present).
    #[arg(long)]
    pub manifest: Option<String>,

    /// Overlap window, in days, recorded with the rotation: how long
    /// the rotated-out key's signatures stay first-class while the
    /// successor rolls out. Expired windows downgrade to a verify
    /// warning.
    #[arg(long, default_value_t = crate::sign::DEFAULT_WINDOW_DAYS)]
    pub window_days: u32,

    /// Output structured JSON instead of human-friendly output.
    #[arg(long)]
    pub json: bool,
}

/// The `nau trust promote` arguments.
#[derive(clap::Args)]
pub struct TrustPromoteArgs {
    /// Key-ceremony home (default: $HOME).
    #[arg(long)]
    pub home: Option<String>,

    /// Output structured JSON instead of human-friendly output.
    #[arg(long)]
    pub json: bool,
}

/// The `nau trust revoke` arguments.
#[derive(clap::Args)]
pub struct TrustRevokeArgs {
    /// Key id (first 16 hex chars of the public key).
    pub key_id: String,

    /// Key-ceremony home (default: $HOME).
    #[arg(long)]
    pub home: Option<String>,

    /// Output structured JSON instead of human-friendly output.
    #[arg(long)]
    pub json: bool,
}

/// The `nau trust list` arguments: the ceremony ledger, or the SSH
/// host CA introspection with `--ca`.
#[derive(clap::Args)]
pub struct TrustListArgs {
    /// Key-ceremony home (default: $HOME).
    #[arg(long)]
    pub home: Option<String>,

    /// Scope the listing to the SSH host CA (ADR-0045) instead of the
    /// ceremony ledger.
    #[arg(long)]
    pub ca: bool,

    /// Output structured JSON instead of human-friendly output.
    #[arg(long)]
    pub json: bool,
}

/// The `nau trust verify` arguments.
#[derive(clap::Args)]
pub struct TrustVerifyArgs {
    /// Path to the manifest JSON to verify.
    pub manifest: String,

    /// Key-ceremony home (default: $HOME).
    #[arg(long)]
    pub home: Option<String>,

    /// Output structured JSON instead of human-friendly output.
    #[arg(long)]
    pub json: bool,
}

/// Verbs for `nau pool` (ADR-0049, as amended by the #321 council —
/// `pool` replaces ADR-0040's "farm" naming, which already belongs to
/// the pod bin farm): the build-worker fleet coordinator surface plus
/// the two worker-side verbs. The coordinator verbs share their
/// argument structs with the legacy `WorkersCommand` variants;
/// `publish` is `workers receive-publish`.
#[derive(clap::Subcommand)]
pub enum PoolCommand {
    /// Provision cloud workers (ADR-0040, ADR-0045)
    Provision(WorkersProvisionArgs),

    /// Destroy one provisioned worker
    Destroy(WorkersDestroyArgs),

    /// One-command build window (#301): provision, wait for issuance,
    /// run the wrapped command, then tear down
    Burst(WorkersBurstArgs),

    /// Tear down every entry in the managed `workers` block (#301)
    Down(WorkersDownArgs),

    /// Issue short-lived host certificates (ADR-0045 amendment, #295)
    Issue(WorkersIssueArgs),

    /// Receive one guest publish (ADR-0045 amendment, #295): the
    /// coordinator half of the publish channel (`workers
    /// receive-publish`)
    Publish,

    /// Serve one issued certificate back to its guest (the pickup half
    /// of the publish channel)
    Pickup(WorkersPickupArgs),

    /// Advanced: invoked by nau itself. Build-worker capability probe:
    /// prints one JSON capability document (protocol, arch, nproc, RAM,
    /// free disk, tool presence, functioning-sandbox and KVM probes) on
    /// stdout, then exits (ADR-0040 Decision 2) — the revealed form of
    /// the hidden `__worker-cap` alias.
    Probe,

    /// Advanced: invoked by nau itself. Build-worker job executor:
    /// executes exactly one job manifest — verifies every payload
    /// sha256, then runs the ordinary offline sandbox build path — and
    /// prints one JSON result document on stdout (ADR-0040 Decision 2).
    /// Any refusal exits nonzero before anything runs. The revealed
    /// form of the hidden `__worker-job` alias.
    Job {
        /// Path to the job manifest file.
        job_file: String,
    },
}

impl From<PoolCommand> for Command {
    fn from(sub: PoolCommand) -> Self {
        match sub {
            PoolCommand::Provision(args) => Command::Workers {
                command: WorkersCommand::Provision(args),
            },
            PoolCommand::Destroy(args) => Command::Workers {
                command: WorkersCommand::Destroy(args),
            },
            PoolCommand::Burst(args) => Command::Workers {
                command: WorkersCommand::Burst(args),
            },
            PoolCommand::Down(args) => Command::Workers {
                command: WorkersCommand::Down(args),
            },
            PoolCommand::Issue(args) => Command::Workers {
                command: WorkersCommand::Issue(args),
            },
            PoolCommand::Publish => Command::Workers {
                command: WorkersCommand::ReceivePublish,
            },
            PoolCommand::Pickup(args) => Command::Workers {
                command: WorkersCommand::Pickup(args),
            },
            PoolCommand::Probe => Command::WorkerCap,
            PoolCommand::Job { job_file } => Command::WorkerJob { job_file },
        }
    }
}

/// The `nau chart search` / legacy `nau search` arguments (ADR-0049).
#[derive(clap::Args)]
pub struct SearchArgs {
    /// Search query (package name or partial match)
    pub query: String,

    /// Output structured JSON instead of human-friendly output.
    #[arg(long)]
    pub json: bool,
}

/// The `nau chart check` / legacy `nau check` arguments (ADR-0049).
#[derive(clap::Args)]
pub struct CheckArgs {
    /// Path to the Lua definition file
    pub file: String,

    /// Output structured JSON instead of human-friendly output.
    #[arg(long)]
    pub json: bool,
}

/// The `nau chart lint` / legacy `nau lint` arguments (ADR-0049).
#[derive(clap::Args)]
pub struct LintArgs {
    /// Path to the Lua definition file (default: nau.lua)
    #[arg(short, long, default_value = "nau.lua")]
    pub file: String,

    /// Lint a pod's declared packages (app collisions) instead of a
    /// definition file.
    #[arg(long)]
    pub pod: Option<String>,

    /// Snap channel for resolution context (default: latest/stable).
    /// Kernel/gadget snaps derive their channel from the image base
    /// track on top of this (ADR-0019).
    #[arg(long, default_value = "latest/stable")]
    pub channel: String,

    /// Output structured JSON instead of human-friendly output.
    #[arg(long)]
    pub json: bool,
}

/// The `nau chart audit` / legacy `nau audit` arguments (ADR-0049).
#[derive(clap::Args)]
pub struct AuditArgs {
    /// Path to the Lua definition file. Optional: when given, its
    /// evaluated outputs enrich the audit with declared versions and
    /// declaration labels for source pins.
    #[arg(short, long)]
    pub file: Option<String>,

    /// Path to lockfile (project nau.lock or a pod's lockfile).
    #[arg(short, long, default_value = "nau.lock")]
    pub lockfile: String,

    /// Force a refresh: bypass the local OSV response cache and
    /// rewrite it from the live database.
    #[arg(long)]
    pub update: bool,

    /// Output structured JSON instead of human-friendly output.
    #[arg(long)]
    pub json: bool,
}

/// The `nau chart lock` / legacy `nau lock` arguments (ADR-0049).
#[derive(clap::Args)]
pub struct LockArgs {
    /// Path to the Lua config file (default: nau.lua).
    /// If not found, locks the default package index input.
    #[arg(short, long, default_value = "nau.lua")]
    pub file: String,

    /// Path to lockfile (default: nau.lock).
    #[arg(long, default_value = "nau.lock")]
    pub lockfile: String,

    /// Output structured JSON with pin state instead of human output.
    #[arg(long)]
    pub json: bool,
}

/// The `nau chart eval` / legacy `nau eval` arguments (ADR-0049).
#[derive(clap::Args)]
pub struct EvalArgs {
    /// Path to the Lua config file (default: nau.lua)
    #[arg(short, long, default_value = "nau.lua")]
    pub file: String,

    /// Write the manifest to this file atomically (default: stdout)
    #[arg(short, long)]
    pub output: Option<String>,

    /// Only evaluate this output or image (from the definition's
    /// returned table). Default: everything declared.
    pub output_name: Option<String>,

    /// Target architecture for image contents (default: amd64)
    #[arg(short, long, default_value = "amd64")]
    pub arch: String,

    /// Snap channel for the resolution context (default: latest/stable)
    #[arg(long, default_value = "latest/stable")]
    pub channel: String,

    /// Path to lockfile (default: nau.lock).
    /// Pins source hashes and snap revisions for reproducible evals.
    #[arg(long, default_value = "nau.lock")]
    pub lockfile: String,

    /// Use only pinned/cached inputs — never touch the network.
    #[arg(long)]
    pub offline: bool,

    /// Suppress human-readable status output (the manifest is JSON
    /// either way).
    #[arg(long)]
    pub json: bool,
}

/// The `nau chart versions` arguments (ADR-0052 Decision 2).
#[derive(clap::Args)]
pub struct VersionsArgs {
    /// Path to the Lua definition file.
    pub file: String,

    /// Only list versions for this output. An unknown name is a clean
    /// error naming what the definition does declare.
    #[arg(long)]
    pub output: Option<String>,

    /// Emit `{"<output>": {"resolved": "...", "versions": [...] | null}}`
    /// instead of the aligned table.
    #[arg(long)]
    pub json: bool,
}

/// The `nau ship push` / legacy `nau push` arguments (ADR-0049).
#[derive(clap::Args)]
pub struct PushArgs {
    /// Destination reference: [registry[:port]/]repo[:tag|@digest].
    /// An explicit registry host is required (e.g. localhost:5000/ns/repo,
    /// ghcr.io/owner/repo) — the docker.io implicit default is
    /// deliberately out of scope. Pushing by @digest is an error.
    pub reference: String,

    /// Directory to auto-discover artifacts in (*.snap, *.img;
    /// default: current dir, matching build/image --output)
    #[arg(short = 'd', long, default_value = ".")]
    pub dir: String,

    /// Explicit artifact file(s) to push (repeatable; overrides --dir
    /// discovery). Extension decides the layer media type.
    #[arg(long)]
    pub snap: Vec<String>,

    /// Explicit disk image file(s) to push (repeatable; overrides
    /// --dir discovery).
    #[arg(long)]
    pub image: Vec<String>,

    /// Tag to push under (default: <name>-<version> derived from the
    /// artifact file names and sanitized to the registry tag charset).
    #[arg(long)]
    pub tag: Option<String>,

    /// Registry username (requires --password-stdin).
    #[arg(long)]
    pub username: Option<String>,

    /// Read the registry password from stdin (one line, no echo).
    #[arg(long)]
    pub password_stdin: bool,

    /// Talk plain http:// (no TLS) — intended for local registries
    /// (e.g. registry:2 on localhost:5000). Refused otherwise.
    #[arg(long)]
    pub insecure_http: bool,

    /// Attempt cross-repo blob mounts from this source repository
    /// (`POST ...?mount=<digest>&from=<repo>`) before uploading:
    /// a 201 response reuses the bytes already in the registry (no
    /// transfer). Default: empty = mounts skipped.
    #[arg(long)]
    pub mount_from: Option<String>,

    /// Write the built-manifest record (the manifest Artifact
    /// extension: per-blob sha256 digest, size, media type) to this
    /// file after a successful push. `pull --expect` consumes it.
    #[arg(long)]
    pub record: Option<String>,

    /// Output structured JSON instead of human-friendly output.
    #[arg(long)]
    pub json: bool,
}

/// The `nau ship pull` / legacy `nau pull` arguments (ADR-0049).
#[derive(clap::Args)]
pub struct PullArgs {
    /// Source reference: [registry[:port]/]repo[:tag|@digest]. An
    /// explicit registry host is required. A tag or @digest is
    /// required — there is no default tag. When pulled by @digest,
    /// the received manifest itself is digest-verified.
    pub reference: String,

    /// Directory to write pulled artifact files into (default: current dir)
    #[arg(short, long, default_value = ".")]
    pub out_dir: String,

    /// Registry username (requires --password-stdin).
    #[arg(long)]
    pub username: Option<String>,

    /// Read the registry password from stdin (one line, no echo).
    #[arg(long)]
    pub password_stdin: bool,

    /// Talk plain http:// (no TLS) — intended for local registries.
    #[arg(long)]
    pub insecure_http: bool,

    /// Verify received blobs against a built-manifest record (from
    /// `push --record`) IN ADDITION to the OCI descriptors —
    /// fail-closed on any digest, size, or media-type mismatch.
    #[arg(long)]
    pub expect: Option<String>,

    /// Install pulled `.snap` payloads into the state root after the
    /// download. Revisions resolve from the `nau.lock` pins in
    /// the current directory (matched by sha3-384); unpinned or
    /// divergent blobs are refused (use plain pull to keep files).
    #[arg(long)]
    pub install: bool,

    /// State root for --install (default: /var/lib/nau).
    #[arg(long)]
    pub state_dir: Option<String>,

    /// Pod store that peer (`nau://`) and static-URL
    /// (`http(s)://`) pulls stage into (default: `default`) — the
    /// verified manifest + blobs land in the named pod's store and
    /// installation stays the pod workflow, never a pull side
    /// effect (ADR-0033 Decision 5). Ignored for plain registry
    /// references.
    #[arg(long, value_name = "POD")]
    pub pod: Option<String>,

    /// Accept a manifest whose revision is OLDER than the installed
    /// or staged one for that name (ADR-0033 Decision 7 freshness
    /// rule). Peer/URL pulls only. Note: `nau.lock` pins do NOT
    /// bind on the peer lane yet — PackageManifest carries no store
    /// pin; pin-binding is deferred (ADR-0033 Decision 7).
    #[arg(long = "allow-downgrade")]
    pub allow_downgrade: bool,

    /// Output structured JSON instead of human-friendly output.
    #[arg(long)]
    pub json: bool,
}

/// The `nau peer serve` / legacy `nau serve` arguments (ADR-0049).
#[derive(clap::Args)]
pub struct ServeArgs {
    /// Bind address override. Default: `node {}`'s
    /// `serve.address`, else 127.0.0.1 (loopback — `/info`
    /// publishes the pod inventory to everyone who can reach the
    /// socket; `0.0.0.0` is an explicit choice).
    #[arg(long)]
    pub address: Option<String>,

    /// Bind port override (default: 7780, unprivileged).
    #[arg(long)]
    pub port: Option<u16>,

    /// Announce the node on the LAN via mDNS (`_nau._tcp`,
    /// ADR-0033 Decision 3), overriding `node {}`'s
    /// `serve.announce`. The declaration is the source of truth;
    /// absent both, serve does not announce.
    #[arg(long)]
    pub announce: bool,

    /// Pod whose store to serve (default: `default`) — the named
    /// pod's store is the served surface, matching `--pod` on
    /// `pull` and `export` (ADR-0033 Decision 5).
    #[arg(long, value_name = "POD")]
    pub pod: Option<String>,

    /// Open `POST /build-requests` (ADR-0052 Decision 4): the file of
    /// bearer tokens, one per line, operator-managed — a request
    /// without a valid token is a 4xx and never reaches the queue, and
    /// removing a line revokes it on the next request. Absent, the
    /// write route is off (POST answers 404).
    #[arg(long, value_name = "FILE")]
    pub token_file: Option<String>,

    /// Build-request queue directory override (ADR-0052 Decision 4;
    /// default: the XDG data root's nau dir,
    /// `$XDG_DATA_HOME/nau/build-requests`).
    #[arg(long, value_name = "DIR")]
    pub queue_dir: Option<String>,
}

/// The `nau peer browse` / legacy `nau peers` arguments (ADR-0049).
#[derive(clap::Args)]
pub struct PeersArgs {
    /// Browse window in seconds (default: 2).
    #[arg(long, default_value_t = 2)]
    pub secs: u64,

    /// Output structured JSON instead of human-friendly output.
    #[arg(long)]
    pub json: bool,
}

/// The `nau peer export` / legacy `nau export` arguments (ADR-0049).
#[derive(clap::Args)]
pub struct ExportArgs {
    /// Directory to write the export tree into
    pub out: String,

    /// Pod whose store to export (default: `default`).
    #[arg(long, value_name = "POD")]
    pub pod: Option<String>,

    /// Curate the export to one mission's pinned pool (#275): only
    /// the packages the named `image()` declaration pins (base,
    /// kernel, gadget, snaps). Every pinned package must be in the
    /// pod store — a missing pin fails the export.
    #[arg(long, value_name = "MISSION")]
    pub mission: Option<String>,

    /// Project Lua declaring the mission (with --mission).
    #[arg(long, value_name = "FILE", requires = "mission")]
    pub file: Option<String>,
}

/// The `nau image test` / legacy `nau test` arguments (ADR-0049).
#[derive(clap::Args)]
pub struct TestArgs {
    /// Path to the built disk image (`.img`) to boot.
    pub image: String,

    /// Boot timeout in seconds. QEMU is killed when it elapses; the kill
    /// still passes when a completion target was reached before it.
    #[arg(long, default_value_t = 120)]
    pub timeout: u64,

    /// QEMU accelerator. `kvm` (default) falls back to `tcg` when KVM is
    /// unavailable — `tcg` is software emulation (much slower).
    #[arg(long, value_enum, default_value = "kvm")]
    pub accel: Accel,

    /// Write the captured serial console here (default:
    /// `<image>.serial.log`). This is the auditable boot evidence.
    #[arg(long)]
    pub log: Option<String>,

    /// Extra substring the serial log MUST contain to pass (repeatable).
    /// Tightens the boot assertion beyond the built-in markers, e.g.
    /// `--require "Reached target Boot Completion Check"` for an A/B image
    /// that emits the try-boot completion target.
    #[arg(long = "require")]
    pub require: Vec<String>,

    /// Accept a boot that reached the init handoff without ever reaching
    /// a completed target (issue #84 opt-out). Restores the pre-#84
    /// handoff-only gate; use only for images that legitimately never
    /// reach `boot-complete.target` or `default.target`.
    #[arg(long = "allow-no-completion")]
    pub allow_no_completion: bool,

    /// Directory holding the UEFI firmware (`OVMF_CODE.fd`/`OVMF_VARS.fd`
    /// or the edk2 equivalents). Default: auto-discovered.
    #[arg(long)]
    pub firmware_dir: Option<String>,

    /// Boot the image N times in sequence (default 1). With N > 1 a single
    /// sparse copy is booted repeatedly so guest mutations persist; each
    /// boot's serial log and ESP listing are archived.
    #[arg(long, default_value_t = 1)]
    pub runs: u32,

    /// Expected try-boot counter sequence, one element per boot, observed
    /// BEFORE each boot. `3-0,2-1` pins tries-left and tries-done; a bare
    /// `3,2,1,0` leaves tries-done unchecked.
    ///
    /// Boot counting lives in the ESP filename: systemd-boot renames the
    /// selected UKI (`foo+3-0.efi` -> `foo+2-1.efi`) before the kernel
    /// loads, so the serial console cannot see it. A fixture MUST use a
    /// DISTINCT version for a counted entry: systemd-boot strips the
    /// `+N-M` counter when deriving an entry id, so a counted UKI
    /// differing from its sibling only by the counter shares its id; with
    /// one entry counterless the comparator returns 0 and selection
    /// becomes arbitrary.
    #[arg(long = "expect-counter-seq")]
    pub expect_counter_seq: Option<String>,

    /// Extra argv token passed through to QEMU verbatim (repeatable;
    /// each value is ONE argv token, so an option and its value are two
    /// `--qemu-arg` occurrences; values starting with `-` need clap's
    /// `=` form: `--qemu-arg=-nic`). Appended after the built-in
    /// drives — this is how the update proof (#80) attaches guest
    /// networking: `--qemu-arg=-nic --qemu-arg user,model=virtio-net-pci`.
    #[arg(long = "qemu-arg")]
    pub qemu_args: Vec<String>,

    /// Output structured JSON instead of human-friendly output.
    #[arg(long)]
    pub json: bool,
}

/// The `nau image verify` / legacy `nau verify-image` arguments
/// (ADR-0049).
#[derive(clap::Args)]
pub struct VerifyImageArgs {
    /// Flashed target to verify: a block device named by stable id
    /// (/dev/disk/by-id/...) or a whole-disk image file. Only ever
    /// opened for reading.
    #[arg(long)]
    pub device: String,

    /// Signed image manifest (.manifest.json) published with the
    /// mission image (ADR-0044 D5).
    #[arg(long)]
    pub manifest: String,

    /// Extra trust anchor for the manifest signature: a public-key
    /// file (same two-line format `nau key keygen` writes),
    /// accepted beside the operator keychain (~/.config/nau/keys).
    #[arg(long)]
    pub key: Option<String>,

    /// Which slot's regions to verify: `a`, `b`, or `auto` (the
    /// default). The manifest signs a generation, not a slot — auto
    /// locates it wherever it sits (the post-sysupdate case: the new
    /// manifest verifies the slot sysupdate filled); `a`/`b` demand
    /// the physical slot (the build writes slot B contiguous behind
    /// slot A) and refuse by name when the generation sits elsewhere.
    #[arg(long, value_enum, default_value = "auto")]
    pub slot: crate::image::SlotSelector,

    /// Output structured JSON instead of human-friendly output.
    #[arg(long)]
    pub json: bool,
}

/// `--count` bounds for `nau workers provision` (M5): at least ONE
/// server — a zero count would run nothing and exit 0 — and at most
/// [`WORKERS_MAX_COUNT`] per run, the API fan-out cap; larger fleets
/// should be split into runs.
const WORKERS_MIN_COUNT: u32 = 1;
const WORKERS_MAX_COUNT: u32 = 50;

/// `nau workers burst --max` default (#301): the council's daily fleet
/// is 2-3 workers, so 4 is the fat-finger guard — a count above it is a
/// deliberate `--max` raise, never a silent oversized bill.
const WORKERS_BURST_MAX_DEFAULT: u32 = 4;

/// The `--count` value parser: decimal u32 within the named bounds.
fn workers_count(raw: &str) -> Result<u32, String> {
    let n: u32 = raw
        .parse()
        .map_err(|_| format!("invalid unsigned integer: '{raw}'"))?;
    if !(WORKERS_MIN_COUNT..=WORKERS_MAX_COUNT).contains(&n) {
        return Err(format!(
            "{n} is not in {WORKERS_MIN_COUNT}..={WORKERS_MAX_COUNT}"
        ));
    }
    Ok(n)
}

/// `workers burst --count`: an explicit fleet size, or `auto` — size the
/// burst from the wrapped build's pending jobs (#304). The explicit
/// spelling keeps the #301 bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BurstCount {
    /// min(--max, ceil(pending / jobs-per-worker)) of the wrapped build.
    Auto,
    /// An explicit worker count within the #301 bounds.
    Fixed(u32),
}

/// The burst `--count` value parser: `auto`, else the shared
/// [`workers_count`] bounds.
fn burst_count(raw: &str) -> Result<BurstCount, String> {
    if raw == "auto" {
        return Ok(BurstCount::Auto);
    }
    Ok(BurstCount::Fixed(workers_count(raw)?))
}

/// The wrapped argv of `workers burst --count auto` (#304): it must BE a
/// nau build, parsed through the same Cli definition the real build uses,
/// so sizing sees exactly the flags a real build would. Anything else is
/// a named refusal — no pending set exists to size from. Accepts the
/// legacy `nau build …` spelling, the bare `build …` shorthand, and
/// their ADR-0049 domain forms (`nau build snap …` / `build snap …` —
/// [`normalize_domain`] folds the subcommand onto the same flat
/// [`Command::Build`], which the sizing caller does).
pub fn wrapped_build(command: &[String]) -> miette::Result<Command> {
    let not_a_build = || {
        miette::miette!(
            "workers burst: --count auto sizes a wrapped 'nau build' — '{}' is not one, \
             and there is no pending set to size from",
            command.join(" ")
        )
    };
    let argv: Vec<String> = match command {
        [first, rest @ ..] if first == "nau" => {
            if rest.first().map(String::as_str) != Some("build") {
                return Err(not_a_build());
            }
            rest.to_vec()
        }
        [..] if command.first().map(String::as_str) == Some("build") => command.to_vec(),
        _ => return Err(not_a_build()),
    };
    let mut full = vec!["nau".to_string()];
    full.extend(argv);
    let cli = Cli::try_parse_from(full).map_err(|e| {
        miette::miette!("workers burst: the wrapped build's arguments do not parse: {e}")
    })?;
    match cli.command {
        cmd @ Command::Build { .. } => Ok(cmd),
        // Unreachable through try_parse_from of a `build` argv; kept
        // fail-closed for future Cli reshapes.
        _ => Err(not_a_build()),
    }
}

/// Fold the ADR-0049 domain-namespace spellings onto the legacy
/// [`Command`] variants: one dispatch, two grammars. The legacy
/// spellings keep parsing as hidden aliases and land here unchanged;
/// every namespace verb lands on the same variant its legacy spelling
/// produces, so main() dispatches through a single match.
pub fn normalize_domain(command: Command) -> Command {
    match command {
        Command::Chart { command } => command.into(),
        Command::Ship { command } => command.into(),
        Command::Peer { command } => command.into(),
        Command::Trust { command } => command.into(),
        Command::Pool { command } => command.into(),
        Command::Build { args, command } => match command {
            None => Command::Build {
                args,
                command: None,
            },
            Some(BuildCommand::Snap(args)) => Command::Build {
                args: *args,
                command: None,
            },
            Some(BuildCommand::Cache(cache)) => Command::Cache(cache),
        },
        Command::Image { args, command } => match command {
            None => Command::Image {
                args,
                command: None,
            },
            Some(ImageCommand::Build(args)) => Command::Image {
                args,
                command: None,
            },
            Some(ImageCommand::Test(test)) => Command::Test(test),
            Some(ImageCommand::Verify(verify)) => Command::VerifyImage(verify),
        },
        other => other,
    }
}

// ── External subcommands (ADR-0049 Decision 5) ─────────────────────
//
// git's dashed-external mechanism: an unknown verb falls through to an
// executable `nau-<verb>`. This is a DISPATCH contract, not a code
// split — nau stays one binary; third parties (and pods, whose bin
// farms land on PATH via `pod shellenv`) extend the CLI by shipping
// helpers, exactly as `git-credential-*` extends git.

/// The external-verb charset (ADR-0049 Decision 5): git's own rule,
/// `[a-z][a-z0-9-]*`. No dots, no colons, no path separators, no
/// leading dash, no uppercase, never empty — a verb failing this is
/// refused by name BEFORE any `nau-<verb>` lookup, so a verb can never
/// smuggle a path component into the search.
fn is_external_verb(verb: &str) -> bool {
    let mut chars = verb.chars();
    match chars.next() {
        Some(first) if first.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// An executable helper: exists, is a regular file (symlinks resolve —
/// packagers ship `nau-x -> ../libexec/nau-x`), and carries an exec
/// bit.
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Resolve `nau-<verb>` for an unknown verb: a sibling of the running
/// nau binary first, then PATH in order. Deliberately NOT
/// environment-overridable — the house isolation posture forbids
/// env-influenced lookup; PATH itself is the documented fallback, the
/// same rule git's dashed-external search follows.
fn resolve_external_helper(verb: &str) -> Option<PathBuf> {
    let name = format!("nau-{verb}");
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join(&name);
            if is_executable_file(&sibling) {
                return Some(sibling);
            }
        }
    }
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .find(|dir| is_executable_file(&dir.join(&name)))
        .map(|dir| dir.join(name))
}

/// Dispatch an unknown verb to a `nau-<verb>` executable (ADR-0049
/// Decision 5). `argv` is clap's external catch-all: element 0 is the
/// verb, the rest is the remaining command line, forwarded verbatim —
/// the helper never sees the verb itself, exactly like `git-<cmd>`.
/// EXEC, not spawn-and-wait: the process image is replaced, stdio is
/// inherited, and the helper's exit code is nau's own.
pub fn run_external(argv: &[OsString]) -> miette::Result<()> {
    use std::os::unix::process::CommandExt;
    let Some((verb, args)) = argv.split_first() else {
        // Unreachable through clap: the catch-all always carries the
        // verb as element 0. Kept fail-closed for direct callers.
        return Err(miette::miette!(
            "nau: external subcommand arrived without a verb"
        ));
    };
    let verb = verb.to_string_lossy();
    if !is_external_verb(&verb) {
        return Err(miette::miette!(
            "unknown command '{verb}' — verb names must match [a-z][a-z0-9-]* \
             (no dots, colons, path separators, leading dashes, or uppercase)"
        ));
    }
    let Some(helper) = resolve_external_helper(&verb) else {
        return Err(miette::miette!(
            "unknown command `{verb}` — and no `nau-{verb}` extension found on PATH"
        ));
    };
    let error = std::process::Command::new(&helper).args(args).exec();
    // exec() only returns on failure — the image was not replaced.
    Err(miette::miette!(
        "nau {verb}: failed to exec {}: {error}",
        helper.display()
    ))
}

/// Subcommands for `nau workers`.
#[derive(clap::Subcommand)]
pub enum WorkersCommand {
    /// Provision cloud workers: each guest GENERATES its own SSH host
    /// keypair locally on first boot and publishes the PUBLIC half to the
    /// coordinator over a one-time provisioning token (ADR-0045 amendment
    /// — no private half ever ships in user-data); provision pins the
    /// host CA's fingerprint into a machine-managed `workers` entry in
    /// nau.lua BEFORE first use — never ssh-keyscan. Certificate
    /// issuance from the published keys is #295 sub-task 3.
    Provision(WorkersProvisionArgs),

    /// Destroy one provisioned worker: removes the server and evicts its
    /// managed `workers` entry (operator-owned text is never rewritten).
    Destroy(WorkersDestroyArgs),

    /// Receive one guest publish (ADR-0045 amendment, #295): reads the
    /// JSON payload on stdin with the bearer token in
    /// `NAU_PUBLISH_TOKEN`, validates one-time-ness + key shape, and
    /// stores the pending identity under
    /// `~/.config/nau/ca/pending/` for `nau workers issue`.
    /// The transport binding for any TLS-terminating front: extract the
    /// Authorization header, hand the body here — fail-closed on every
    /// bad token, replay, or malformed key.
    ReceivePublish,

    /// Issue short-lived host certificates (ADR-0045 amendment, #295
    /// sub-task 3): the host CA signs one certificate per pending
    /// identity — principals bind the machine identity plus the provider
    /// instance-identity content (Decision 3) — and the identity moves to
    /// the issued record (`~/.config/nau/ca/issued/`), the audit
    /// trail. The guest picks its certificate up with
    /// `nau workers pickup`.
    Issue(WorkersIssueArgs),

    /// Serve one issued certificate back to its guest (the pickup half
    /// of the publish channel): authenticates with the machine's
    /// one-time publish token (`NAU_PUBLISH_TOKEN` — the same bearer
    /// that carried the publish) and prints the certificate to stdout.
    /// The GET of the callback URL, symmetric with receive-publish's
    /// POST. Idempotent reads; refuses (nonzero exit) while the identity
    /// is not yet issued or the token is expired/unknown — the guest
    /// retries, and the TTL sweep reclaims a guest that never picks up.
    Pickup(WorkersPickupArgs),

    /// One-command build window (#301): provision N workers, wait for
    /// every host certificate to be issued (`issue --wait` semantics),
    /// run the wrapped command with inherited stdio, then destroy +
    /// evict every worker THIS burst provisioned — the teardown fires on
    /// command failure and Ctrl-C alike, unless `--keep` parks the
    /// workers for a later `nau workers down --all-managed`. The burst
    /// exit code is the wrapped command's exit code.
    Burst(WorkersBurstArgs),

    /// Tear down every entry in the managed `workers` block (#301): the
    /// `--keep` burst's promised drain. Each entry's server is destroyed
    /// (the machine linkage names it) and its pin evicted; an empty or
    /// absent block is a green no-op.
    Down(WorkersDownArgs),
}

/// The `nau workers provision` / `nau pool provision` arguments
/// (ADR-0049).
#[derive(clap::Args)]
pub struct WorkersProvisionArgs {
    /// Provider driver (currently: hetzner, aws, gcp, azure, scaleway).
    #[arg(long)]
    pub provider: String,

    /// Server SKU — operator-supplied, never hardcoded (Hetzner
    /// repriced the lineup 2026-06-15; classes CX23/CX33/CAX11/CAX21;
    /// AWS: the EC2 instance type, e.g. c7i.large).
    #[arg(long = "type", value_name = "SKU")]
    pub server_type: String,

    /// Provider location (e.g. hel1, fsn1; AWS: the region, e.g.
    /// eu-central-1).
    #[arg(long)]
    pub location: String,

    /// How many servers to create (1-50).
    #[arg(long, default_value_t = WORKERS_MIN_COUNT, value_parser = workers_count)]
    pub count: u32,

    /// Worker lifetime before the TTL sweep reclaims it (e.g. 4h,
    /// 30m). Stamped into /etc/nau/worker-ttl and the
    /// `nau-worker` hcloud label (epoch-seconds expiry).
    #[arg(long, default_value = "4h")]
    pub ttl: String,

    /// Request a spot/preemptible instance (aws only; hetzner has no
    /// spot product). Eviction is T5 worker loss — re-dispatched,
    /// never migrated (ADR-0040 Amendment 1). On-demand hourly is the
    /// default; spot is for eviction-tolerant lanes only.
    #[arg(long)]
    pub spot: bool,

    /// Hourly USD price cap for `--spot` (e.g. 0.05). Required with
    /// `--spot` — an uncapped bid is not a cap; refused without it.
    #[arg(long, value_name = "USD_H")]
    pub max_price: Option<String>,

    /// GCP spelling of --spot (gcp): a preemptible VM. Eviction is
    /// T5 worker loss — re-dispatched, never migrated (ADR-0040
    /// Amendment 1). Preemptible pricing is fixed per machine type,
    /// so --max-price does not apply (refused by the gcp provider).
    /// (`--spot` is the provider-independent spelling — same request.)
    #[arg(long)]
    pub preemptible: bool,

    /// Print the plan (type, location, count, TTL, user-data hash) and
    /// exit — resolved fully, no API call, no token needed.
    #[arg(long)]
    pub dry_run: bool,

    /// Config file the workers entries are pinned into.
    #[arg(short, long, default_value = "nau.lua")]
    pub file: String,
}

/// The `nau workers destroy` / `nau pool destroy` arguments (ADR-0049).
#[derive(clap::Args)]
pub struct WorkersDestroyArgs {
    /// Provider driver (currently: hetzner, aws, gcp, azure, scaleway).
    #[arg(long)]
    pub provider: String,

    /// Server name, as printed by provision.
    pub name: String,

    /// Config file the workers entry is evicted from.
    #[arg(short, long, default_value = "nau.lua")]
    pub file: String,
}

/// The `nau workers issue` / `nau pool issue` arguments (ADR-0049).
#[derive(clap::Args)]
pub struct WorkersIssueArgs {
    /// CA ceremony home (default: $HOME).
    #[arg(long)]
    pub home: Option<String>,

    /// Issue only this machine identity (default: every pending
    /// identity).
    #[arg(long)]
    pub identity: Option<String>,

    /// Certificate validity — short-lived and relative to now,
    /// ssh-keygen form (e.g. +48h, +2d12h). Absolute dates and
    /// forever windows are refused: certificates must age out.
    #[arg(long, default_value = crate::provision::publish::HOST_CERT_VALIDITY_DEFAULT)]
    pub validity: String,

    /// Re-issue an identity that already has an issued record (the
    /// previous certificate stays valid until its own expiry).
    #[arg(long)]
    pub force: bool,

    /// Wait for guest publishes that have not landed yet (#299):
    /// poll the pending store and sign each identity as its publish
    /// lands, instead of signing only what is already pending. The
    /// provision→issue race fix; opt-in, so ADR-0045's
    /// explicit-trust posture is unchanged without it.
    #[arg(long)]
    pub wait: bool,

    /// `--wait` ceiling in seconds: how long to keep polling for
    /// publishes before failing loudly (guests publish 1-4 min
    /// after server create).
    #[arg(
        long,
        default_value_t = crate::provision::ISSUE_WAIT_DEFAULT_TIMEOUT_SECS,
        requires = "wait"
    )]
    pub timeout: u64,

    /// Output structured JSON instead of human-friendly output.
    #[arg(long)]
    pub json: bool,
}

/// The `nau workers pickup` / `nau pool pickup` arguments (ADR-0049).
#[derive(clap::Args)]
pub struct WorkersPickupArgs {
    /// CA ceremony home (default: $HOME).
    #[arg(long)]
    pub home: Option<String>,
}

/// The `nau workers burst` / `nau pool burst` arguments (ADR-0049).
#[derive(clap::Args)]
pub struct WorkersBurstArgs {
    /// Provider driver (currently: hetzner, aws, gcp, azure, scaleway).
    #[arg(long)]
    pub provider: String,

    /// Server SKU — operator-supplied, never hardcoded (same
    /// vocabulary as `workers provision`).
    #[arg(long = "type", value_name = "SKU")]
    pub server_type: String,

    /// Provider location (e.g. hel1, fsn1; AWS: the region, e.g.
    /// eu-central-1).
    #[arg(long)]
    pub location: String,

    /// How many workers this burst provisions (default: 1), or
    /// `auto` — size the burst from the wrapped build's pending jobs
    /// (#304); a wrapped command that is not a build is a named
    /// refusal before any API call.
    #[arg(long, default_value = "1", value_parser = burst_count)]
    pub count: BurstCount,

    /// Guardrail: refuse `--count` above it. A fat-fingered count is
    /// an hourly bill; raising it is a deliberate act.
    #[arg(long, default_value_t = WORKERS_BURST_MAX_DEFAULT)]
    pub max: u32,

    /// Worker lifetime before the TTL sweep reclaims it (e.g. 4h).
    /// The safety net under the burst teardown, not a substitute.
    #[arg(long, default_value = "4h")]
    pub ttl: String,

    /// `issue --wait` ceiling in seconds for the whole burst. The
    /// effective ceiling scales with the count (each guest publishes
    /// 1-4 min after create).
    #[arg(
        long,
        default_value_t = crate::provision::ISSUE_WAIT_DEFAULT_TIMEOUT_SECS
    )]
    pub timeout: u64,

    /// Skip the teardown: leave the burst workers provisioned and
    /// pinned (for inspection or a follow-up run). Tear them down
    /// later with `nau workers down --all-managed`.
    #[arg(long)]
    pub keep: bool,

    /// Config file the workers entries are pinned into.
    #[arg(short, long, default_value = "nau.lua")]
    pub file: String,

    /// The command to run against the burst workers, after `--`.
    /// Stdio is inherited; its exit code is the burst's.
    #[arg(last = true, num_args = 1.., required = true, value_name = "CMD")]
    pub command: Vec<String>,
}

/// The `nau workers down` / `nau pool down` arguments (ADR-0049).
#[derive(clap::Args)]
pub struct WorkersDownArgs {
    /// Destroy every managed-block entry (v1's only mode — per-entry
    /// destruction stays `workers destroy`).
    #[arg(long, required = true)]
    pub all_managed: bool,

    /// Provider driver the block's servers were provisioned with.
    #[arg(long)]
    pub provider: String,

    /// Config file the workers entries are evicted from.
    #[arg(short, long, default_value = "nau.lua")]
    pub file: String,
}

/// Subcommands for `nau deps`.
#[derive(clap::Subcommand)]
pub enum DepsCommand {
    /// Show dependency tree for a package
    Show {
        /// Package name or path to nau.lua file
        package: String,

        /// Resolve all transitive dependencies (recursive)
        #[arg(long)]
        recursive: bool,

        /// Display as tree (requires --recursive)
        #[arg(long)]
        tree: bool,

        /// Print flat, ordered list (build order)
        #[arg(long)]
        flat: bool,

        /// Output structured JSON instead of human-friendly colored output.
        #[arg(long)]
        json: bool,
    },

    /// Fetch dependency closures for a pod's interpreted packages
    /// (ADR-0017, issue #13): resolve + download npm/pip closures into the
    /// pod store and record their pins in the pod lockfile. `pod add`/
    /// `pod sync` auto-fetch; this command forces a re-fetch without a
    /// build. `--latest` re-resolves even locked packages.
    Fetch {
        /// Pod to operate on (default: `default`).
        #[arg(long, value_name = "POD")]
        name: Option<String>,

        /// Pod state root (default: $XDG_DATA_HOME/nau/pods).
        #[arg(long)]
        root: Option<String>,

        /// Re-resolve latest closures even for locked packages.
        #[arg(long)]
        latest: bool,

        /// Output structured JSON instead of human-friendly output.
        #[arg(long)]
        json: bool,
    },
}

/// Subcommands for `nau cache`.
#[derive(clap::Subcommand)]
pub enum CacheCommand {
    /// Show cache statistics (entries, packages, disk usage)
    Info {
        /// Cache directory (default: ~/.cache/nau/pkgs)
        #[arg(long)]
        cache: Option<String>,
    },

    /// Remove all cached packages
    Clear {
        /// Cache directory (default: ~/.cache/nau/pkgs)
        #[arg(long)]
        cache: Option<String>,

        /// Skip confirmation prompt
        #[arg(long, default_value_t = false)]
        force: bool,
    },

    /// Remove cache entries not accessed in N days (default: 30)
    Prune {
        /// Maximum age in days (default: 30)
        #[arg(long, default_value_t = 30)]
        days: u64,

        /// Cache directory (default: ~/.cache/nau/pkgs)
        #[arg(long)]
        cache: Option<String>,

        /// Skip confirmation prompt
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}

/// Subcommands for `nau runtime` (ADR-0012 step 5, Phase 24b):
/// on-device install/remove/upgrade/rollback/gc over generations.
#[derive(clap::Subcommand)]
pub enum RuntimeCommand {
    /// Install a snap on-device: resolve, download, verify, unpack into
    /// the content store, and activate a new generation (sysext tree +
    /// unit reconciliation).
    Install {
        /// Snap name to install
        name: String,

        /// Snap channel to resolve from (default: latest/stable)
        #[arg(long, default_value = "latest/stable")]
        channel: String,

        /// State root for generations + content store
        /// (default: /var/lib/nau)
        #[arg(long)]
        state_dir: Option<String>,

        /// Output structured JSON instead of human-friendly output.
        #[arg(long)]
        json: bool,
    },

    /// Remove an installed snap: activate a new generation without it,
    /// stop/disable its units, and unlink its sysext tree (best-effort).
    Remove {
        /// Snap name to remove
        name: String,

        /// State root for generations + content store
        /// (default: /var/lib/nau)
        #[arg(long)]
        state_dir: Option<String>,

        /// Output structured JSON instead of human-friendly output.
        #[arg(long)]
        json: bool,
    },

    /// Upgrade installed snaps to their channel head. Only snaps whose
    /// resolved revision changed produce a new generation — no changes
    /// is a noted no-op.
    Upgrade {
        /// Snap name to upgrade (default: all installed snaps)
        name: Option<String>,

        /// Upgrade every installed snap
        #[arg(long)]
        all: bool,

        /// Snap channel to resolve from (default: latest/stable)
        #[arg(long, default_value = "latest/stable")]
        channel: String,

        /// State root for generations + content store
        /// (default: /var/lib/nau)
        #[arg(long)]
        state_dir: Option<String>,

        /// Output structured JSON instead of human-friendly output.
        #[arg(long)]
        json: bool,
    },

    /// Roll back to a previous generation (default: the one before the
    /// active one): flips the `active` symlink, relinks sysext trees,
    /// and reconciles daemon units.
    Rollback {
        /// Generation number to roll back to (default: previous)
        generation: Option<u64>,

        /// State root for generations + content store
        /// (default: /var/lib/nau)
        #[arg(long)]
        state_dir: Option<String>,

        /// Output structured JSON instead of human-friendly output.
        #[arg(long)]
        json: bool,
    },

    /// Garbage-collect the content store (mark-sweep over every
    /// generation manifest). Default keeps every generation; --prune
    /// additionally drops all but the active and previous generations
    /// before the sweep.
    Gc {
        /// Also drop all generations except active + previous before
        /// sweeping unreferenced blobs.
        #[arg(long)]
        prune: bool,

        /// Also sweep the downloads staging directory (re-fetchable
        /// .snap payload cache). Payloads written within the last hour
        /// are kept — a concurrent install may still need them.
        #[arg(long)]
        downloads: bool,

        /// State root for generations + content store
        /// (default: /var/lib/nau)
        #[arg(long)]
        state_dir: Option<String>,

        /// Output structured JSON instead of human-friendly output.
        #[arg(long)]
        json: bool,
    },

    /// Activate the current generation (ADR-0023 §4). Idempotent and
    /// boot-safe: a cold store is a clean no-op, and a half-written
    /// journal is discarded so boot never wedges. The emitted
    /// `nau-runtime-activate.service` oneshot runs this at boot.
    Activate {
        /// State root for generations + content store
        /// (default: /var/lib/nau)
        #[arg(long)]
        state_dir: Option<String>,

        /// Output structured JSON instead of human-friendly output.
        #[arg(long)]
        json: bool,
    },

    /// Reclaim sysupdate A/B slots stranded mid-install (issue #86). A
    /// killed install can leave a slot carrying the new version label
    /// with no matching UKI on the ESP — the next update then finds no
    /// writable target (systemd 249 has no vacuum verb). This command
    /// relabels such slots `_empty` when the evidence proves the loader
    /// never selected them, surfaces a named anomaly otherwise, and never
    /// touches the running version. Boot-safe: every refusal is a named
    /// no-op. The emitted `nau-slot-recovery.service` oneshot runs
    /// this at boot, ordered before `systemd-sysupdate.service`.
    RecoverSlots {
        /// Where the image mounts the ESP — the emitted unit bakes the
        /// image's own declaration in (default: /boot).
        #[arg(long, default_value = "/boot")]
        esp_mount: String,
    },
}

/// Subcommands for `nau key` (ADR-0011 step (e), ADR-0024 §4): the
/// key-ceremony operator surface. `--home` redirects the whole ceremony
/// away from `$HOME` (tests, alternate operators); it defaults to `HOME`.
///
/// - `keygen`  — mint `secret-key` and trust it (install `keys/<id>.pub`),
///   recording the creation in the ceremony ledger.
/// - `rotate`  — mint the successor `secret-key.new` (NOT trusted yet),
///   record the generation chain (id → replaced-by → date → window), and
///   dual-sign `--manifest` under the successor when given (re-attaching
///   provenance; issue #51).
/// - `promote` — move `secret-key.new` → `secret-key`, install its anchor.
/// - `revoke`  — drop a trust anchor, list it in `keys/revoked-keys`, and
///   date the revocation in the ledger.
/// - `list`    — print the ledger: the auditable ceremony trail.
/// - `verify`  — verify a manifest under the ceremony policy (either key
///   during a rotation window; revoked-only is a named error).
#[derive(clap::Subcommand)]
pub enum KeyCommand {
    /// Generate the update signing key under `--home`. Refuses to
    /// overwrite an existing key; installs the public key into the trust
    /// directory so the freshly minted key is immediately trusted.
    Keygen {
        /// Key-ceremony home (default: $HOME). The secret key lives at
        /// `<home>/.config/nau/secret-key`, anchors under `keys/`.
        #[arg(long)]
        home: Option<String>,

        /// Output structured JSON instead of human-friendly output.
        #[arg(long)]
        json: bool,
    },

    /// Mint the rotation successor at `<home>/.config/nau/secret-key.new`.
    /// The successor is NOT trusted until `key promote`: it has no anchor,
    /// so the keychain cannot accept its signature. Requires an existing
    /// `secret-key`; refuses to overwrite a pending `secret-key.new`.
    ///
    /// The generation chain (this key → successor → date → overlap
    /// window) is recorded in `keys/ceremony.json` (issue #51). With
    /// `--manifest`, that manifest is additionally dual-signed under the
    /// successor — the old signature entry is kept, and an attested
    /// entry's provenance is re-attached under the new signature (same
    /// claims, new key).
    Rotate {
        /// Key-ceremony home (default: $HOME).
        #[arg(long)]
        home: Option<String>,

        /// Manifest JSON to dual-sign under the successor (old signature
        /// kept; provenance re-attached when present).
        #[arg(long)]
        manifest: Option<String>,

        /// Overlap window, in days, recorded with the rotation: how long
        /// the rotated-out key's signatures stay first-class while the
        /// successor rolls out. Expired windows downgrade to a verify
        /// warning.
        #[arg(long, default_value_t = crate::sign::DEFAULT_WINDOW_DAYS)]
        window_days: u32,

        /// Output structured JSON instead of human-friendly output.
        #[arg(long)]
        json: bool,
    },

    /// Promote the pending rotation: `secret-key.new` → `secret-key`,
    /// overwriting the old secret, then install the successor's public
    /// key as a trust anchor. The old anchor is left in place (dual-trust
    /// overlap window) and stays revocable.
    Promote {
        /// Key-ceremony home (default: $HOME).
        #[arg(long)]
        home: Option<String>,

        /// Output structured JSON instead of human-friendly output.
        #[arg(long)]
        json: bool,
    },

    /// Revoke `key-id`: remove its trust anchor from the local key
    /// directory and record it in `keys/revoked-keys` so the build can
    /// carry the revocation to devices. The key id is the 16-hex prefix
    /// of the public key.
    Revoke {
        /// Key id (first 16 hex chars of the public key).
        key_id: String,

        /// Key-ceremony home (default: $HOME).
        #[arg(long)]
        home: Option<String>,

        /// Output structured JSON instead of human-friendly output.
        #[arg(long)]
        json: bool,
    },

    /// Print the ceremony ledger (`keys/ceremony.json`): every key the
    /// ceremony touched with its created/rotated/revoked dates and the
    /// generation chain — the auditable trail (issue #51).
    List {
        /// Key-ceremony home (default: $HOME).
        #[arg(long)]
        home: Option<String>,

        /// Output structured JSON instead of human-friendly output.
        #[arg(long)]
        json: bool,
    },

    /// Verify a manifest JSON under the ceremony policy: any signature
    /// from a live trusted key verifies; a rotated-out key past its
    /// overlap window verifies with a warning; a manifest signed only by
    /// revoked keys fails with a named error.
    Verify {
        /// Path to the manifest JSON to verify.
        manifest: String,

        /// Key-ceremony home (default: $HOME).
        #[arg(long)]
        home: Option<String>,

        /// Output structured JSON instead of human-friendly output.
        #[arg(long)]
        json: bool,
    },
}

/// Subcommands for `nau ca` (ADR-0045 amendment, #283 decided — the
/// host CA ceremony joins ADR-0024's): the coordinator CA is the ONE
/// trust root that signs every worker's short-lived host certificate,
/// distinct from the update-manifest signing key. `--home` redirects the
/// ceremony away from `$HOME` (tests, alternate operators).
#[derive(clap::Subcommand)]
pub enum CaCommand {
    /// Generate the host CA keypair under `--home` via `ssh-keygen`
    /// (ed25519, no passphrase). Refuses to overwrite an existing CA
    /// without `--force` — replacing the high-value trust root is a
    /// deliberate act. On success prints the public line and its
    /// ssh-keygen SHA256 fingerprint (the identity workers entries carry).
    Keygen {
        /// CA ceremony home (default: $HOME). The keypair lives at
        /// `<home>/.config/nau/ca/` (`ca` private 0600, `ca.pub`
        /// public).
        #[arg(long)]
        home: Option<String>,

        /// Replace an existing CA keypair. Both halves are removed
        /// before the mint — a failed regeneration can never leave the
        /// old public half paired with a new secret.
        #[arg(long)]
        force: bool,

        /// Output structured JSON instead of human-friendly output.
        #[arg(long)]
        json: bool,
    },

    /// Introspect the host CA: which halves are on disk, the public
    /// line, and the ssh-keygen SHA256 fingerprint. Absent CA is not an
    /// error (an informational hint, exit 0); a private half without its
    /// public half is a named refusal (fail closed).
    List {
        /// CA ceremony home (default: $HOME).
        #[arg(long)]
        home: Option<String>,

        /// Output structured JSON instead of human-friendly output.
        #[arg(long)]
        json: bool,
    },
}

/// Verbs for `nau pod` (pods, issue #2): imperative edits to one
/// pod's declaration + lockfile, mirroring the runtime command group's
/// lifecycle shape. The `--root` state override travels with each verb
/// (test-scoped redirection); `--name` travels on the `pod` command
/// itself before the verb and, via the flattened [`PodTarget`], on
/// every verb after it (issue #4) — `cmd_pod` merges the two positions
/// fail-closed.
#[derive(clap::Subcommand)]
pub enum PodCommand {
    /// Add a package to the selected pod: records it in the pod
    /// declaration and pins the resolved version in the lockfile.
    /// (Re)initializes an unknown pod. With `--snap`, sideloads a built
    /// `.snap` payload instead of resolving from the collection
    /// (issue #116).
    Add {
        #[command(flatten)]
        target: PodTarget,

        /// Package name, optionally with a version constraint
        /// (`name@constraint`, e.g. `ripgrep@14`). Required unless
        /// `--snap` carries the identity (issue #116).
        #[arg(required_unless_present = "snap")]
        package: Option<String>,

        /// Sideload a built `.snap` payload (issue #116): the payload's
        /// `meta/snap.yaml` is the identity, its sha3-384 the pin. A
        /// filename/name mismatch or a snapd infrastructure payload
        /// refuses fail-closed.
        #[arg(long, value_name = "SNAP", conflicts_with = "package")]
        snap: Option<String>,

        /// Acknowledge the sideloaded payload is unsigned (v1 carries
        /// no pod-side signature; snapd's `--dangerous` precedent).
        /// Without it the sideload refuses before any write. Only
        /// meaningful with `--snap`.
        #[arg(long, requires = "snap")]
        ack_unsigned: bool,

        /// Pod state root (default: $XDG_DATA_HOME/nau/pods, i.e.
        /// ~/.local/share/nau/pods). Overridable via NAU_POD_ROOT.
        /// Tests redirect this into tempdirs.
        #[arg(long)]
        root: Option<String>,
    },

    /// Declare the selected pod from a checked-in `pod.lua` file
    /// (gate-pod gap 5): the file is loaded, validated, and its content
    /// becomes the pod's declaration — REPLACING whatever was there,
    /// the file is the source of truth — then the pod reconciles
    /// through the same path add/sync uses (store, generation chain,
    /// bin farm). (Re)initializes an unknown pod.
    Declare {
        #[command(flatten)]
        target: PodTarget,

        /// Path to the `pod.lua` to load.
        #[arg(long, value_name = "FILE")]
        file: String,

        /// Pod state root (see `pod add --root`).
        #[arg(long)]
        root: Option<String>,
    },

    /// Remove a package from the selected pod: drops the declaration
    /// entry and the lockfile pin.
    Remove {
        #[command(flatten)]
        target: PodTarget,

        /// Package name (a trailing `@constraint` is ignored).
        package: String,

        /// Pod state root (see `pod add --root`).
        #[arg(long)]
        root: Option<String>,
    },

    /// Reconcile the selected pod's declaration into its store: build
    /// every declared package, install the changed set as a new
    /// generation, remove dropped ones, and refresh the bin farm behind
    /// the pod's `current` link. A no-op when nothing changed.
    Sync {
        #[command(flatten)]
        target: PodTarget,

        /// Opt into the one-time migration rebuild sweep (issue #142):
        /// lock entries being stamped for the FIRST time this sync are
        /// treated as drifted — they rebuild at their pins from the
        /// CURRENT recipes instead of baselining silently. The default
        /// sync stamps without rebuilding: existing pods must not
        /// mass-rebuild on their first post-#142 sync.
        #[arg(long)]
        rebuild_unstamped: bool,

        /// Pod state root (see `pod add --root`).
        #[arg(long)]
        root: Option<String>,
    },

    /// List the selected pod's packages with their resolved versions.
    List {
        #[command(flatten)]
        target: PodTarget,

        /// Pod state root (see `pod add --root`).
        #[arg(long)]
        root: Option<String>,
    },

    /// Print shell statements that put the selected pod's bin farm on
    /// PATH in the current shell (issue #47): `eval "$(nau pod
    /// shellenv)"`. Pure stdout — never writes an RC file, never starts
    /// a daemon (ADR-0015 §7, ADR-0016 §7). Fails on an unknown pod or
    /// one with no active generation.
    Shellenv {
        #[command(flatten)]
        target: PodTarget,

        /// Output structured JSON instead of shell statements.
        #[arg(long)]
        json: bool,

        /// Pod state root (see `pod add --root`).
        #[arg(long)]
        root: Option<String>,
    },

    /// Update the selected pod's packages to the newest versions
    /// matching their constraints (`pkg@14` = newest 14.x, bare `pkg` =
    /// newest available): repins the lockfile, rebuilds only what
    /// changed, and bumps the generation. A no-op when every package is
    /// already at its newest matching version; constrained packages
    /// whose newest candidate no longer matches are held at their pin.
    /// Update is version-driven — recipe-only drift in a package's
    /// requires closure is swept by `pod sync` (issue #142).
    Update {
        #[command(flatten)]
        target: PodTarget,

        /// Package names to update (default: all declared packages).
        packages: Vec<String>,

        /// Pod state root (see `pod add --root`).
        #[arg(long)]
        root: Option<String>,
    },

    /// Rebuild one declared package from the selected pod (issue #15):
    /// builds it again at ITS pins (version pin + dependency-closure
    /// pin) and installs the result — the cached closure is reused,
    /// never re-fetched, and the sync hold check is bypassed for this
    /// one package. `--latest` additionally re-resolves the dependency
    /// closure, moving the deps pin deliberately (ADR-0017 Decision 5).
    Rebuild {
        #[command(flatten)]
        target: PodTarget,

        /// Package name to rebuild (must be declared in the pod).
        package: String,

        /// Also re-resolve the dependency closure (`deps fetch
        /// --latest` semantics): moves the deps pin deliberately,
        /// recording a fresh `fetched_at` (ADR-0017 Decision 5).
        #[arg(long)]
        latest: bool,

        /// Pod state root (see `pod add --root`).
        #[arg(long)]
        root: Option<String>,
    },

    /// Rebuild named members from their CURRENT recipes (issue #142),
    /// regardless of whether they are declared: the escape hatch for
    /// undeclarable requires-closure members (curl riding git's
    /// closure) and for fixes that predate a pod's recipe-closure
    /// baseline — sync can never reach either. A member the rebuild
    /// finds byte-identical keeps its store content (no generation
    /// churn); a changed member installs with its binary claims
    /// collected, so its farm entries materialize. Unrelated drifted
    /// members are baselined (current recipe hash stamped, installed
    /// content kept), never rebuilt. Explicit opt-in:
    /// build-tool failures are loud errors here, never a broken day-0
    /// sync. Blob-pinned (sideloaded) members refuse — the payload is
    /// their content, there is no recipe.
    Refresh {
        #[command(flatten)]
        target: PodTarget,

        /// Member names to rebuild: declared packages, loaded packages,
        /// or requires-closure members of the pod's package set.
        #[arg(required = true)]
        members: Vec<String>,

        /// Pod state root (see `pod add --root`).
        #[arg(long)]
        root: Option<String>,
    },

    /// Roll the selected pod back to a previous generation (default:
    /// the one before the current): flips that pod's `current` link
    /// only — never reboots, never touches system generations. Binaries
    /// the newer generation added disappear from the farm.
    Rollback {
        #[command(flatten)]
        target: PodTarget,

        /// Generation number to roll back to (default: previous).
        generation: Option<u64>,

        /// Pod state root (see `pod add --root`).
        #[arg(long)]
        root: Option<String>,
    },

    /// Garbage-collect the selected pod's content store: mark-sweep
    /// over every pod generation manifest. `--prune` additionally drops
    /// all but the pod's current + previous generations before
    /// sweeping, freeing their exclusive blobs (live generations keep
    /// theirs). System generations are never eligible.
    Gc {
        #[command(flatten)]
        target: PodTarget,

        /// Also drop all pod generations except current + previous
        /// before sweeping unreferenced blobs.
        #[arg(long)]
        prune: bool,

        /// Also sweep the downloads staging directory (re-fetchable
        /// .snap payload cache). Payloads written within the last hour
        /// are kept — a concurrent install may still need them.
        #[arg(long)]
        downloads: bool,

        /// Pod state root (see `pod add --root`).
        #[arg(long)]
        root: Option<String>,
    },
    /// Inspect and refresh the selected pod's secret references
    /// (ADR-0042, issue #183). Values never print (D8): references,
    /// per-source health, and session-cache state only.
    Secrets {
        #[command(flatten)]
        target: PodTarget,

        #[command(subcommand)]
        command: PodSecretsCommand,

        /// Pod state root (see `pod add --root`).
        #[arg(long)]
        root: Option<String>,
    },

    /// Run an app from the pod (ADR-0016, ticket #11) — the visible
    /// ADR-0049 spelling of the hidden `nau run` alias, over the same
    /// shared RunArgs struct. Two forms, dispatched declared-app-first: a
    /// declared app runs confined behind its declared grants (a
    /// `confined` app on a host without its backend FAILS CLOSED);
    /// `pod run [--pod N] -- <cmd…>` execs an arbitrary command with the
    /// pod's env overlaid (farm-first PATH + loader-lib
    /// LD_LIBRARY_PATH), no sandbox — a name that IS a declared app
    /// always wins over the command form. TRUST BOUNDARY: the command
    /// form runs unsandboxed with the caller's full privileges and farm
    /// names shadow host PATH. The pre-verb pod `--name` merges
    /// fail-closed onto the run's own `--pod`.
    Run {
        #[command(flatten)]
        args: RunArgs,
    },
}

/// Subcommands for `nau pod secrets` (ADR-0042 D3/D7/D8).
#[derive(clap::Subcommand)]
pub enum PodSecretsCommand {
    /// List the pod's folded secret references with their session-cache
    /// state (hit / stale / miss). Values never print (ADR-0042 D8).
    List,
    /// Resolve every reference through its provider and report
    /// per-source health; exits 1 naming failures. Values never print.
    Check,
    /// Bust the pod's session-cache entries, re-resolve every reference
    /// through its provider, and rewrite the active entry (rotation,
    /// ADR-0042 D3). Prunes stale-generation entries.
    Refresh,
}

/// The `nau pod run` / legacy `nau run` arguments (ADR-0049): one
/// `#[derive(clap::Args)]` struct shared by both spellings, so each
/// parses to the same shape and dispatches to the identical handler
/// ([`crate::commands::cmd_run`]). The struct-level `trailing_var_arg`
/// lands on whichever command flattens it — both the hidden top-level
/// `run` and the visible `pod run` verb.
#[derive(clap::Args, Clone, Debug, PartialEq, Eq)]
#[command(trailing_var_arg = true)]
pub struct RunArgs {
    /// App name: a declared app from the pod, or — as everything after
    /// `--` — the start of an arbitrary command whose remaining words
    /// are the rest of the args. Declared-first: a name that matches a
    /// declared app always runs that app, confined.
    pub app: Option<String>,

    /// Pod to operate on (default: `default`).
    #[arg(long, value_name = "POD")]
    pub pod: Option<String>,

    /// Pod state root (default: $XDG_DATA_HOME/nau/pods).
    #[arg(long)]
    pub root: Option<String>,

    /// Arguments passed through to the app. Everything after `--` is
    /// forwarded verbatim.
    #[arg(trailing_var_arg = true)]
    pub app_args: Vec<String>,
}

/// Pod selector shared by every `nau pod` verb: the `--name` flag
/// accepted AFTER the verb (`nau pod add jq --name work`). Merged
/// fail-closed in `cmd_pod` against the before-verb value on the `pod`
/// command itself — conflicting values are a hard error, never a silent
/// precedence.
#[derive(clap::Args)]
pub struct PodTarget {
    /// Pod to operate on (default: `default`).
    #[arg(long, value_name = "POD")]
    pub name: Option<String>,
}

impl PodCommand {
    /// The verb-position `--name` (from the flattened [`PodTarget`]),
    /// for merging with the before-verb value in `cmd_pod`.
    pub fn pod_name(&self) -> Option<&str> {
        match self {
            PodCommand::Add { target, .. }
            | PodCommand::Declare { target, .. }
            | PodCommand::Remove { target, .. }
            | PodCommand::Sync { target, .. }
            | PodCommand::Refresh { target, .. }
            | PodCommand::List { target, .. }
            | PodCommand::Shellenv { target, .. }
            | PodCommand::Update { target, .. }
            | PodCommand::Rebuild { target, .. }
            | PodCommand::Rollback { target, .. }
            | PodCommand::Gc { target, .. }
            | PodCommand::Secrets { target, .. } => target.name.as_deref(),
            // `pod run` carries the legacy `nau run` flag surface (`--pod`),
            // not the verb-position `--name`; its pod selection merges in
            // the cmd_pod early arm.
            PodCommand::Run { .. } => None,
        }
    }
}

/// Subcommands for `nau index`.
#[derive(clap::Subcommand)]
pub enum IndexCommand {
    /// List snaps in the package index
    List {
        /// Path to the package index file (default: package-index.json)
        #[arg(long, default_value = crate::index::DEFAULT_INDEX)]
        index: String,
    },

    /// Add a snap to the package index
    Add {
        /// Snap name
        name: String,

        /// Summary/description
        #[arg(long)]
        summary: Option<String>,

        /// Store name (defaults to the snap name)
        #[arg(long)]
        store_name: Option<String>,

        /// Channel (default: latest/stable)
        #[arg(long, default_value = "latest/stable")]
        channel: String,

        /// Alternative name(s) this snap is known by (repeatable)
        #[arg(long)]
        alias: Vec<String>,

        /// Path to the package index file (default: package-index.json)
        #[arg(long, default_value = crate::index::DEFAULT_INDEX)]
        index: String,
    },

    /// Resolve store snap pins: query the Snap Store for each entry
    Resolve {
        /// Path to the package index file (default: package-index.json)
        #[arg(long, default_value = crate::index::DEFAULT_INDEX)]
        index: String,

        /// Channel to resolve from (default: latest/stable)
        #[arg(long, default_value = "latest/stable")]
        channel: String,

        /// Image base(s) to add base-track passes for (repeatable). A base
        /// like `core22` makes resolve also pin every entry on `22/stable` —
        /// the channel the image build derives for kernel/gadget snaps
        /// (ADR-0019, issue #69).
        #[arg(long)]
        base: Vec<String>,
    },

    /// Update package source inputs (re-fetch GitHub repositories).
    /// Ensures the local cache matches the remote.
    Update {
        /// Path to the Lua config file (default: nau.lua).
        /// If not found, updates the default package index.
        #[arg(short, long, default_value = "nau.lua")]
        file: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }

    fn parse_build(args: &[&str]) -> Command {
        Cli::try_parse_from(args).unwrap().command
    }

    #[test]
    fn test_build_defaults() {
        match parse_build(&["nau", "build"]) {
            Command::Build {
                args:
                    BuildArgs {
                        file,
                        stage,
                        output,
                        arch,
                        output_name,
                        ..
                    },
                command: None,
            } => {
                assert_eq!(file, "nau.lua");
                // No --stage flag: default stage, tracked as None so the
                // build knows it may wipe nau's own ./stage/.
                assert_eq!(stage, None);
                assert_eq!(output, ".");
                assert!(arch.is_empty());
                assert!(output_name.is_none());
            }
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_with_file_flag() {
        match parse_build(&["nau", "build", "--file", "my-snap.lua"]) {
            Command::Build {
                args: BuildArgs { file, .. },
                command: None,
            } => assert_eq!(file, "my-snap.lua"),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_with_short_file_flag() {
        match parse_build(&["nau", "build", "-f", "other.lua"]) {
            Command::Build {
                args: BuildArgs { file, .. },
                command: None,
            } => assert_eq!(file, "other.lua"),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_with_stage_and_output() {
        match parse_build(&[
            "nau",
            "build",
            "--stage",
            "/tmp/stage",
            "--output",
            "/tmp/out",
        ]) {
            Command::Build {
                args: BuildArgs { stage, output, .. },
                command: None,
            } => {
                assert_eq!(stage, Some("/tmp/stage".to_string()));
                assert_eq!(output, "/tmp/out");
            }
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_with_single_arch() {
        match parse_build(&["nau", "build", "--arch", "arm64"]) {
            Command::Build {
                args: BuildArgs { arch, .. },
                command: None,
            } => assert_eq!(arch, &["arm64"]),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_with_multi_arch() {
        match parse_build(&["nau", "build", "--arch", "amd64", "-A", "arm64"]) {
            Command::Build {
                args: BuildArgs { arch, .. },
                command: None,
            } => assert_eq!(arch, &["amd64", "arm64"]),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_with_positional_output_name() {
        match parse_build(&["nau", "build", "server"]) {
            Command::Build {
                args: BuildArgs { output_name, .. },
                command: None,
            } => {
                assert_eq!(output_name.as_deref(), Some("server"))
            }
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_with_positional_and_flags() {
        match parse_build(&[
            "nau",
            "build",
            "cli",
            "--file",
            "multi.lua",
            "--arch",
            "arm64",
        ]) {
            Command::Build {
                args:
                    BuildArgs {
                        output_name,
                        file,
                        arch,
                        ..
                    },
                command: None,
            } => {
                assert_eq!(output_name.as_deref(), Some("cli"));
                assert_eq!(file, "multi.lua");
                assert_eq!(arch, &["arm64"]);
            }
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_image_defaults() {
        match parse_build(&["nau", "image"]) {
            Command::Image {
                args:
                    ImageArgs {
                        file,
                        output,
                        arch,
                        channel,
                        cache,
                        output_name,
                        ..
                    },
                command: None,
            } => {
                assert_eq!(file, "nau.lua");
                assert_eq!(output, ".");
                assert_eq!(arch, "amd64");
                assert_eq!(channel, "latest/stable");
                assert!(cache.is_none());
                assert!(output_name.is_none());
            }
            _ => panic!("expected Image"),
        }
    }

    #[test]
    fn test_image_with_flags() {
        match parse_build(&[
            "nau",
            "image",
            "--file",
            "my-image.lua",
            "--output",
            "/tmp/img",
            "--arch",
            "arm64",
            "--channel",
            "latest/edge",
            "--cache",
            "/custom/cache",
            "my-system",
        ]) {
            Command::Image {
                args:
                    ImageArgs {
                        file,
                        output,
                        arch,
                        channel,
                        cache,
                        output_name,
                        ..
                    },
                command: None,
            } => {
                assert_eq!(file, "my-image.lua");
                assert_eq!(output, "/tmp/img");
                assert_eq!(arch, "arm64");
                assert_eq!(channel, "latest/edge");
                assert_eq!(cache.as_deref(), Some("/custom/cache"));
                assert_eq!(output_name.as_deref(), Some("my-system"));
            }
            _ => panic!("expected Image"),
        }
    }

    #[test]
    fn test_missing_subcommand_fails() {
        let result = Cli::try_parse_from(["nau"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_image_source_date_epoch() {
        match parse_build(&["nau", "image", "--source-date-epoch", "0"]) {
            Command::Image {
                args: ImageArgs {
                    source_date_epoch, ..
                },
                ..
            } => {
                assert_eq!(source_date_epoch.as_deref(), Some("0"));
            }
            _ => panic!("expected Image"),
        }
    }

    #[test]
    fn test_image_release_flag() {
        match parse_build(&["nau", "image", "--release", "site/nau"]) {
            Command::Image {
                args: ImageArgs { release, .. },
                ..
            } => {
                assert_eq!(release.as_deref(), Some("site/nau"));
            }
            _ => panic!("expected Image"),
        }
    }

    #[test]
    fn test_image_release_conflicts_with_output() {
        let result = Cli::try_parse_from([
            "nau",
            "image",
            "--release",
            "site/nau",
            "--output",
            "elsewhere",
        ]);
        assert!(
            result.is_err(),
            "--release replaces --output — combined use must fail at parse time"
        );
    }

    // ── New flag tests ──

    #[test]
    fn test_build_all_flag() {
        match parse_build(&["nau", "build", "--all"]) {
            Command::Build {
                args: BuildArgs { all, .. },
                command: None,
            } => assert!(all),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_cache_flag() {
        match parse_build(&["nau", "build", "--cache", "/tmp/cache"]) {
            Command::Build {
                args: BuildArgs { cache, .. },
                command: None,
            } => {
                assert_eq!(cache.as_deref(), Some("/tmp/cache"));
            }
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_json_flag() {
        match parse_build(&["nau", "build", "--json"]) {
            Command::Build {
                args: BuildArgs { json, .. },
                command: None,
            } => assert!(json),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_target_flag() {
        match parse_build(&["nau", "build", "--target", "aarch64-linux-gnu"]) {
            Command::Build {
                args: BuildArgs { target, .. },
                command: None,
            } => {
                assert_eq!(target.as_deref(), Some("aarch64-linux-gnu"));
            }
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_update_one_input() {
        match parse_build(&["nau", "build", "--update", "pkgs"]) {
            Command::Build {
                args: BuildArgs { update, .. },
                command: None,
            } => assert_eq!(update.as_deref(), Some("pkgs")),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_update_all_inputs() {
        match parse_build(&["nau", "build", "--update"]) {
            Command::Build {
                args: BuildArgs { update, .. },
                command: None,
            } => assert_eq!(update.as_deref(), Some("")),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_offline_flag() {
        match parse_build(&["nau", "build", "--offline"]) {
            Command::Build {
                args: BuildArgs { offline, .. },
                command: None,
            } => assert!(offline),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_lock_subcommand_defaults() {
        match Cli::try_parse_from(["nau", "lock"]).unwrap().command {
            Command::Lock(LockArgs {
                file,
                lockfile,
                json,
            }) => {
                assert_eq!(file, "nau.lua");
                assert_eq!(lockfile, "nau.lock");
                assert!(!json);
            }
            _ => panic!("expected Lock"),
        }
    }

    #[test]
    fn test_lock_subcommand_flags() {
        match Cli::try_parse_from([
            "nau",
            "lock",
            "--file",
            "cfg.lua",
            "--lockfile",
            "other.lock",
        ])
        .unwrap()
        .command
        {
            Command::Lock(LockArgs { file, lockfile, .. }) => {
                assert_eq!(file, "cfg.lua");
                assert_eq!(lockfile, "other.lock");
            }
            _ => panic!("expected Lock"),
        }
    }

    #[test]
    fn test_lock_subcommand_json_flag() {
        match Cli::try_parse_from(["nau", "lock", "--json", "--lockfile", "p.lock"])
            .unwrap()
            .command
        {
            Command::Lock(LockArgs { lockfile, json, .. }) => {
                assert!(json);
                assert_eq!(lockfile, "p.lock");
            }
            _ => panic!("expected Lock"),
        }
    }

    #[test]
    fn test_image_json_flag() {
        match parse_build(&["nau", "image", "--json"]) {
            Command::Image {
                args: ImageArgs { json, .. },
                ..
            } => assert!(json),
            _ => panic!("expected Image"),
        }
    }

    #[test]
    fn test_deps_json_flag() {
        let args = ["nau", "deps", "show", "glibc", "--json"];
        let cmd = Cli::try_parse_from(args).unwrap().command;
        match cmd {
            Command::Deps(DepsCommand::Show { json, .. }) => assert!(json),
            _ => panic!("expected Deps::Show"),
        }
    }

    #[test]
    fn test_deps_fetch_parses() {
        let args = ["nau", "deps", "fetch", "--name", "work", "--latest"];
        let cmd = Cli::try_parse_from(args).unwrap().command;
        match cmd {
            Command::Deps(DepsCommand::Fetch { name, latest, .. }) => {
                assert_eq!(name.as_deref(), Some("work"));
                assert!(latest);
            }
            _ => panic!("expected Deps::Fetch"),
        }
    }

    #[test]
    fn test_build_all_flags_combo() {
        match parse_build(&[
            "nau",
            "build",
            "--all",
            "--cache",
            "/tmp/cache",
            "--json",
            "--target",
            "aarch64-linux-gnu",
        ]) {
            Command::Build {
                args:
                    BuildArgs {
                        all,
                        cache,
                        json,
                        target,
                        ..
                    },
                command: None,
            } => {
                assert!(all);
                assert_eq!(cache.as_deref(), Some("/tmp/cache"));
                assert!(json);
                assert_eq!(target.as_deref(), Some("aarch64-linux-gnu"));
            }
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_check_with_json_flag() {
        match Cli::try_parse_from(["nau", "check", "cfg.lua", "--json"])
            .unwrap()
            .command
        {
            Command::Check(CheckArgs { file, json }) => {
                assert_eq!(file, "cfg.lua");
                assert!(json);
            }
            _ => panic!("expected Check"),
        }
    }

    #[test]
    fn test_completion_bash() {
        match Cli::try_parse_from(["nau", "completion", "bash"])
            .unwrap()
            .command
        {
            Command::Completion { shell } => {
                assert_eq!(shell, clap_complete::Shell::Bash);
            }
            _ => panic!("expected Completion"),
        }
    }

    #[test]
    fn test_cache_info() {
        match Cli::try_parse_from(["nau", "cache", "info"])
            .unwrap()
            .command
        {
            Command::Cache(CacheCommand::Info { .. }) => {}
            _ => panic!("expected Cache Info"),
        }
    }

    #[test]
    fn test_cache_clear() {
        match Cli::try_parse_from(["nau", "cache", "clear", "--force"])
            .unwrap()
            .command
        {
            Command::Cache(CacheCommand::Clear { force, .. }) => assert!(force),
            _ => panic!("expected Cache Clear"),
        }
    }

    #[test]
    fn test_cache_prune() {
        match Cli::try_parse_from(["nau", "cache", "prune", "--days", "60", "--force"])
            .unwrap()
            .command
        {
            Command::Cache(CacheCommand::Prune { days, force, .. }) => {
                assert_eq!(days, 60);
                assert!(force);
            }
            _ => panic!("expected Cache Prune"),
        }
    }

    #[test]
    fn test_runtime_install_defaults() {
        match Cli::try_parse_from(["nau", "runtime", "install", "hello"])
            .unwrap()
            .command
        {
            Command::Runtime(RuntimeCommand::Install {
                name,
                channel,
                state_dir,
                json,
            }) => {
                assert_eq!(name, "hello");
                assert_eq!(channel, "latest/stable");
                assert_eq!(state_dir, None);
                assert!(!json);
            }
            _ => panic!("expected Runtime Install"),
        }
    }

    #[test]
    fn test_runtime_install_flags() {
        match Cli::try_parse_from([
            "nau",
            "runtime",
            "install",
            "hello",
            "--channel",
            "latest/edge",
            "--state-dir",
            "/tmp/state",
            "--json",
        ])
        .unwrap()
        .command
        {
            Command::Runtime(RuntimeCommand::Install {
                channel,
                state_dir,
                json,
                ..
            }) => {
                assert_eq!(channel, "latest/edge");
                assert_eq!(state_dir.as_deref(), Some("/tmp/state"));
                assert!(json);
            }
            _ => panic!("expected Runtime Install"),
        }
    }

    #[test]
    fn test_runtime_remove_and_rollback_and_gc() {
        match Cli::try_parse_from(["nau", "runtime", "remove", "hello", "--json"])
            .unwrap()
            .command
        {
            Command::Runtime(RuntimeCommand::Remove { name, json, .. }) => {
                assert_eq!(name, "hello");
                assert!(json);
            }
            _ => panic!("expected Runtime Remove"),
        }
        match Cli::try_parse_from(["nau", "runtime", "rollback", "3"])
            .unwrap()
            .command
        {
            Command::Runtime(RuntimeCommand::Rollback { generation, .. }) => {
                assert_eq!(generation, Some(3));
            }
            _ => panic!("expected Runtime Rollback"),
        }
        match Cli::try_parse_from(["nau", "runtime", "rollback"])
            .unwrap()
            .command
        {
            Command::Runtime(RuntimeCommand::Rollback { generation, .. }) => {
                assert_eq!(generation, None);
            }
            _ => panic!("expected Runtime Rollback default"),
        }
        match Cli::try_parse_from(["nau", "runtime", "gc", "--prune", "--downloads"])
            .unwrap()
            .command
        {
            Command::Runtime(RuntimeCommand::Gc {
                prune, downloads, ..
            }) => {
                assert!(prune);
                assert!(downloads);
            }
            _ => panic!("expected Runtime Gc"),
        }
        // Defaults: no prune, no downloads sweep.
        match Cli::try_parse_from(["nau", "runtime", "gc"])
            .unwrap()
            .command
        {
            Command::Runtime(RuntimeCommand::Gc {
                prune, downloads, ..
            }) => {
                assert!(!prune);
                assert!(!downloads);
            }
            _ => panic!("expected Runtime Gc defaults"),
        }
    }

    #[test]
    fn test_runtime_activate() {
        match Cli::try_parse_from([
            "nau",
            "runtime",
            "activate",
            "--state-dir",
            "/tmp/state",
            "--json",
        ])
        .unwrap()
        .command
        {
            Command::Runtime(RuntimeCommand::Activate { state_dir, json }) => {
                assert_eq!(state_dir.as_deref(), Some("/tmp/state"));
                assert!(json);
            }
            _ => panic!("expected Runtime Activate"),
        }
        // Defaults: no state-dir, human output.
        match Cli::try_parse_from(["nau", "runtime", "activate"])
            .unwrap()
            .command
        {
            Command::Runtime(RuntimeCommand::Activate { state_dir, json }) => {
                assert!(state_dir.is_none());
                assert!(!json);
            }
            _ => panic!("expected Runtime Activate defaults"),
        }
    }

    #[test]
    fn test_runtime_upgrade_all() {
        match Cli::try_parse_from(["nau", "runtime", "upgrade", "--all"])
            .unwrap()
            .command
        {
            Command::Runtime(RuntimeCommand::Upgrade { name, all, .. }) => {
                assert_eq!(name, None);
                assert!(all);
            }
            _ => panic!("expected Runtime Upgrade"),
        }
        match Cli::try_parse_from(["nau", "runtime", "upgrade", "hello"])
            .unwrap()
            .command
        {
            Command::Runtime(RuntimeCommand::Upgrade { name, all, .. }) => {
                assert_eq!(name.as_deref(), Some("hello"));
                assert!(!all);
            }
            _ => panic!("expected Runtime Upgrade named"),
        }
    }

    // ── Stranded-slot recovery (issue #86) ──

    #[test]
    fn test_runtime_recover_slots_defaults_and_flag() {
        match Cli::try_parse_from(["nau", "runtime", "recover-slots"])
            .unwrap()
            .command
        {
            Command::Runtime(RuntimeCommand::RecoverSlots { esp_mount }) => {
                assert_eq!(esp_mount, "/boot", "the emitted units' default mount");
            }
            _ => panic!("expected Runtime RecoverSlots"),
        }
        match Cli::try_parse_from([
            "nau",
            "runtime",
            "recover-slots",
            "--esp-mount",
            "/boot/efi",
        ])
        .unwrap()
        .command
        {
            Command::Runtime(RuntimeCommand::RecoverSlots { esp_mount }) => {
                assert_eq!(esp_mount, "/boot/efi");
            }
            _ => panic!("expected Runtime RecoverSlots with --esp-mount"),
        }
    }

    // ── Key ceremony (ADR-0024 §4) ──

    #[test]
    fn test_key_keygen_defaults_and_flags() {
        match Cli::try_parse_from(["nau", "key", "keygen"])
            .unwrap()
            .command
        {
            Command::Key(KeyCommand::Keygen { home, json }) => {
                assert!(home.is_none());
                assert!(!json);
            }
            _ => panic!("expected Key Keygen"),
        }
        match Cli::try_parse_from(["nau", "key", "keygen", "--home", "/tmp/k", "--json"])
            .unwrap()
            .command
        {
            Command::Key(KeyCommand::Keygen { home, json }) => {
                assert_eq!(home.as_deref(), Some("/tmp/k"));
                assert!(json);
            }
            _ => panic!("expected Key Keygen with flags"),
        }
    }

    #[test]
    fn test_key_rotate_promote_and_revoke() {
        match Cli::try_parse_from(["nau", "key", "rotate"])
            .unwrap()
            .command
        {
            Command::Key(KeyCommand::Rotate {
                home,
                json,
                manifest,
                window_days,
            }) => {
                assert!(home.is_none());
                assert!(!json);
                assert!(manifest.is_none(), "no manifest to dual-sign by default");
                assert_eq!(
                    window_days,
                    crate::sign::DEFAULT_WINDOW_DAYS,
                    "default overlap window"
                );
            }
            _ => panic!("expected Key Rotate"),
        }
        match Cli::try_parse_from([
            "nau",
            "key",
            "rotate",
            "--manifest",
            "m.json",
            "--window-days",
            "7",
            "--home",
            "/tmp/k",
            "--json",
        ])
        .unwrap()
        .command
        {
            Command::Key(KeyCommand::Rotate {
                home,
                json,
                manifest,
                window_days,
            }) => {
                assert_eq!(home.as_deref(), Some("/tmp/k"));
                assert!(json);
                assert_eq!(manifest.as_deref(), Some("m.json"));
                assert_eq!(window_days, 7);
            }
            _ => panic!("expected Key Rotate with manifest and window"),
        }
        match Cli::try_parse_from(["nau", "key", "promote", "--json"])
            .unwrap()
            .command
        {
            Command::Key(KeyCommand::Promote { json, .. }) => assert!(json),
            _ => panic!("expected Key Promote"),
        }
        match Cli::try_parse_from([
            "nau",
            "key",
            "revoke",
            "deadbeef00112233",
            "--home",
            "/tmp/k",
        ])
        .unwrap()
        .command
        {
            Command::Key(KeyCommand::Revoke { key_id, home, json }) => {
                assert_eq!(key_id, "deadbeef00112233");
                assert_eq!(home.as_deref(), Some("/tmp/k"));
                assert!(!json);
            }
            _ => panic!("expected Key Revoke"),
        }
        // `revoke` requires its key-id positional.
        assert!(Cli::try_parse_from(["nau", "key", "revoke"]).is_err());
    }

    #[test]
    fn test_key_list_and_verify_parse() {
        match Cli::try_parse_from(["nau", "key", "list", "--json"])
            .unwrap()
            .command
        {
            Command::Key(KeyCommand::List { home, json }) => {
                assert!(home.is_none());
                assert!(json);
            }
            _ => panic!("expected Key List"),
        }
        match Cli::try_parse_from(["nau", "key", "verify", "m.json"])
            .unwrap()
            .command
        {
            Command::Key(KeyCommand::Verify {
                manifest,
                home,
                json,
            }) => {
                assert_eq!(manifest, "m.json");
                assert!(home.is_none());
                assert!(!json);
            }
            _ => panic!("expected Key Verify"),
        }
        // `verify` requires its manifest positional.
        assert!(Cli::try_parse_from(["nau", "key", "verify"]).is_err());
    }

    #[test]
    fn test_ca_keygen_and_list_parse() {
        match Cli::try_parse_from(["nau", "ca", "keygen"])
            .unwrap()
            .command
        {
            Command::Ca(CaCommand::Keygen { home, force, json }) => {
                assert!(home.is_none());
                assert!(!force);
                assert!(!json);
            }
            _ => panic!("expected Ca Keygen"),
        }
        match Cli::try_parse_from([
            "nau",
            "ca",
            "keygen",
            "--home",
            "/tmp/ca-home",
            "--force",
            "--json",
        ])
        .unwrap()
        .command
        {
            Command::Ca(CaCommand::Keygen { home, force, json }) => {
                assert_eq!(home.as_deref(), Some("/tmp/ca-home"));
                assert!(force);
                assert!(json);
            }
            _ => panic!("expected Ca Keygen with flags"),
        }
        match Cli::try_parse_from(["nau", "ca", "list", "--json"])
            .unwrap()
            .command
        {
            Command::Ca(CaCommand::List { home, json }) => {
                assert!(home.is_none());
                assert!(json);
            }
            _ => panic!("expected Ca List"),
        }
        // `ca` refuses to run without a verb.
        assert!(Cli::try_parse_from(["nau", "ca"]).is_err());
    }

    // ── OCI push/pull (Phase 25) ──

    #[test]
    fn test_push_defaults() {
        match Cli::try_parse_from(["nau", "push", "localhost:5000/team/app"])
            .unwrap()
            .command
        {
            Command::Push(PushArgs {
                reference,
                dir,
                snap,
                image,
                tag,
                username,
                password_stdin,
                insecure_http,
                mount_from,
                record,
                json,
            }) => {
                assert_eq!(reference, "localhost:5000/team/app");
                assert_eq!(dir, ".");
                assert!(snap.is_empty() && image.is_empty());
                assert!(tag.is_none());
                assert!(username.is_none());
                assert!(!password_stdin);
                assert!(!insecure_http);
                assert!(mount_from.is_none());
                assert!(record.is_none());
                assert!(!json);
            }
            _ => panic!("expected Push"),
        }
    }

    #[test]
    fn test_push_flags() {
        match Cli::try_parse_from([
            "nau",
            "push",
            "localhost:5000/team/app",
            "--dir",
            "out",
            "--snap",
            "a_1.0_amd64.snap",
            "--image",
            "b_1.0_amd64.img",
            "--tag",
            "v2",
            "--username",
            "ci",
            "--password-stdin",
            "--insecure-http",
            "--json",
        ])
        .unwrap()
        .command
        {
            Command::Push(PushArgs {
                dir,
                snap,
                image,
                tag,
                username,
                password_stdin,
                insecure_http,
                json,
                ..
            }) => {
                assert_eq!(dir, "out");
                assert_eq!(snap, ["a_1.0_amd64.snap"]);
                assert_eq!(image, ["b_1.0_amd64.img"]);
                assert_eq!(tag.as_deref(), Some("v2"));
                assert_eq!(username.as_deref(), Some("ci"));
                assert!(password_stdin);
                assert!(insecure_http);
                assert!(json);
            }
            _ => panic!("expected Push"),
        }
    }

    #[test]
    fn test_push_requires_reference() {
        assert!(Cli::try_parse_from(["nau", "push"]).is_err());
    }

    #[test]
    fn test_pull_defaults() {
        match Cli::try_parse_from(["nau", "pull", "ghcr.io/owner/repo:v1"])
            .unwrap()
            .command
        {
            Command::Pull(PullArgs {
                reference,
                out_dir,
                username,
                password_stdin,
                insecure_http,
                expect,
                install,
                state_dir,
                pod,
                allow_downgrade,
                json,
            }) => {
                assert_eq!(reference, "ghcr.io/owner/repo:v1");
                assert_eq!(out_dir, ".");
                assert!(username.is_none());
                assert!(!password_stdin);
                assert!(!insecure_http);
                assert!(expect.is_none());
                assert!(!install);
                assert!(state_dir.is_none());
                // Peer/static staging flags default off: registry
                // pulls keep writing files, pod-less.
                assert!(pod.is_none());
                assert!(!allow_downgrade);
                assert!(!json);
            }
            _ => panic!("expected Pull"),
        }
    }

    #[test]
    fn test_pull_flags() {
        match Cli::try_parse_from([
            "nau",
            "pull",
            "localhost:5000/team/app",
            "--out-dir",
            "pulled",
            "--username",
            "ci",
            "--password-stdin",
            "--insecure-http",
            "--expect",
            "built.json",
            "--install",
            "--state-dir",
            "st",
            "--json",
        ])
        .unwrap()
        .command
        {
            Command::Pull(PullArgs {
                out_dir,
                username,
                password_stdin,
                insecure_http,
                expect,
                install,
                state_dir,
                json,
                ..
            }) => {
                assert_eq!(out_dir, "pulled");
                assert_eq!(username.as_deref(), Some("ci"));
                assert!(password_stdin);
                assert!(insecure_http);
                assert_eq!(expect.as_deref(), Some("built.json"));
                assert!(install);
                assert_eq!(state_dir.as_deref(), Some("st"));
                assert!(json);
            }
            _ => panic!("expected Pull"),
        }
    }

    // ── QEMU boot-and-assert harness (issue #50) ──

    #[test]
    fn test_test_defaults() {
        match Cli::try_parse_from(["nau", "test", "disk.img"])
            .unwrap()
            .command
        {
            Command::Test(TestArgs {
                image,
                timeout,
                accel,
                log,
                require,
                firmware_dir,
                runs,
                expect_counter_seq,
                allow_no_completion,
                qemu_args,
                json,
            }) => {
                assert_eq!(image, "disk.img");
                assert_eq!(timeout, 120);
                assert_eq!(accel, Accel::Kvm);
                assert!(log.is_none());
                assert!(require.is_empty());
                assert!(firmware_dir.is_none());
                assert_eq!(runs, 1);
                assert!(expect_counter_seq.is_none());
                assert!(!allow_no_completion);
                assert!(qemu_args.is_empty(), "no QEMU args by default");
                assert!(!json);
            }
            _ => panic!("expected Test"),
        }
    }

    #[test]
    fn test_test_flags() {
        match Cli::try_parse_from([
            "nau",
            "test",
            "disk.img",
            "--timeout",
            "300",
            "--accel",
            "tcg",
            "--log",
            "evidence.log",
            "--require",
            "first",
            "--require",
            "Reached target Multi-User System.",
            "--runs",
            "4",
            "--expect-counter-seq",
            "3-0,2-1,1-2,0-3",
            "--json",
        ])
        .unwrap()
        .command
        {
            Command::Test(TestArgs {
                timeout,
                accel,
                log,
                require,
                runs,
                expect_counter_seq,
                allow_no_completion,
                json,
                ..
            }) => {
                assert_eq!(timeout, 300);
                assert_eq!(accel, Accel::Tcg);
                assert_eq!(log.as_deref(), Some("evidence.log"));
                assert_eq!(require, ["first", "Reached target Multi-User System."]);
                assert_eq!(runs, 4);
                assert_eq!(expect_counter_seq.as_deref(), Some("3-0,2-1,1-2,0-3"));
                assert!(!allow_no_completion);
                assert!(json);
            }
            _ => panic!("expected Test"),
        }
    }

    #[test]
    fn test_test_qemu_args_pass_through_verbatim() {
        // #80: guest networking for the in-guest sysupdate fetch. Each
        // value is one argv token; values starting with '-' use clap's
        // `=` form so they are not parsed as flags.
        match Cli::try_parse_from([
            "nau",
            "test",
            "disk.img",
            "--qemu-arg=-nic",
            "--qemu-arg",
            "user,model=virtio-net-pci",
        ])
        .unwrap()
        .command
        {
            Command::Test(TestArgs { qemu_args, .. }) => {
                assert_eq!(qemu_args, ["-nic", "user,model=virtio-net-pci"]);
            }
            _ => panic!("expected Test"),
        }
    }

    #[test]
    fn test_test_requires_image() {
        assert!(Cli::try_parse_from(["nau", "test"]).is_err());
    }

    // ── `nau run` command form (issue #102) ──

    #[test]
    fn test_run_double_dash_starts_the_command_form() {
        // `--` is sugar for the command form: the first word after it is
        // the program, the rest its args — forwarded verbatim, hyphens
        // included.
        match parse_build(&["nau", "run", "--", "git", "-c", "x", "status"]) {
            Command::Run {
                args: RunArgs { app, app_args, .. },
            } => {
                assert_eq!(app.as_deref(), Some("git"));
                assert_eq!(app_args, ["-c", "x", "status"]);
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_run_pod_flag_before_the_double_dash() {
        match parse_build(&["nau", "run", "--pod", "daily", "--", "true"]) {
            Command::Run {
                args: RunArgs { app, pod, .. },
            } => {
                assert_eq!(app.as_deref(), Some("true"));
                assert_eq!(pod.as_deref(), Some("daily"));
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_run_bare_parses_without_an_app() {
        // Bare `nau run` parses (the dispatch turns it into a usage
        // error naming both forms). It must NOT be a clap error: the
        // confined launcher forwards `<app> "$@"` without a `--`, so the
        // positional has to stay optional.
        match parse_build(&["nau", "run"]) {
            Command::Run {
                args: RunArgs { app, app_args, .. },
            } => {
                assert_eq!(app, None);
                assert!(app_args.is_empty());
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_run_declared_app_form_unchanged() {
        // The confined launcher's shape: bare positional + trailing args,
        // no `--` anywhere. (Hyphen-leading values here never parsed
        // without a `--`, before or after #102 — clap rejects them as
        // unknown flags.)
        match parse_build(&["nau", "run", "--pod", "work", "gcm", "cred"]) {
            Command::Run {
                args: RunArgs {
                    app, pod, app_args, ..
                },
            } => {
                assert_eq!(app.as_deref(), Some("gcm"));
                assert_eq!(pod.as_deref(), Some("work"));
                assert_eq!(app_args, ["cred"]);
            }
            _ => panic!("expected Run"),
        }
    }

    // ── `nau pod run` — the visible ADR-0049 spelling (ADR-0049 D3a) ──

    #[test]
    fn pod_run_parses_to_the_shared_args() {
        match parse_build(&["nau", "pod", "run", "--pod", "work", "gcm", "cred"]) {
            Command::Pod {
                name,
                command: PodCommand::Run { args },
            } => {
                assert_eq!(name, None);
                assert_eq!(
                    args,
                    RunArgs {
                        app: Some("gcm".to_string()),
                        pod: Some("work".to_string()),
                        root: None,
                        app_args: vec!["cred".to_string()],
                    }
                );
            }
            _ => panic!("expected Pod Run"),
        }
    }

    #[test]
    fn pod_run_and_legacy_run_parse_identically() {
        // The two spellings land on the same shared RunArgs — identical
        // effective flags parse identically, and both dispatch to the
        // one cmd_run handler (main()'s `Command::Run` arm for the
        // legacy spelling, cmd_pod's early `pod run` arm for the domain
        // one).
        let legacy = match parse_build(&[
            "nau", "run", "--pod", "work", "--root", "/tmp/r", "app", "--", "x", "-y",
        ]) {
            Command::Run { args } => args,
            _ => panic!("expected Run"),
        };
        match parse_build(&[
            "nau", "pod", "run", "--pod", "work", "--root", "/tmp/r", "app", "--", "x", "-y",
        ]) {
            Command::Pod {
                name,
                command: PodCommand::Run { args },
            } => {
                assert_eq!(name, None);
                assert_eq!(args, legacy, "both spellings parse identically");
            }
            _ => panic!("expected Pod Run"),
        }

        // The pre-verb `--name` still lands on the pod command itself.
        match parse_build(&["nau", "pod", "--name", "work", "run", "app"]) {
            Command::Pod {
                name,
                command: PodCommand::Run { args },
            } => {
                assert_eq!(name.as_deref(), Some("work"));
                assert_eq!(args.app.as_deref(), Some("app"));
                assert_eq!(args.pod, None);
            }
            _ => panic!("expected Pod Run"),
        }
    }

    // `--name` before the verb lands on the `pod` command's own field.
    #[test]
    fn pod_name_before_verb_parses_into_parent_field() {
        match Cli::try_parse_from(["nau", "pod", "--name", "daily", "add", "jq"])
            .unwrap()
            .command
        {
            Command::Pod { name, command } => {
                assert_eq!(name.as_deref(), Some("daily"));
                assert_eq!(command.pod_name(), None, "verb position unset");
            }
            _ => panic!("expected Pod"),
        }
    }

    // `--name` after the verb lands on the verb's flattened PodTarget.
    #[test]
    fn pod_name_after_verb_parses_into_verb_field() {
        match Cli::try_parse_from(["nau", "pod", "shellenv", "--name", "daily"])
            .unwrap()
            .command
        {
            Command::Pod { name, command } => {
                assert_eq!(name, None, "parent position unset");
                assert_eq!(command.pod_name(), Some("daily"));
            }
            _ => panic!("expected Pod"),
        }
    }

    // `pod add` needs a package OR `--snap` (issue #135): neither is a
    // missing-required error.
    fn parse_err(args: &[&str]) -> clap::error::Error {
        match Cli::try_parse_from(args) {
            Ok(_) => panic!("expected parse failure: {args:?}"),
            Err(e) => e,
        }
    }

    #[test]
    fn pod_add_requires_package_or_snap() {
        use clap::error::ErrorKind;
        assert_eq!(
            parse_err(&["nau", "pod", "add"]).kind(),
            ErrorKind::MissingRequiredArgument
        );
    }

    // `--snap` and the package positional are mutually exclusive.
    #[test]
    fn pod_add_snap_conflicts_with_package() {
        use clap::error::ErrorKind;
        assert_eq!(
            parse_err(&["nau", "pod", "add", "--snap", "p.snap", "hello"]).kind(),
            ErrorKind::ArgumentConflict
        );
    }

    // `--ack-unsigned` is only meaningful with `--snap`.
    #[test]
    fn pod_add_ack_unsigned_requires_snap() {
        use clap::error::ErrorKind;
        assert_eq!(
            parse_err(&["nau", "pod", "add", "--ack-unsigned"]).kind(),
            ErrorKind::MissingRequiredArgument
        );
    }

    // The two happy shapes parse into their fields.
    #[test]
    fn pod_add_happy_shapes_parse() {
        match Cli::try_parse_from(["nau", "pod", "add", "hello"])
            .unwrap()
            .command
        {
            Command::Pod {
                command:
                    PodCommand::Add {
                        package,
                        snap,
                        ack_unsigned,
                        ..
                    },
                ..
            } => {
                assert_eq!(package.as_deref(), Some("hello"));
                assert!(snap.is_none());
                assert!(!ack_unsigned);
            }
            _ => panic!("expected pod add"),
        }
        match Cli::try_parse_from(["nau", "pod", "add", "--snap", "p.snap", "--ack-unsigned"])
            .unwrap()
            .command
        {
            Command::Pod {
                command:
                    PodCommand::Add {
                        package,
                        snap,
                        ack_unsigned,
                        ..
                    },
                ..
            } => {
                assert!(package.is_none());
                assert_eq!(snap.as_deref(), Some("p.snap"));
                assert!(ack_unsigned);
            }
            _ => panic!("expected pod add"),
        }
    }

    #[test]
    fn workers_count_is_bounded_one_to_fifty() {
        // M5: count 0 would run nothing and exit 0; the range parser
        // refuses it (and anything past the 50 fan-out cap) at the CLI
        // boundary.
        let base = [
            "nau",
            "workers",
            "provision",
            "--provider",
            "hetzner",
            "--type",
            "CX33",
            "--location",
            "hel1",
        ];
        match Cli::try_parse_from(base).unwrap().command {
            Command::Workers {
                command: WorkersCommand::Provision(WorkersProvisionArgs { count, .. }),
            } => assert_eq!(count, 1, "default count is one"),
            _ => panic!("expected Workers Provision"),
        }
        for good in ["1", "50"] {
            let mut args: Vec<&str> = base.to_vec();
            args.extend(["--count", good]);
            match Cli::try_parse_from(args).unwrap().command {
                Command::Workers {
                    command: WorkersCommand::Provision(WorkersProvisionArgs { count, .. }),
                } => assert_eq!(count, good.parse::<u32>().unwrap()),
                _ => panic!("expected Workers Provision"),
            }
        }
        for bad in ["0", "51"] {
            let mut args: Vec<&str> = base.to_vec();
            args.extend(["--count", bad]);
            let err = match Cli::try_parse_from(args) {
                Err(e) => e.to_string(),
                Ok(_) => panic!("count {bad} must be refused"),
            };
            assert!(
                err.contains("not in 1..=50"),
                "refusal names the range: {err}"
            );
        }
    }

    #[test]
    fn test_workers_issue_and_pickup_parse() {
        // Defaults: all pending identities, the 48h default validity, no
        // force, no wait (the #299 race fix is opt-in).
        match Cli::try_parse_from(["nau", "workers", "issue"])
            .unwrap()
            .command
        {
            Command::Workers {
                command:
                    WorkersCommand::Issue(WorkersIssueArgs {
                        home,
                        identity,
                        validity,
                        force,
                        wait,
                        timeout,
                        json,
                    }),
            } => {
                assert!(home.is_none());
                assert!(identity.is_none());
                assert_eq!(
                    validity,
                    crate::provision::publish::HOST_CERT_VALIDITY_DEFAULT
                );
                assert!(!force);
                assert!(!wait);
                assert_eq!(timeout, crate::provision::ISSUE_WAIT_DEFAULT_TIMEOUT_SECS);
                assert!(!json);
            }
            _ => panic!("expected Workers Issue"),
        }
        match Cli::try_parse_from([
            "nau",
            "workers",
            "issue",
            "--home",
            "/tmp/ca-home",
            "--identity",
            "nau-worker-abc123-01",
            "--validity",
            "+2d12h",
            "--force",
            "--wait",
            "--timeout",
            "30",
            "--json",
        ])
        .unwrap()
        .command
        {
            Command::Workers {
                command:
                    WorkersCommand::Issue(WorkersIssueArgs {
                        home,
                        identity,
                        validity,
                        force,
                        wait,
                        timeout,
                        json,
                    }),
            } => {
                assert_eq!(home.as_deref(), Some("/tmp/ca-home"));
                assert_eq!(identity.as_deref(), Some("nau-worker-abc123-01"));
                assert_eq!(validity, "+2d12h");
                assert!(force);
                assert!(wait);
                assert_eq!(timeout, 30);
                assert!(json);
            }
            _ => panic!("expected Workers Issue with flags"),
        }
        match Cli::try_parse_from(["nau", "workers", "pickup", "--home", "/tmp/ca-home"])
            .unwrap()
            .command
        {
            Command::Workers {
                command: WorkersCommand::Pickup(WorkersPickupArgs { home }),
            } => assert_eq!(home.as_deref(), Some("/tmp/ca-home")),
            _ => panic!("expected Workers Pickup"),
        }
    }

    // ── Doctor `--pod` flag shapes (issue #231) ──

    #[test]
    fn doctor_pod_bare_is_scope_only() {
        match Cli::try_parse_from(["nau", "doctor", "--pod"])
            .unwrap()
            .command
        {
            Command::Doctor { pod, fix, from } => {
                // Bare `--pod`: the scope flag with NO pod identity —
                // the pre-#231 surface, byte-for-byte.
                assert_eq!(pod, Some(None));
                assert!(!fix);
                assert_eq!(from, None);
            }
            _ => panic!("expected Doctor"),
        }
    }

    #[test]
    fn doctor_pod_with_name_carries_identity() {
        match Cli::try_parse_from(["nau", "doctor", "--pod", "work"])
            .unwrap()
            .command
        {
            Command::Doctor { pod, .. } => assert_eq!(pod.flatten().as_deref(), Some("work")),
            _ => panic!("expected Doctor"),
        }
        // The `=` form too.
        match Cli::try_parse_from(["nau", "doctor", "--pod=work"])
            .unwrap()
            .command
        {
            Command::Doctor { pod, .. } => assert_eq!(pod.flatten().as_deref(), Some("work")),
            _ => panic!("expected Doctor"),
        }
    }

    #[test]
    fn doctor_pod_does_not_swallow_a_following_flag() {
        match Cli::try_parse_from(["nau", "doctor", "--pod", "--fix"])
            .unwrap()
            .command
        {
            Command::Doctor { pod, fix, .. } => {
                assert_eq!(pod, Some(None), "`--fix` must not be eaten as the value");
                assert!(fix);
            }
            _ => panic!("expected Doctor"),
        }
    }

    #[test]
    fn doctor_without_pod_behaves_as_today() {
        match Cli::try_parse_from(["nau", "doctor", "--fix"])
            .unwrap()
            .command
        {
            Command::Doctor { pod, fix, from } => {
                assert_eq!(pod, None);
                assert!(fix);
                assert_eq!(from, None);
            }
            _ => panic!("expected Doctor"),
        }
    }

    // ── Domain namespaces (ADR-0049, as amended: `pool` not `farm`,
    //    `trust` flattened) ──

    #[test]
    fn domain_groups_are_visible_legacy_spellings_hidden() {
        let cmd = Cli::command();
        for visible in [
            "chart",
            "build",
            "image",
            "ship",
            "peer",
            "trust",
            "pool",
            "pod",
            "runtime",
            "doctor",
            "completion",
        ] {
            let sub = cmd
                .find_subcommand(visible)
                .unwrap_or_else(|| panic!("{visible} must exist"));
            assert!(!sub.is_hide_set(), "{visible} must be visible");
        }
        for hidden in [
            "check",
            "eval",
            "lock",
            "lint",
            "audit",
            "search",
            "index",
            "deps",
            "cache",
            "key",
            "ca",
            "push",
            "pull",
            "serve",
            "peers",
            "export",
            "test",
            "verify-image",
            "run",
            "workers",
            "__eval-worker",
            "__check-worker",
            "__worker-cap",
            "__worker-job",
        ] {
            let sub = cmd
                .find_subcommand(hidden)
                .unwrap_or_else(|| panic!("{hidden} must exist"));
            assert!(sub.is_hide_set(), "{hidden} must be hidden");
        }
    }

    // ── External subcommands (ADR-0049 Decision 5, #324) ──

    #[test]
    fn unknown_verbs_arrive_as_the_external_catch_all() {
        // git semantics: the verb is consumed, the rest forwarded verbatim.
        match Cli::try_parse_from(["nau", "foo", "a", "-b"])
            .unwrap()
            .command
        {
            Command::External(argv) => {
                let strs: Vec<String> = argv
                    .iter()
                    .map(|s| s.to_string_lossy().into_owned())
                    .collect();
                assert_eq!(strs, ["foo", "a", "-b"]);
            }
            _ => panic!("expected the external catch-all"),
        }
        // Shapes clap only delivers after `--` or as bare values still
        // land in the catch-all — where the charset validator refuses
        // them before any lookup.
        for bad in [
            ["nau", "--", "-x"].as_slice(),
            ["nau", ""].as_slice(),
            ["nau", "foo.bar"].as_slice(),
        ] {
            match Cli::try_parse_from(bad).unwrap().command {
                Command::External(_) => {}
                _ => panic!("expected {bad:?} in the external catch-all"),
            }
        }
        // A bare hyphen-leading verb never reaches the catch-all: clap
        // refuses it as an unknown flag first (parse must fail).
        assert!(
            Cli::try_parse_from(["nau", "-x"]).is_err(),
            "-x without -- is clap's unknown-argument refusal, not a lookup"
        );
    }

    #[test]
    fn real_variants_never_reach_the_external_catch_all() {
        // Public domain group.
        assert!(matches!(
            Cli::try_parse_from(["nau", "chart", "check", "cfg.lua"])
                .unwrap()
                .command,
            Command::Chart { .. }
        ));
        // Hidden legacy spelling.
        assert!(matches!(
            Cli::try_parse_from(["nau", "push", "localhost:5000/team/app"])
                .unwrap()
                .command,
            Command::Push { .. }
        ));
        // Hidden internal workers.
        assert!(matches!(
            Cli::try_parse_from(["nau", "__eval-worker"])
                .unwrap()
                .command,
            Command::EvalWorker
        ));
        assert!(matches!(
            Cli::try_parse_from(["nau", "__worker-cap"])
                .unwrap()
                .command,
            Command::WorkerCap
        ));
        // A planted `nau-chart`/`nau-__eval-worker` helper is only ever
        // consulted for verbs no real variant claims; these never get
        // there (clap matches real subcommands before the external
        // capture). normalize_domain passes the catch-all through
        // untouched so main's dispatch owns it.
        let external = Command::External(vec!["foo".into()]);
        assert!(matches!(normalize_domain(external), Command::External(_)));
    }

    #[test]
    fn external_verb_charset_is_gits_rule() {
        assert!(is_external_verb("foo"));
        assert!(is_external_verb("credential-manager"));
        assert!(is_external_verb("a1-2b"));
        // Dots, colons, path separators, leading dash, uppercase, empty.
        assert!(!is_external_verb("foo.bar"));
        assert!(!is_external_verb("foo:bar"));
        assert!(!is_external_verb("foo/bar"));
        assert!(!is_external_verb("../evil"));
        assert!(!is_external_verb("-x"));
        assert!(!is_external_verb("Foo"));
        assert!(!is_external_verb(""));
        assert!(!is_external_verb("á"));
    }

    #[test]
    fn external_dispatch_refuses_bad_verbs_and_missing_helpers() {
        // Charset refusals name the rule and never reach a lookup.
        let err = run_external(&["foo.bar".into()]).unwrap_err();
        assert!(
            err.to_string().contains("must match [a-z][a-z0-9-]*"),
            "unexpected refusal: {err:#}"
        );
        // Unknown verb with no helper anywhere: the named not-found
        // refusal. (No sibling of this test binary and nothing on PATH
        // is named nau-definitely-not-a-verb-324.)
        let err = run_external(&["definitely-not-a-verb-324".into()]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unknown command `definitely-not-a-verb-324`")
                && msg.contains("no `nau-definitely-not-a-verb-324` extension found"),
            "unexpected refusal: {msg}"
        );
    }

    #[test]
    fn chart_namespace_folds_onto_the_legacy_commands() {
        let fold = |argv: &[&str]| normalize_domain(Cli::try_parse_from(argv).unwrap().command);
        match fold(&["nau", "chart", "check", "cfg.lua", "--json"]) {
            Command::Check(CheckArgs { file, json }) => {
                assert_eq!(file, "cfg.lua");
                assert!(json);
            }
            _ => panic!("expected chart check → Check"),
        }
        match fold(&["nau", "chart", "eval-worker"]) {
            Command::EvalWorker => {}
            _ => panic!("expected chart eval-worker → EvalWorker"),
        }
        match fold(&["nau", "chart", "check-worker"]) {
            Command::CheckWorker => {}
            _ => panic!("expected chart check-worker → CheckWorker"),
        }
        match fold(&["nau", "chart", "deps", "show", "jq"]) {
            Command::Deps(DepsCommand::Show { package, .. }) => assert_eq!(package, "jq"),
            _ => panic!("expected chart deps → Deps"),
        }
        match fold(&["nau", "chart", "index", "list"]) {
            Command::Index(IndexCommand::List { .. }) => {}
            _ => panic!("expected chart index → Index"),
        }
        // The legacy spelling still folds through unchanged.
        match fold(&["nau", "check", "cfg.lua"]) {
            Command::Check(CheckArgs { file, .. }) => assert_eq!(file, "cfg.lua"),
            _ => panic!("expected legacy check"),
        }
    }

    #[test]
    fn build_namespace_accepts_snap_and_cache_beside_the_legacy_spelling() {
        let fold = |argv: &[&str]| normalize_domain(Cli::try_parse_from(argv).unwrap().command);
        // `build snap` — the namespaced build (`snap` dispatches the
        // verb, it never lands in the positional).
        match fold(&["nau", "build", "snap", "--file", "x.lua"]) {
            Command::Build {
                args: BuildArgs {
                    file, output_name, ..
                },
                command: None,
            } => {
                assert_eq!(file, "x.lua");
                assert!(
                    output_name.is_none(),
                    "`snap` dispatches the verb, not the positional"
                );
            }
            _ => panic!("expected build snap → Build"),
        }
        // Bare `build` — the legacy spelling: flags on the group itself.
        match fold(&["nau", "build", "--file", "x.lua"]) {
            Command::Build {
                args: BuildArgs { file, .. },
                command: None,
            } => assert_eq!(file, "x.lua"),
            _ => panic!("expected bare build → Build"),
        }
        // The positional output_name survives beside the subcommands.
        match fold(&["nau", "build", "server"]) {
            Command::Build {
                args: BuildArgs { output_name, .. },
                command: None,
            } => {
                assert_eq!(output_name.as_deref(), Some("server"))
            }
            _ => panic!("expected positional output name"),
        }
        // `build cache` — the cache verbs under the build domain.
        match fold(&["nau", "build", "cache", "info"]) {
            Command::Cache(CacheCommand::Info { .. }) => {}
            _ => panic!("expected build cache → Cache"),
        }
    }

    #[test]
    fn image_ship_peer_namespaces_fold_onto_the_legacy_commands() {
        let fold = |argv: &[&str]| normalize_domain(Cli::try_parse_from(argv).unwrap().command);
        match fold(&["nau", "image", "build", "--arch", "arm64"]) {
            Command::Image {
                args: ImageArgs {
                    arch, output_name, ..
                },
                command: None,
            } => {
                assert_eq!(arch, "arm64");
                assert!(
                    output_name.is_none(),
                    "`build` dispatches the verb, not the positional"
                );
            }
            _ => panic!("expected image build → Image"),
        }
        // The legacy spelling: build flags directly on `image`.
        match fold(&["nau", "image", "--arch", "arm64"]) {
            Command::Image {
                args: ImageArgs { arch, .. },
                command: None,
            } => assert_eq!(arch, "arm64"),
            _ => panic!("expected bare image → Image"),
        }
        match fold(&["nau", "image", "test", "d.img"]) {
            Command::Test(TestArgs { image, .. }) => assert_eq!(image, "d.img"),
            _ => panic!("expected image test → Test"),
        }
        match fold(&[
            "nau",
            "image",
            "verify",
            "--device",
            "/dev/disk/by-id/x",
            "--manifest",
            "m.json",
        ]) {
            Command::VerifyImage(VerifyImageArgs {
                device, manifest, ..
            }) => {
                assert_eq!(device, "/dev/disk/by-id/x");
                assert_eq!(manifest, "m.json");
            }
            _ => panic!("expected image verify → VerifyImage"),
        }
        match fold(&["nau", "ship", "push", "localhost:5000/a/b"]) {
            Command::Push(PushArgs { reference, .. }) => {
                assert_eq!(reference, "localhost:5000/a/b")
            }
            _ => panic!("expected ship push → Push"),
        }
        match fold(&["nau", "ship", "pull", "localhost:5000/a:b"]) {
            Command::Pull(PullArgs { reference, .. }) => {
                assert_eq!(reference, "localhost:5000/a:b")
            }
            _ => panic!("expected ship pull → Pull"),
        }
        match fold(&["nau", "peer", "browse", "--secs", "5"]) {
            Command::Peers(PeersArgs { secs, .. }) => assert_eq!(secs, 5),
            _ => panic!("expected peer browse → Peers"),
        }
        match fold(&["nau", "peer", "serve", "--port", "8080"]) {
            Command::Serve(ServeArgs { port, .. }) => assert_eq!(port, Some(8080)),
            _ => panic!("expected peer serve → Serve"),
        }
        match fold(&["nau", "peer", "export", "out"]) {
            Command::Export(ExportArgs { out, .. }) => assert_eq!(out, "out"),
            _ => panic!("expected peer export → Export"),
        }
    }

    #[test]
    fn trust_verbs_map_onto_the_key_and_ca_ceremonies() {
        let fold = |argv: &[&str]| normalize_domain(Cli::try_parse_from(argv).unwrap().command);
        // Without --ca: the manifest-key ceremony.
        match fold(&["nau", "trust", "keygen"]) {
            Command::Key(KeyCommand::Keygen { home, json }) => {
                assert!(home.is_none());
                assert!(!json);
            }
            _ => panic!("expected trust keygen → Key"),
        }
        match fold(&["nau", "trust", "rotate", "--manifest", "m.json"]) {
            Command::Key(KeyCommand::Rotate { manifest, .. }) => {
                assert_eq!(manifest.as_deref(), Some("m.json"));
            }
            _ => panic!("expected trust rotate → Key"),
        }
        match fold(&["nau", "trust", "promote"]) {
            Command::Key(KeyCommand::Promote { .. }) => {}
            _ => panic!("expected trust promote → Key"),
        }
        match fold(&["nau", "trust", "revoke", "deadbeef00112233"]) {
            Command::Key(KeyCommand::Revoke { key_id, .. }) => {
                assert_eq!(key_id, "deadbeef00112233");
            }
            _ => panic!("expected trust revoke → Key"),
        }
        match fold(&["nau", "trust", "list"]) {
            Command::Key(KeyCommand::List { .. }) => {}
            _ => panic!("expected trust list → Key"),
        }
        match fold(&["nau", "trust", "verify", "m.json"]) {
            Command::Key(KeyCommand::Verify { manifest, .. }) => assert_eq!(manifest, "m.json"),
            _ => panic!("expected trust verify → Key"),
        }
        // With --ca: the host CA ceremony.
        match fold(&["nau", "trust", "keygen", "--ca", "--force"]) {
            Command::Ca(CaCommand::Keygen { force, .. }) => assert!(force),
            _ => panic!("expected trust keygen --ca → Ca"),
        }
        match fold(&["nau", "trust", "list", "--ca"]) {
            Command::Ca(CaCommand::List { .. }) => {}
            _ => panic!("expected trust list --ca → Ca"),
        }
        // `--force` is CA-scoped: refused without `--ca`.
        assert!(Cli::try_parse_from(["nau", "trust", "keygen", "--force"]).is_err());
        // The legacy spellings still parse.
        assert!(matches!(
            fold(&["nau", "key", "keygen"]),
            Command::Key(KeyCommand::Keygen { .. })
        ));
        assert!(matches!(
            fold(&["nau", "ca", "keygen"]),
            Command::Ca(CaCommand::Keygen { .. })
        ));
    }

    #[test]
    fn pool_namespace_wraps_workers_and_reveals_the_worker_verbs() {
        let fold = |argv: &[&str]| normalize_domain(Cli::try_parse_from(argv).unwrap().command);
        match fold(&[
            "nau",
            "pool",
            "provision",
            "--provider",
            "hetzner",
            "--type",
            "CX33",
            "--location",
            "hel1",
        ]) {
            Command::Workers {
                command: WorkersCommand::Provision(WorkersProvisionArgs { provider, .. }),
            } => assert_eq!(provider, "hetzner"),
            _ => panic!("expected pool provision → Workers"),
        }
        match fold(&[
            "nau",
            "pool",
            "burst",
            "--provider",
            "hetzner",
            "--type",
            "CX33",
            "--location",
            "hel1",
            "--",
            "true",
        ]) {
            Command::Workers {
                command: WorkersCommand::Burst(_),
            } => {}
            _ => panic!("expected pool burst → Workers"),
        }
        match fold(&["nau", "pool", "publish"]) {
            Command::Workers {
                command: WorkersCommand::ReceivePublish,
            } => {}
            _ => panic!("expected pool publish → ReceivePublish"),
        }
        match fold(&["nau", "pool", "issue", "--wait"]) {
            Command::Workers {
                command: WorkersCommand::Issue(WorkersIssueArgs { wait, .. }),
            } => assert!(wait),
            _ => panic!("expected pool issue → Workers"),
        }
        // The revealed worker verbs.
        match fold(&["nau", "pool", "probe"]) {
            Command::WorkerCap => {}
            _ => panic!("expected pool probe → WorkerCap"),
        }
        match fold(&["nau", "pool", "job", "job.json"]) {
            Command::WorkerJob { job_file } => assert_eq!(job_file, "job.json"),
            _ => panic!("expected pool job → WorkerJob"),
        }
        // The legacy spellings still parse (hidden aliases).
        match fold(&["nau", "workers", "pickup"]) {
            Command::Workers {
                command: WorkersCommand::Pickup(_),
            } => {}
            _ => panic!("expected workers pickup"),
        }
        match fold(&["nau", "__worker-cap"]) {
            Command::WorkerCap => {}
            _ => panic!("expected __worker-cap alias"),
        }
    }
}
