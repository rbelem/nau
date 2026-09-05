use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "shuttle",
    version,
    about = "Build Snap packages from Lua declarations"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Build a snap from a Lua declaration file
    Build {
        /// Path to the Lua config file (default: shuttle.lua)
        #[arg(short, long, default_value = "shuttle.lua")]
        file: String,

        /// Directory containing pre-built binaries (default: ./stage/).
        /// The default ./stage/ is shuttle-managed: wiped before every
        /// build phase so stale files cannot leak into a snap. A directory
        /// passed explicitly via --stage is never wiped — it must be empty
        /// (or new), or the build is refused.
        #[arg(short, long)]
        stage: Option<String>,

        /// Output directory for the .snap file (default: current dir)
        #[arg(short, long, default_value = ".")]
        output: String,

        /// Build only for specific architecture(s). Repeat for multiple.
        /// Default: build for all architectures declared in the config.
        #[arg(short = 'A', long)]
        arch: Vec<String>,

        /// Output name to build (from shuttle.lua outputs table).
        /// Default: build all outputs.
        output_name: Option<String>,

        /// Reproducible timestamp for SquashFS (Unix epoch seconds).
        /// Also read from SOURCE_DATE_EPOCH environment variable.
        /// Default: current time (non-reproducible).
        #[arg(long)]
        source_date_epoch: Option<String>,

        /// Path to lockfile (default: shuttle.lock).
        /// Locks source hashes for reproducible builds.
        #[arg(long, default_value = "shuttle.lock")]
        lockfile: String,

        /// Print dependency build order and exit (no build).
        #[arg(long)]
        order: bool,

        /// Build all transitive dependencies before building the requested output(s).
        /// Deps are built in topological order and stored in the binary cache.
        /// Use --cache to control where cached builds are stored.
        #[arg(long)]
        all: bool,

        /// Binary cache directory for built packages (default: ~/.cache/shuttle/pkgs).
        /// Cached builds are keyed by source SHA-256, so rebuilds only happen when
        /// source changes. Combine with --all to build full dependency trees efficiently.
        #[arg(long)]
        cache: Option<String>,

        /// Maximum cache size (e.g. "500M", "2G"). When exceeded, oldest entries
        /// are pruned automatically. Only applies when --cache is set or --all is used.
        #[arg(long)]
        cache_max_size: Option<String>,

        /// Override cross-compilation target for all packages.
        /// Sets the GNU target triplet (e.g. "aarch64-linux-gnu") and exports
        /// CC/CXX/LD/AR environment variables in the build sandbox.
        /// Overrides the `target` field on individual snap() declarations.
        #[arg(long)]
        target: Option<String>,

        /// Re-resolve input(s) to their latest branch head and update the
        /// lockfile pins before building. Pass an input name to update one
        /// input; omit the value to update all inputs.
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        update: Option<String>,

        /// Use only cached/locked inputs — never touch the network.
        #[arg(long)]
        offline: bool,

        /// Output structured JSON instead of human-friendly colored output.
        /// Useful for tooling, CI, or machine parsing.
        #[arg(long)]
        json: bool,
    },

    /// Build a system image from pinned snaps
    Image {
        /// Path to the Lua config file (default: shuttle.lua)
        #[arg(short, long, default_value = "shuttle.lua")]
        file: String,

        /// Output directory for the .img file (default: current dir)
        #[arg(short, long, default_value = ".")]
        output: String,

        /// Target architecture
        #[arg(short, long, default_value = "amd64")]
        arch: String,

        /// Snap channel to use for store queries (default: latest/stable)
        #[arg(long, default_value = "latest/stable")]
        channel: String,

        /// Cache directory for downloaded snaps (default: ~/.cache/shuttle/snaps)
        #[arg(long)]
        cache: Option<String>,

        /// Maximum cache size (e.g. "500M", "2G"). Auto-prunes oldest entries.
        #[arg(long)]
        cache_max_size: Option<String>,

        /// Image output name to build (from shuttle.lua images table).
        /// Default: build the first image found.
        output_name: Option<String>,

        /// Reproducible timestamp for SquashFS (Unix epoch seconds).
        /// Also read from SOURCE_DATE_EPOCH environment variable.
        #[arg(long)]
        source_date_epoch: Option<String>,

        /// Path to lockfile (default: shuttle.lock).
        #[arg(long, default_value = "shuttle.lock")]
        lockfile: String,

        /// Output structured JSON instead of human-friendly colored output.
        #[arg(long)]
        json: bool,
    },

    /// Manage the package index (list, add, resolve)
    #[command(subcommand)]
    Index(IndexCommand),

    /// Show dependency tree for a package
    Deps {
        /// Package name or path to shuttle.lua file
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

    /// Search available packages by name or keyword
    Search {
        /// Search query (package name or partial match)
        query: String,

        /// Output structured JSON instead of human-friendly output.
        #[arg(long)]
        json: bool,
    },

    /// Check system readiness (required tools)
    Doctor,

    /// Validate a Lua definition without building: bounded subprocess eval
    /// plus Rust-side schema checks, printing every diagnostic (ADR-0010
    /// Decisions 2-3). The fast AI feedback-loop entry point.
    Check {
        /// Path to the Lua definition file
        file: String,

        /// Output structured JSON instead of human-friendly output.
        #[arg(long)]
        json: bool,
    },

    /// Resolve and refresh all input pins in the lockfile (no build).
    /// Pins each github input to its current branch head and records a
    /// content hash; `path:` inputs are marked local (unlocked).
    Lock {
        /// Path to the Lua config file (default: shuttle.lua).
        /// If not found, locks the default package index input.
        #[arg(short, long, default_value = "shuttle.lua")]
        file: String,

        /// Path to lockfile (default: shuttle.lock).
        #[arg(long, default_value = "shuttle.lock")]
        lockfile: String,

        /// Output structured JSON with pin state instead of human output.
        #[arg(long)]
        json: bool,
    },

    /// Evaluate a definition and emit the image manifest IR (no build).
    /// Deterministic: the same definition + lockfile always produce
    /// byte-identical JSON. Resolution is data-only (definition pins,
    /// lockfile, package index) — fully pinned projects eval offline; the
    /// --offline flag additionally forbids fetching uncached inputs.
    Eval {
        /// Path to the Lua config file (default: shuttle.lua)
        #[arg(short, long, default_value = "shuttle.lua")]
        file: String,

        /// Write the manifest to this file atomically (default: stdout)
        #[arg(short, long)]
        output: Option<String>,

        /// Only evaluate this output or image (from the definition's
        /// returned table). Default: everything declared.
        output_name: Option<String>,

        /// Target architecture for image contents (default: amd64)
        #[arg(short, long, default_value = "amd64")]
        arch: String,

        /// Snap channel for the resolution context (default: latest/stable)
        #[arg(long, default_value = "latest/stable")]
        channel: String,

        /// Path to lockfile (default: shuttle.lock).
        /// Pins source hashes and snap revisions for reproducible evals.
        #[arg(long, default_value = "shuttle.lock")]
        lockfile: String,

        /// Use only pinned/cached inputs — never touch the network.
        #[arg(long)]
        offline: bool,

        /// Suppress human-readable status output (the manifest is JSON
        /// either way).
        #[arg(long)]
        json: bool,
    },

    /// Generate shell completion scripts
    Completion {
        /// Shell to generate completions for (bash, zsh, fish, powershell, elvish)
        shell: clap_complete::Shell,
    },

    /// Push built artifacts (`.snap`/`.img`) to an OCI registry as one
    /// OCI image manifest bundle (Phase 25). Blobs are sha256-content-
    /// addressed; blobs already in the registry are skipped.
    Push {
        /// Destination reference: [registry[:port]/]repo[:tag|@digest].
        /// An explicit registry host is required (e.g. localhost:5000/ns/repo,
        /// ghcr.io/owner/repo) — the docker.io implicit default is
        /// deliberately out of scope. Pushing by @digest is an error.
        reference: String,

        /// Directory to auto-discover artifacts in (*.snap, *.img;
        /// default: current dir, matching build/image --output)
        #[arg(short = 'd', long, default_value = ".")]
        dir: String,

        /// Explicit artifact file(s) to push (repeatable; overrides --dir
        /// discovery). Extension decides the layer media type.
        #[arg(long)]
        snap: Vec<String>,

        /// Explicit disk image file(s) to push (repeatable; overrides
        /// --dir discovery).
        #[arg(long)]
        image: Vec<String>,

        /// Tag to push under (default: <name>-<version> derived from the
        /// artifact file names and sanitized to the registry tag charset).
        #[arg(long)]
        tag: Option<String>,

        /// Registry username (requires --password-stdin).
        #[arg(long)]
        username: Option<String>,

        /// Read the registry password from stdin (one line, no echo).
        #[arg(long)]
        password_stdin: bool,

        /// Talk plain http:// (no TLS) — intended for local registries
        /// (e.g. registry:2 on localhost:5000). Refused otherwise.
        #[arg(long)]
        insecure_http: bool,

        /// Attempt cross-repo blob mounts from this source repository
        /// (`POST ...?mount=<digest>&from=<repo>`) before uploading:
        /// a 201 response reuses the bytes already in the registry (no
        /// transfer). Default: empty = mounts skipped.
        #[arg(long)]
        mount_from: Option<String>,

        /// Write the built-manifest record (the manifest Artifact
        /// extension: per-blob sha256 digest, size, media type) to this
        /// file after a successful push. `pull --expect` consumes it.
        #[arg(long)]
        record: Option<String>,

        /// Output structured JSON instead of human-friendly output.
        #[arg(long)]
        json: bool,
    },

    /// Pull an artifact bundle from an OCI registry: fetch the manifest,
    /// download every blob with sha256 verification (fail-closed on any
    /// mismatch), and write the files under their original names.
    Pull {
        /// Source reference: [registry[:port]/]repo[:tag|@digest]. An
        /// explicit registry host is required. A tag or @digest is
        /// required — there is no default tag. When pulled by @digest,
        /// the received manifest itself is digest-verified.
        reference: String,

        /// Directory to write pulled artifact files into (default: current dir)
        #[arg(short, long, default_value = ".")]
        out_dir: String,

        /// Registry username (requires --password-stdin).
        #[arg(long)]
        username: Option<String>,

        /// Read the registry password from stdin (one line, no echo).
        #[arg(long)]
        password_stdin: bool,

        /// Talk plain http:// (no TLS) — intended for local registries.
        #[arg(long)]
        insecure_http: bool,

        /// Verify received blobs against a built-manifest record (from
        /// `push --record`) IN ADDITION to the OCI descriptors —
        /// fail-closed on any digest, size, or media-type mismatch.
        #[arg(long)]
        expect: Option<String>,

        /// Install pulled `.snap` payloads into the state root after the
        /// download. Revisions resolve from the `shuttle.lock` pins in
        /// the current directory (matched by sha3-384); unpinned or
        /// divergent blobs are refused (use plain pull to keep files).
        #[arg(long)]
        install: bool,

        /// State root for --install (default: /var/lib/shuttle).
        #[arg(long)]
        state_dir: Option<String>,

        /// Output structured JSON instead of human-friendly output.
        #[arg(long)]
        json: bool,
    },

    /// Manage the binary package cache
    #[command(subcommand)]
    Cache(CacheCommand),

    /// Manage on-device installs: generations + file-level content store
    /// (ADR-0012 step 5, Phase 24b). Operates on a state root (default
    /// /var/lib/shuttle) holding generations/, store/ blobs, and the
    /// `active` symlink.
    #[command(subcommand)]
    Runtime(RuntimeCommand),

    /// Manage user-level pods (CONTEXT.md: Pod). `shuttle pod [--name <n>]
    /// <verb>`: imperative edits to one pod's declaration + lockfile pins.
    /// `--name` selects the pod (default: `default`) and must appear before
    /// the verb; `add` initializes an unknown pod, read verbs fail on
    /// unknown pods. No builds, binaries, or generations yet — later
    /// tickets.
    Pod {
        /// Pod to operate on (default: `default`). Belongs to the `pod`
        /// command itself, so it goes before the verb:
        /// `shuttle pod --name work add jq`.
        #[arg(long, value_name = "POD")]
        name: Option<String>,

        #[command(subcommand)]
        command: PodCommand,
    },

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
}

/// Subcommands for `shuttle cache`.
#[derive(clap::Subcommand)]
pub enum CacheCommand {
    /// Show cache statistics (entries, packages, disk usage)
    Info {
        /// Cache directory (default: ~/.cache/shuttle/pkgs)
        #[arg(long)]
        cache: Option<String>,
    },

    /// Remove all cached packages
    Clear {
        /// Cache directory (default: ~/.cache/shuttle/pkgs)
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

        /// Cache directory (default: ~/.cache/shuttle/pkgs)
        #[arg(long)]
        cache: Option<String>,

        /// Skip confirmation prompt
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}

/// Subcommands for `shuttle runtime` (ADR-0012 step 5, Phase 24b):
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
        /// (default: /var/lib/shuttle)
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
        /// (default: /var/lib/shuttle)
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
        /// (default: /var/lib/shuttle)
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
        /// (default: /var/lib/shuttle)
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

        /// State root for generations + content store
        /// (default: /var/lib/shuttle)
        #[arg(long)]
        state_dir: Option<String>,

        /// Output structured JSON instead of human-friendly output.
        #[arg(long)]
        json: bool,
    },
}

/// Verbs for `shuttle pod` (pods, issue #2): imperative edits to one
/// pod's declaration + lockfile, mirroring the runtime command group's
/// lifecycle shape. The `--root` state override travels with each verb
/// (test-scoped redirection); `--name` travels on the `pod` command
/// itself, before the verb (issue #4).
#[derive(clap::Subcommand)]
pub enum PodCommand {
    /// Add a package to the selected pod: records it in the pod
    /// declaration and pins the resolved version in the lockfile.
    /// (Re)initializes an unknown pod.
    Add {
        /// Package name, optionally with a version constraint
        /// (`name@constraint`, e.g. `ripgrep@14`).
        package: String,

        /// Pod state root (default: $XDG_DATA_HOME/shuttle/pods, i.e.
        /// ~/.local/share/shuttle/pods). Overridable via SHUTTLE_POD_ROOT.
        /// Tests redirect this into tempdirs.
        #[arg(long)]
        root: Option<String>,
    },

    /// Remove a package from the selected pod: drops the declaration
    /// entry and the lockfile pin.
    Remove {
        /// Package name (a trailing `@constraint` is ignored).
        package: String,

        /// Pod state root (see `pod add --root`).
        #[arg(long)]
        root: Option<String>,
    },

    /// List the selected pod's packages with their resolved versions.
    List {
        /// Pod state root (see `pod add --root`).
        #[arg(long)]
        root: Option<String>,
    },
}

/// Subcommands for `shuttle index`.
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
    },

    /// Update package source inputs (re-fetch GitHub repositories).
    /// Ensures the local cache matches the remote.
    Update {
        /// Path to the Lua config file (default: shuttle.lua).
        /// If not found, updates the default package index.
        #[arg(short, long, default_value = "shuttle.lua")]
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
        match parse_build(&["shuttle", "build"]) {
            Command::Build {
                file,
                stage,
                output,
                arch,
                output_name,
                ..
            } => {
                assert_eq!(file, "shuttle.lua");
                // No --stage flag: default stage, tracked as None so the
                // build knows it may wipe shuttle's own ./stage/.
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
        match parse_build(&["shuttle", "build", "--file", "my-snap.lua"]) {
            Command::Build { file, .. } => assert_eq!(file, "my-snap.lua"),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_with_short_file_flag() {
        match parse_build(&["shuttle", "build", "-f", "other.lua"]) {
            Command::Build { file, .. } => assert_eq!(file, "other.lua"),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_with_stage_and_output() {
        match parse_build(&[
            "shuttle",
            "build",
            "--stage",
            "/tmp/stage",
            "--output",
            "/tmp/out",
        ]) {
            Command::Build { stage, output, .. } => {
                assert_eq!(stage, Some("/tmp/stage".to_string()));
                assert_eq!(output, "/tmp/out");
            }
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_with_single_arch() {
        match parse_build(&["shuttle", "build", "--arch", "arm64"]) {
            Command::Build { arch, .. } => assert_eq!(arch, &["arm64"]),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_with_multi_arch() {
        match parse_build(&["shuttle", "build", "--arch", "amd64", "-A", "arm64"]) {
            Command::Build { arch, .. } => assert_eq!(arch, &["amd64", "arm64"]),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_with_positional_output_name() {
        match parse_build(&["shuttle", "build", "server"]) {
            Command::Build { output_name, .. } => {
                assert_eq!(output_name.as_deref(), Some("server"))
            }
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_with_positional_and_flags() {
        match parse_build(&[
            "shuttle",
            "build",
            "cli",
            "--file",
            "multi.lua",
            "--arch",
            "arm64",
        ]) {
            Command::Build {
                output_name,
                file,
                arch,
                ..
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
        match parse_build(&["shuttle", "image"]) {
            Command::Image {
                file,
                output,
                arch,
                channel,
                cache,
                output_name,
                ..
            } => {
                assert_eq!(file, "shuttle.lua");
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
            "shuttle",
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
                file,
                output,
                arch,
                channel,
                cache,
                output_name,
                ..
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
        let result = Cli::try_parse_from(["shuttle"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_image_source_date_epoch() {
        match parse_build(&["shuttle", "image", "--source-date-epoch", "0"]) {
            Command::Image {
                source_date_epoch, ..
            } => {
                assert_eq!(source_date_epoch.as_deref(), Some("0"));
            }
            _ => panic!("expected Image"),
        }
    }

    // ── New flag tests ──

    #[test]
    fn test_build_all_flag() {
        match parse_build(&["shuttle", "build", "--all"]) {
            Command::Build { all, .. } => assert!(all),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_cache_flag() {
        match parse_build(&["shuttle", "build", "--cache", "/tmp/cache"]) {
            Command::Build { cache, .. } => {
                assert_eq!(cache.as_deref(), Some("/tmp/cache"));
            }
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_json_flag() {
        match parse_build(&["shuttle", "build", "--json"]) {
            Command::Build { json, .. } => assert!(json),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_target_flag() {
        match parse_build(&["shuttle", "build", "--target", "aarch64-linux-gnu"]) {
            Command::Build { target, .. } => {
                assert_eq!(target.as_deref(), Some("aarch64-linux-gnu"));
            }
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_update_one_input() {
        match parse_build(&["shuttle", "build", "--update", "pkgs"]) {
            Command::Build { update, .. } => assert_eq!(update.as_deref(), Some("pkgs")),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_update_all_inputs() {
        match parse_build(&["shuttle", "build", "--update"]) {
            Command::Build { update, .. } => assert_eq!(update.as_deref(), Some("")),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_offline_flag() {
        match parse_build(&["shuttle", "build", "--offline"]) {
            Command::Build { offline, .. } => assert!(offline),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_lock_subcommand_defaults() {
        match Cli::try_parse_from(["shuttle", "lock"]).unwrap().command {
            Command::Lock {
                file,
                lockfile,
                json,
            } => {
                assert_eq!(file, "shuttle.lua");
                assert_eq!(lockfile, "shuttle.lock");
                assert!(!json);
            }
            _ => panic!("expected Lock"),
        }
    }

    #[test]
    fn test_lock_subcommand_flags() {
        match Cli::try_parse_from([
            "shuttle",
            "lock",
            "--file",
            "cfg.lua",
            "--lockfile",
            "other.lock",
        ])
        .unwrap()
        .command
        {
            Command::Lock { file, lockfile, .. } => {
                assert_eq!(file, "cfg.lua");
                assert_eq!(lockfile, "other.lock");
            }
            _ => panic!("expected Lock"),
        }
    }

    #[test]
    fn test_lock_subcommand_json_flag() {
        match Cli::try_parse_from(["shuttle", "lock", "--json", "--lockfile", "p.lock"])
            .unwrap()
            .command
        {
            Command::Lock { lockfile, json, .. } => {
                assert!(json);
                assert_eq!(lockfile, "p.lock");
            }
            _ => panic!("expected Lock"),
        }
    }

    #[test]
    fn test_image_json_flag() {
        match parse_build(&["shuttle", "image", "--json"]) {
            Command::Image { json, .. } => assert!(json),
            _ => panic!("expected Image"),
        }
    }

    #[test]
    fn test_deps_json_flag() {
        let args = ["shuttle", "deps", "glibc", "--json"];
        let cmd = Cli::try_parse_from(args).unwrap().command;
        match cmd {
            Command::Deps { json, .. } => assert!(json),
            _ => panic!("expected Deps"),
        }
    }

    #[test]
    fn test_build_all_flags_combo() {
        match parse_build(&[
            "shuttle",
            "build",
            "--all",
            "--cache",
            "/tmp/cache",
            "--json",
            "--target",
            "aarch64-linux-gnu",
        ]) {
            Command::Build {
                all,
                cache,
                json,
                target,
                ..
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
        match Cli::try_parse_from(["shuttle", "check", "cfg.lua", "--json"])
            .unwrap()
            .command
        {
            Command::Check { file, json } => {
                assert_eq!(file, "cfg.lua");
                assert!(json);
            }
            _ => panic!("expected Check"),
        }
    }

    #[test]
    fn test_completion_bash() {
        match Cli::try_parse_from(["shuttle", "completion", "bash"])
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
        match Cli::try_parse_from(["shuttle", "cache", "info"])
            .unwrap()
            .command
        {
            Command::Cache(CacheCommand::Info { .. }) => {}
            _ => panic!("expected Cache Info"),
        }
    }

    #[test]
    fn test_cache_clear() {
        match Cli::try_parse_from(["shuttle", "cache", "clear", "--force"])
            .unwrap()
            .command
        {
            Command::Cache(CacheCommand::Clear { force, .. }) => assert!(force),
            _ => panic!("expected Cache Clear"),
        }
    }

    #[test]
    fn test_cache_prune() {
        match Cli::try_parse_from(["shuttle", "cache", "prune", "--days", "60", "--force"])
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
        match Cli::try_parse_from(["shuttle", "runtime", "install", "hello"])
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
            "shuttle",
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
        match Cli::try_parse_from(["shuttle", "runtime", "remove", "hello", "--json"])
            .unwrap()
            .command
        {
            Command::Runtime(RuntimeCommand::Remove { name, json, .. }) => {
                assert_eq!(name, "hello");
                assert!(json);
            }
            _ => panic!("expected Runtime Remove"),
        }
        match Cli::try_parse_from(["shuttle", "runtime", "rollback", "3"])
            .unwrap()
            .command
        {
            Command::Runtime(RuntimeCommand::Rollback { generation, .. }) => {
                assert_eq!(generation, Some(3));
            }
            _ => panic!("expected Runtime Rollback"),
        }
        match Cli::try_parse_from(["shuttle", "runtime", "rollback"])
            .unwrap()
            .command
        {
            Command::Runtime(RuntimeCommand::Rollback { generation, .. }) => {
                assert_eq!(generation, None);
            }
            _ => panic!("expected Runtime Rollback default"),
        }
        match Cli::try_parse_from(["shuttle", "runtime", "gc", "--prune"])
            .unwrap()
            .command
        {
            Command::Runtime(RuntimeCommand::Gc { prune, .. }) => assert!(prune),
            _ => panic!("expected Runtime Gc"),
        }
    }

    #[test]
    fn test_runtime_upgrade_all() {
        match Cli::try_parse_from(["shuttle", "runtime", "upgrade", "--all"])
            .unwrap()
            .command
        {
            Command::Runtime(RuntimeCommand::Upgrade { name, all, .. }) => {
                assert_eq!(name, None);
                assert!(all);
            }
            _ => panic!("expected Runtime Upgrade"),
        }
        match Cli::try_parse_from(["shuttle", "runtime", "upgrade", "hello"])
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

    // ── OCI push/pull (Phase 25) ──

    #[test]
    fn test_push_defaults() {
        match Cli::try_parse_from(["shuttle", "push", "localhost:5000/team/app"])
            .unwrap()
            .command
        {
            Command::Push {
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
            } => {
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
            "shuttle",
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
            Command::Push {
                dir,
                snap,
                image,
                tag,
                username,
                password_stdin,
                insecure_http,
                json,
                ..
            } => {
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
        assert!(Cli::try_parse_from(["shuttle", "push"]).is_err());
    }

    #[test]
    fn test_pull_defaults() {
        match Cli::try_parse_from(["shuttle", "pull", "ghcr.io/owner/repo:v1"])
            .unwrap()
            .command
        {
            Command::Pull {
                reference,
                out_dir,
                username,
                password_stdin,
                insecure_http,
                expect,
                install,
                state_dir,
                json,
            } => {
                assert_eq!(reference, "ghcr.io/owner/repo:v1");
                assert_eq!(out_dir, ".");
                assert!(username.is_none());
                assert!(!password_stdin);
                assert!(!insecure_http);
                assert!(expect.is_none());
                assert!(!install);
                assert!(state_dir.is_none());
                assert!(!json);
            }
            _ => panic!("expected Pull"),
        }
    }

    #[test]
    fn test_pull_flags() {
        match Cli::try_parse_from([
            "shuttle",
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
            Command::Pull {
                out_dir,
                username,
                password_stdin,
                insecure_http,
                expect,
                install,
                state_dir,
                json,
                ..
            } => {
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
}
