use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "shoot",
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
        /// Path to the Lua config file (default: shoot.lua)
        #[arg(short, long, default_value = "shoot.lua")]
        file: String,

        /// Directory containing pre-built binaries (default: ./stage/)
        #[arg(short, long, default_value = "./stage/")]
        stage: String,

        /// Output directory for the .snap file (default: current dir)
        #[arg(short, long, default_value = ".")]
        output: String,

        /// Build only for specific architecture(s). Repeat for multiple.
        /// Default: build for all architectures declared in the config.
        #[arg(short = 'A', long)]
        arch: Vec<String>,

        /// Output name to build (from shoot.lua outputs table).
        /// Default: build all outputs.
        output_name: Option<String>,

        /// Reproducible timestamp for SquashFS (Unix epoch seconds).
        /// Also read from SOURCE_DATE_EPOCH environment variable.
        /// Default: current time (non-reproducible).
        #[arg(long)]
        source_date_epoch: Option<String>,

        /// Path to lockfile (default: shoot.lock).
        /// Locks source hashes for reproducible builds.
        #[arg(long, default_value = "shoot.lock")]
        lockfile: String,

        /// Print dependency build order and exit (no build).
        #[arg(long)]
        order: bool,

        /// Build all transitive dependencies before building the requested output(s).
        /// Deps are built in topological order and stored in the binary cache.
        /// Use --cache to control where cached builds are stored.
        #[arg(long)]
        all: bool,

        /// Binary cache directory for built packages (default: ~/.cache/shoot/pkgs).
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
        /// Path to the Lua config file (default: shoot.lua)
        #[arg(short, long, default_value = "shoot.lua")]
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

        /// Cache directory for downloaded snaps (default: ~/.cache/shoot/snaps)
        #[arg(long)]
        cache: Option<String>,

        /// Maximum cache size (e.g. "500M", "2G"). Auto-prunes oldest entries.
        #[arg(long)]
        cache_max_size: Option<String>,

        /// Image output name to build (from shoot.lua images table).
        /// Default: build the first image found.
        output_name: Option<String>,

        /// Reproducible timestamp for SquashFS (Unix epoch seconds).
        /// Also read from SOURCE_DATE_EPOCH environment variable.
        #[arg(long)]
        source_date_epoch: Option<String>,

        /// Path to lockfile (default: shoot.lock).
        #[arg(long, default_value = "shoot.lock")]
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
        /// Package name or path to shoot.lua file
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

    /// Resolve and refresh all input pins in the lockfile (no build).
    /// Pins each github input to its current branch head and records a
    /// content hash; `path:` inputs are marked local (unlocked).
    Lock {
        /// Path to the Lua config file (default: shoot.lua).
        /// If not found, locks the default package index input.
        #[arg(short, long, default_value = "shoot.lua")]
        file: String,

        /// Path to lockfile (default: shoot.lock).
        #[arg(long, default_value = "shoot.lock")]
        lockfile: String,
    },

    /// Generate shell completion scripts
    Completion {
        /// Shell to generate completions for (bash, zsh, fish, powershell, elvish)
        shell: clap_complete::Shell,
    },

    /// Manage the binary package cache
    #[command(subcommand)]
    Cache(CacheCommand),
}

/// Subcommands for `shoot cache`.
#[derive(clap::Subcommand)]
pub enum CacheCommand {
    /// Show cache statistics (entries, packages, disk usage)
    Info {
        /// Cache directory (default: ~/.cache/shoot/pkgs)
        #[arg(long)]
        cache: Option<String>,
    },

    /// Remove all cached packages
    Clear {
        /// Cache directory (default: ~/.cache/shoot/pkgs)
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

        /// Cache directory (default: ~/.cache/shoot/pkgs)
        #[arg(long)]
        cache: Option<String>,

        /// Skip confirmation prompt
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}

/// Subcommands for `shoot index`.
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
        /// Path to the Lua config file (default: shoot.lua).
        /// If not found, updates the default package index.
        #[arg(short, long, default_value = "shoot.lua")]
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
        match parse_build(&["shoot", "build"]) {
            Command::Build {
                file,
                stage,
                output,
                arch,
                output_name,
                ..
            } => {
                assert_eq!(file, "shoot.lua");
                assert_eq!(stage, "./stage/");
                assert_eq!(output, ".");
                assert!(arch.is_empty());
                assert!(output_name.is_none());
            }
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_with_file_flag() {
        match parse_build(&["shoot", "build", "--file", "my-snap.lua"]) {
            Command::Build { file, .. } => assert_eq!(file, "my-snap.lua"),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_with_short_file_flag() {
        match parse_build(&["shoot", "build", "-f", "other.lua"]) {
            Command::Build { file, .. } => assert_eq!(file, "other.lua"),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_with_stage_and_output() {
        match parse_build(&[
            "shoot",
            "build",
            "--stage",
            "/tmp/stage",
            "--output",
            "/tmp/out",
        ]) {
            Command::Build { stage, output, .. } => {
                assert_eq!(stage, "/tmp/stage");
                assert_eq!(output, "/tmp/out");
            }
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_with_single_arch() {
        match parse_build(&["shoot", "build", "--arch", "arm64"]) {
            Command::Build { arch, .. } => assert_eq!(arch, &["arm64"]),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_with_multi_arch() {
        match parse_build(&["shoot", "build", "--arch", "amd64", "-A", "arm64"]) {
            Command::Build { arch, .. } => assert_eq!(arch, &["amd64", "arm64"]),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_with_positional_output_name() {
        match parse_build(&["shoot", "build", "server"]) {
            Command::Build { output_name, .. } => {
                assert_eq!(output_name.as_deref(), Some("server"))
            }
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_with_positional_and_flags() {
        match parse_build(&[
            "shoot",
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
        match parse_build(&["shoot", "image"]) {
            Command::Image {
                file,
                output,
                arch,
                channel,
                cache,
                output_name,
                ..
            } => {
                assert_eq!(file, "shoot.lua");
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
            "shoot",
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
        let result = Cli::try_parse_from(["shoot"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_image_source_date_epoch() {
        match parse_build(&["shoot", "image", "--source-date-epoch", "0"]) {
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
        match parse_build(&["shoot", "build", "--all"]) {
            Command::Build { all, .. } => assert!(all),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_cache_flag() {
        match parse_build(&["shoot", "build", "--cache", "/tmp/cache"]) {
            Command::Build { cache, .. } => {
                assert_eq!(cache.as_deref(), Some("/tmp/cache"));
            }
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_json_flag() {
        match parse_build(&["shoot", "build", "--json"]) {
            Command::Build { json, .. } => assert!(json),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_target_flag() {
        match parse_build(&["shoot", "build", "--target", "aarch64-linux-gnu"]) {
            Command::Build { target, .. } => {
                assert_eq!(target.as_deref(), Some("aarch64-linux-gnu"));
            }
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_update_one_input() {
        match parse_build(&["shoot", "build", "--update", "pkgs"]) {
            Command::Build { update, .. } => assert_eq!(update.as_deref(), Some("pkgs")),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_update_all_inputs() {
        match parse_build(&["shoot", "build", "--update"]) {
            Command::Build { update, .. } => assert_eq!(update.as_deref(), Some("")),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_build_offline_flag() {
        match parse_build(&["shoot", "build", "--offline"]) {
            Command::Build { offline, .. } => assert!(offline),
            _ => panic!("expected Build"),
        }
    }

    #[test]
    fn test_lock_subcommand_defaults() {
        match Cli::try_parse_from(["shoot", "lock"]).unwrap().command {
            Command::Lock { file, lockfile } => {
                assert_eq!(file, "shoot.lua");
                assert_eq!(lockfile, "shoot.lock");
            }
            _ => panic!("expected Lock"),
        }
    }

    #[test]
    fn test_lock_subcommand_flags() {
        match Cli::try_parse_from([
            "shoot",
            "lock",
            "--file",
            "cfg.lua",
            "--lockfile",
            "other.lock",
        ])
        .unwrap()
        .command
        {
            Command::Lock { file, lockfile } => {
                assert_eq!(file, "cfg.lua");
                assert_eq!(lockfile, "other.lock");
            }
            _ => panic!("expected Lock"),
        }
    }

    #[test]
    fn test_image_json_flag() {
        match parse_build(&["shoot", "image", "--json"]) {
            Command::Image { json, .. } => assert!(json),
            _ => panic!("expected Image"),
        }
    }

    #[test]
    fn test_deps_json_flag() {
        let args = ["shoot", "deps", "glibc", "--json"];
        let cmd = Cli::try_parse_from(args).unwrap().command;
        match cmd {
            Command::Deps { json, .. } => assert!(json),
            _ => panic!("expected Deps"),
        }
    }

    #[test]
    fn test_build_all_flags_combo() {
        match parse_build(&[
            "shoot",
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
    fn test_completion_bash() {
        match Cli::try_parse_from(["shoot", "completion", "bash"])
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
        match Cli::try_parse_from(["shoot", "cache", "info"])
            .unwrap()
            .command
        {
            Command::Cache(CacheCommand::Info { .. }) => {}
            _ => panic!("expected Cache Info"),
        }
    }

    #[test]
    fn test_cache_clear() {
        match Cli::try_parse_from(["shoot", "cache", "clear", "--force"])
            .unwrap()
            .command
        {
            Command::Cache(CacheCommand::Clear { force, .. }) => assert!(force),
            _ => panic!("expected Cache Clear"),
        }
    }

    #[test]
    fn test_cache_prune() {
        match Cli::try_parse_from(["shoot", "cache", "prune", "--days", "60", "--force"])
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
}
