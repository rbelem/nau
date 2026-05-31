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
    },

    /// Manage the package index (list, add, resolve)
    #[command(subcommand)]
    Index(IndexCommand),
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
}
