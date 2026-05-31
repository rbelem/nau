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

    #[test]
    fn test_build_defaults() {
        let cli = Cli::try_parse_from(["shoot", "build"]).unwrap();
        let Command::Build {
            file,
            stage,
            output,
            arch,
            output_name,
        } = &cli.command;
        assert_eq!(file, "shoot.lua");
        assert_eq!(stage, "./stage/");
        assert_eq!(output, ".");
        assert!(arch.is_empty());
        assert!(output_name.is_none());
    }

    #[test]
    fn test_build_with_file_flag() {
        let cli = Cli::try_parse_from(["shoot", "build", "--file", "my-snap.lua"]).unwrap();
        let Command::Build { file, .. } = &cli.command;
        assert_eq!(file, "my-snap.lua");
    }

    #[test]
    fn test_build_with_short_file_flag() {
        let cli = Cli::try_parse_from(["shoot", "build", "-f", "other.lua"]).unwrap();
        let Command::Build { file, .. } = &cli.command;
        assert_eq!(file, "other.lua");
    }

    #[test]
    fn test_build_with_stage_and_output() {
        let cli = Cli::try_parse_from([
            "shoot",
            "build",
            "--stage",
            "/tmp/stage",
            "--output",
            "/tmp/out",
        ])
        .unwrap();
        let Command::Build { stage, output, .. } = &cli.command;
        assert_eq!(stage, "/tmp/stage");
        assert_eq!(output, "/tmp/out");
    }

    #[test]
    fn test_build_with_single_arch() {
        let cli = Cli::try_parse_from(["shoot", "build", "--arch", "arm64"]).unwrap();
        let Command::Build { arch, .. } = &cli.command;
        assert_eq!(arch, &["arm64"]);
    }

    #[test]
    fn test_build_with_multi_arch() {
        let cli =
            Cli::try_parse_from(["shoot", "build", "--arch", "amd64", "-A", "arm64"]).unwrap();
        let Command::Build { arch, .. } = &cli.command;
        assert_eq!(arch, &["amd64", "arm64"]);
    }

    #[test]
    fn test_build_with_positional_output_name() {
        let cli = Cli::try_parse_from(["shoot", "build", "server"]).unwrap();
        let Command::Build { output_name, .. } = &cli.command;
        assert_eq!(output_name.as_deref(), Some("server"));
    }

    #[test]
    fn test_build_with_positional_and_flags() {
        let cli = Cli::try_parse_from([
            "shoot",
            "build",
            "cli",
            "--file",
            "multi.lua",
            "--arch",
            "arm64",
        ])
        .unwrap();
        let Command::Build {
            output_name,
            file,
            arch,
            ..
        } = &cli.command;
        assert_eq!(output_name.as_deref(), Some("cli"));
        assert_eq!(file, "multi.lua");
        assert_eq!(arch, &["arm64"]);
    }

    #[test]
    fn test_missing_subcommand_fails() {
        let result = Cli::try_parse_from(["shoot"]);
        assert!(result.is_err());
    }
}
