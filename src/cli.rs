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
        } = &cli.command;
        assert_eq!(file, "shoot.lua");
        assert_eq!(stage, "./stage/");
        assert_eq!(output, ".");
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
    fn test_missing_subcommand_fails() {
        let result = Cli::try_parse_from(["shoot"]);
        assert!(result.is_err());
    }
}
