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
    fn test_build_default_file() {
        let cli = Cli::try_parse_from(["shoot", "build"]).unwrap();
        let Command::Build { file } = &cli.command;
        assert_eq!(file, "shoot.lua");
    }

    #[test]
    fn test_build_with_file_flag() {
        let cli = Cli::try_parse_from(["shoot", "build", "--file", "my-snap.lua"]).unwrap();
        let Command::Build { file } = &cli.command;
        assert_eq!(file, "my-snap.lua");
    }

    #[test]
    fn test_build_with_short_file_flag() {
        let cli = Cli::try_parse_from(["shoot", "build", "-f", "other.lua"]).unwrap();
        let Command::Build { file } = &cli.command;
        assert_eq!(file, "other.lua");
    }

    #[test]
    fn test_missing_subcommand_fails() {
        let result = Cli::try_parse_from(["shoot"]);
        assert!(result.is_err());
    }
}
