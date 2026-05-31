use clap::Parser;
use miette::WrapErr;
use shoot::cli::{Cli, Command};

fn main() -> miette::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Build { file } => {
            let outputs = shoot::lua::evaluate_file(&file)
                .wrap_err_with(|| format!("failed to evaluate {}", file))?;

            println!("Outputs from {}:", file);
            for name in outputs.keys() {
                println!("  - {name}");
            }
        }
    }

    Ok(())
}
