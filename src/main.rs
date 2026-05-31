use clap::Parser;
use shoot::cli::{Cli, Command};

fn main() -> miette::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Build {
            file,
            stage,
            output,
        } => {
            let outputs = shoot::lua::evaluate_file(&file)?;

            let stage_dir = std::path::Path::new(&stage);
            let output_dir = std::path::Path::new(&output);

            for (_name, meta) in &outputs {
                println!("Building {} v{}...", meta.name, meta.version);
                let snap_name = shoot::snap::build_snap(meta, stage_dir, output_dir)?;
                println!("  ✓ {snap_name}");
            }
        }
    }

    Ok(())
}
