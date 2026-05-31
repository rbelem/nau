use clap::Parser;
use shoot::cli::{Cli, Command};

fn main() -> miette::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Build {
            file,
            stage,
            output,
            arch,
        } => {
            let outputs = shoot::lua::evaluate_file(&file)?;

            let stage_dir = std::path::Path::new(&stage);
            let output_dir = std::path::Path::new(&output);

            for meta in outputs.values() {
                let archs = shoot::snap::resolve_archs(meta, &arch);

                for a in &archs {
                    println!("Building {} v{} ({})...", meta.name, meta.version, a);
                    let snap_name = shoot::snap::build_snap(meta, stage_dir, output_dir, a)?;
                    println!("  ✓ {snap_name}");
                }
            }
        }
    }

    Ok(())
}
