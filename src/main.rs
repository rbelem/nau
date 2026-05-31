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
            output_name,
        } => {
            let all_outputs = shoot::lua::evaluate_file(&file)?;

            let stage_dir = std::path::Path::new(&stage);
            let output_dir = std::path::Path::new(&output);

            // Filter to requested output name if specified
            let iter: Vec<(&String, &shoot::snap::SnapMeta)> = match &output_name {
                Some(name) => {
                    let meta = all_outputs.get(name).ok_or_else(|| {
                        miette::miette!("output '{}' not found in {}", name, file)
                    })?;
                    vec![(name, meta)]
                }
                None => all_outputs.iter().collect(),
            };

            for (name, meta) in iter {
                let archs = shoot::snap::resolve_archs(meta, &arch);

                println!("Building {} ({})...", name, meta.version);
                for a in &archs {
                    println!("  {}/{}:", name, a);
                    let snap_name = shoot::snap::build_snap(meta, stage_dir, output_dir, a)?;
                    println!("    ✓ {snap_name}");
                }
            }
        }
    }

    Ok(())
}
