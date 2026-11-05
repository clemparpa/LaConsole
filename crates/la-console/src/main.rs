use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "la-console",
    version,
    about = "Confined fake console for AI agents"
)]
struct Cli {
    #[arg(long, value_name = "PATH")]
    root: PathBuf,
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = std::fs::canonicalize(&cli.root) {
        eprintln!("error: cannot resolve root {}: {err}", cli.root.display());
        std::process::exit(1);
    }
}
