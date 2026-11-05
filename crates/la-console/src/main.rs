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
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    if let Err(err) = la_console::console::run(stdin.lock(), stdout.lock()) {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
