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
    #[arg(long, value_name = "N", default_value_t = la_console::commands::DEFAULT_COMMAND_TIMEOUT_SECS)]
    timeout_secs: u64,
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = std::fs::canonicalize(&cli.root) {
        eprintln!("error: cannot resolve root {}: {err}", cli.root.display());
        std::process::exit(1);
    }
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    if let Err(err) =
        la_console::console::run(&cli.root, cli.timeout_secs, stdin.lock(), stdout.lock())
    {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
