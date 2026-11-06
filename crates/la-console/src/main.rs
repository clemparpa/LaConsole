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
    #[arg(long, value_name = "PATH")]
    trusted_file: Option<PathBuf>,
    #[arg(long, value_name = "HEX")]
    trusted_sha256: Option<String>,
    #[arg(long, value_name = "PATH")]
    sensibles_file: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = std::fs::canonicalize(&cli.root) {
        eprintln!("error: cannot resolve root {}: {err}", cli.root.display());
        std::process::exit(1);
    }
    let opts = la_console::console::Options {
        timeout_secs: cli.timeout_secs,
        trusted_file: cli.trusted_file,
        trusted_sha256: cli.trusted_sha256,
        sensibles_file: cli.sensibles_file,
    };
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    if let Err(err) = la_console::console::run(&cli.root, &opts, stdin.lock(), stdout.lock()) {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
