use clap::Parser;
use std::path::PathBuf;

use la_console::commands::ExecContext;
use la_console::sink::DEFAULT_MAX_OUTPUT_BYTES;

#[derive(Parser)]
#[command(
    name = "la-console",
    version,
    about = "Confined fake console for AI agents"
)]
struct Cli {
    #[arg(long, value_name = "PATH")]
    root: PathBuf,
    #[arg(long, value_name = "N", default_value_t = DEFAULT_MAX_OUTPUT_BYTES)]
    max_output_bytes: usize,
    #[arg(long, value_name = "PATH")]
    sensitives_file: Option<PathBuf>,
}

fn load_sensibles(path: Option<&PathBuf>) -> Result<Vec<regex::Regex>, String> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read sensibles file {}: {e}", path.display()))?;
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            regex::Regex::new(line).map_err(|e| format!("invalid sensibles regex {line:?}: {e}"))
        })
        .collect()
}

fn main() {
    let cli = Cli::parse();
    let sensibles = match load_sensibles(cli.sensitives_file.as_ref()) {
        Ok(sensibles) => sensibles,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    };
    let ctx = match ExecContext::new(&cli.root, cli.max_output_bytes, sensibles, Vec::new()) {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("error: cannot resolve root {}: {err}", cli.root.display());
            std::process::exit(1);
        }
    };
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    if let Err(err) = la_console::console::run(stdin.lock(), stdout.lock(), &ctx) {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
