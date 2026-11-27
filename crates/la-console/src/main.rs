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
    #[arg(long, value_name = "N")]
    max_output_bytes: Option<usize>,
    #[arg(long, value_name = "PATH")]
    trusted_file: Option<PathBuf>,
    #[arg(long, value_name = "HEX")]
    trusted_sha256: Option<String>,
    #[arg(long, value_name = "PATH")]
    sensibles_file: Option<PathBuf>,
    /// File of known secrets (one per line, `#` comments): every occurrence
    /// is masked as `***` in outputs and before any on-disk write.
    #[arg(long, value_name = "PATH")]
    secrets_file: Option<PathBuf>,
}

fn main() {
    // Hidden arg0: OS sandbox helper (spec/sandbox-backend.md). The trusted
    // subprocesses are spawned as `la-console __sandbox_helper <profile.json>
    // -- <cmd...>` — re-exec of our own binary, which applies the sandbox just
    // before exec. Intercepted before the clap CLI; no flag can disable it.
    let mut args = std::env::args_os();
    let _exe = args.next();
    if let Some(first) = args.next() {
        if first == std::ffi::OsStr::new(la_console::sandbox_backend::HELPER_ARG0) {
            la_console::sandbox_backend::run_helper(args.collect());
        }
    }
    let cli = Cli::parse();
    if let Err(err) = std::fs::canonicalize(&cli.root) {
        eprintln!("error: cannot resolve root {}: {err}", cli.root.display());
        std::process::exit(1);
    }
    let opts = la_console::console::Options {
        timeout_secs: cli.timeout_secs,
        max_output_bytes: cli.max_output_bytes,
        trusted_file: cli.trusted_file,
        trusted_sha256: cli.trusted_sha256,
        sensibles_file: cli.sensibles_file,
        secrets_file: cli.secrets_file,
    };
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    if let Err(err) = la_console::console::run(&cli.root, &opts, stdin.lock(), stdout.lock()) {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
