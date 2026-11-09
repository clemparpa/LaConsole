use clap::Parser;
use la_console::sandbox::Mode;
use std::ffi::OsString;
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
    #[arg(long, value_enum, value_name = "MODE", default_value = "user")]
    mode: Mode,
    #[arg(long, hide = true)]
    inside_sandbox: bool,
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
}

fn forward_args(cli: &Cli) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        OsString::from("--timeout-secs"),
        OsString::from(cli.timeout_secs.to_string()),
    ];
    if let Some(n) = cli.max_output_bytes {
        args.push(OsString::from("--max-output-bytes"));
        args.push(OsString::from(n.to_string()));
    }
    if let Some(p) = &cli.trusted_file {
        args.push(OsString::from("--trusted-file"));
        args.push(p.as_os_str().to_owned());
    }
    if let Some(h) = &cli.trusted_sha256 {
        args.push(OsString::from("--trusted-sha256"));
        args.push(OsString::from(h));
    }
    if let Some(p) = &cli.sensibles_file {
        args.push(OsString::from("--sensibles-file"));
        args.push(p.as_os_str().to_owned());
    }
    args
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = std::fs::canonicalize(&cli.root) {
        eprintln!("error: cannot resolve root {}: {err}", cli.root.display());
        std::process::exit(1);
    }
    let forward = forward_args(&cli);
    if let Err(err) = la_console::sandbox::gate(cli.mode, cli.inside_sandbox, &cli.root, &forward) {
        eprintln!("error: {err}");
        std::process::exit(2);
    }
    if cli.inside_sandbox {
        la_console::sandbox::cleanup_staged_bin();
    }
    let opts = la_console::console::Options {
        timeout_secs: cli.timeout_secs,
        max_output_bytes: cli.max_output_bytes,
        trusted_file: cli.trusted_file,
        trusted_sha256: cli.trusted_sha256,
        sensibles_file: cli.sensibles_file,
        sandboxed: cli.inside_sandbox,
    };
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    if let Err(err) = la_console::console::run(&cli.root, &opts, stdin.lock(), stdout.lock()) {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
