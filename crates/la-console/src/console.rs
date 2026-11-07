use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use crate::commands::{execute, Ctx, ErrorKind, Limits};
use crate::resolve::Resolver;
use crate::trusted::TrustedRegistry;

#[derive(Debug, Deserialize)]
pub struct Request {
    pub op: String,
    pub cmd: String,
}

#[derive(Debug, Serialize)]
pub struct Response {
    pub ok: bool,
    pub code: u16,
    /// Structured error classification, present only on failure so successful
    /// responses keep the exact v1 contract.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<ErrorKind>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}

pub struct Options {
    pub timeout_secs: u64,
    pub trusted_file: Option<PathBuf>,
    pub trusted_sha256: Option<String>,
    pub sensibles_file: Option<PathBuf>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            timeout_secs: crate::commands::DEFAULT_COMMAND_TIMEOUT_SECS,
            trusted_file: None,
            trusted_sha256: None,
            sensibles_file: None,
        }
    }
}

pub fn run<R: BufRead, W: Write>(
    root: &Path,
    opts: &Options,
    mut input: R,
    mut output: W,
) -> std::io::Result<()> {
    let resolver = Resolver::new(root)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string()))?;
    let sensibles = match &opts.sensibles_file {
        Some(path) => crate::sink::load_sensibles(path)?,
        None => Vec::new(),
    };
    let trusted = match &opts.trusted_file {
        Some(path) => Some(
            TrustedRegistry::load(path, opts.trusted_sha256.clone(), resolver.root()).map_err(
                |err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string()),
            )?,
        ),
        None => None,
    };
    let ctx = Ctx {
        resolver,
        sensibles,
        secrets: Vec::new(),
        limits: Limits {
            command_timeout_secs: opts.timeout_secs,
            ..Limits::default()
        },
        trusted,
    };
    let mut line = String::new();
    loop {
        line.clear();
        if input.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let response = handle_line(&line, &ctx);
        serde_json::to_writer(&mut output, &response)?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
}

fn error_response(kind: ErrorKind, message: String) -> Response {
    let prefix = match kind {
        ErrorKind::Denied => "denied",
        ErrorKind::Limit => "limit",
        ErrorKind::Fail => "fail",
    };
    Response {
        ok: false,
        code: kind.code(),
        kind: Some(kind),
        stdout: String::new(),
        stderr: format!("{prefix}: {message}"),
        truncated: false,
    }
}

fn denied(message: String) -> Response {
    error_response(ErrorKind::Denied, message)
}

fn handle_line(line: &str, ctx: &Ctx) -> Response {
    match serde_json::from_str::<Request>(line) {
        Ok(req) if req.op == "exec" => {
            let vars = HashMap::new();
            match crate::parse::parse_input(&req.cmd, &vars) {
                Err(err) => denied(err.to_string()),
                Ok(node) => match execute(&node, ctx) {
                    Ok(outcome) => Response {
                        ok: outcome.code == 0,
                        code: outcome.code,
                        kind: (outcome.code != 0).then_some(ErrorKind::Fail),
                        stdout: outcome.stdout,
                        stderr: outcome.stderr,
                        truncated: outcome.truncated,
                    },
                    Err(err) => error_response(err.kind(), err.to_string()),
                },
            }
        }
        Ok(_) => denied("unknown op".to_string()),
        Err(_) => denied("invalid JSON request".to_string()),
    }
}
