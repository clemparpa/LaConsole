use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::Path;

use crate::commands::{execute, Ctx, ExecError, Limits};
use crate::resolve::Resolver;

#[derive(Debug, Deserialize)]
pub struct Request {
    pub op: String,
    pub cmd: String,
}

#[derive(Debug, Serialize)]
pub struct Response {
    pub ok: bool,
    pub code: u16,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}

pub fn run<R: BufRead, W: Write>(root: &Path, mut input: R, mut output: W) -> std::io::Result<()> {
    let resolver = Resolver::new(root)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string()))?;
    let sensibles: Vec<regex::Regex> = Vec::new();
    let secrets: Vec<String> = Vec::new();
    let ctx = Ctx {
        resolver: &resolver,
        sensibles: &sensibles,
        secrets: &secrets,
        limits: Limits::default(),
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

fn denied(message: String) -> Response {
    Response {
        ok: false,
        code: 2,
        stdout: String::new(),
        stderr: format!("denied: {message}"),
        truncated: false,
    }
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
                        stdout: outcome.stdout,
                        stderr: outcome.stderr,
                        truncated: outcome.truncated,
                    },
                    Err(ExecError::Denied(message)) => denied(message),
                    Err(ExecError::Fail(message)) => Response {
                        ok: false,
                        code: 1,
                        stdout: String::new(),
                        stderr: message,
                        truncated: false,
                    },
                },
            }
        }
        Ok(_) => denied("unknown op".to_string()),
        Err(_) => denied("invalid JSON request".to_string()),
    }
}
