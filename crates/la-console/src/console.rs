use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, Write};

use crate::commands::{self, ExecContext};

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

pub fn run<R: BufRead, W: Write>(
    mut input: R,
    mut output: W,
    ctx: &ExecContext,
) -> std::io::Result<()> {
    let mut line = String::new();
    loop {
        line.clear();
        if input.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let response = handle_line(&line, ctx);
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

fn handle_line(line: &str, ctx: &ExecContext) -> Response {
    match serde_json::from_str::<Request>(line) {
        Ok(req) if req.op == "exec" => {
            let vars = HashMap::new();
            match crate::parse::parse_input(&req.cmd, &vars) {
                Err(err) => denied(err.to_string()),
                Ok(node) => match commands::execute(&node, ctx) {
                    Ok(result) => Response {
                        ok: result.ok,
                        code: result.code,
                        stdout: result.stdout,
                        stderr: result.stderr,
                        truncated: result.truncated,
                    },
                    Err(err) => denied(err.to_string()),
                },
            }
        }
        Ok(_) => denied("unknown op".to_string()),
        Err(_) => denied("invalid JSON request".to_string()),
    }
}
