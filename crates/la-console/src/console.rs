use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};

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

pub fn run<R: BufRead, W: Write>(mut input: R, mut output: W) -> std::io::Result<()> {
    let mut line = String::new();
    loop {
        line.clear();
        if input.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let response = handle_line(&line);
        serde_json::to_writer(&mut output, &response)?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
}

fn handle_line(line: &str) -> Response {
    match serde_json::from_str::<Request>(line) {
        Ok(req) if req.op == "exec" => Response {
            ok: false,
            code: 2,
            stdout: String::new(),
            stderr: format!("denied: no command available yet: {}", req.cmd),
            truncated: false,
        },
        Ok(_) => Response {
            ok: false,
            code: 2,
            stdout: String::new(),
            stderr: "denied: unknown op".to_string(),
            truncated: false,
        },
        Err(_) => Response {
            ok: false,
            code: 2,
            stdout: String::new(),
            stderr: "denied: invalid JSON request".to_string(),
            truncated: false,
        },
    }
}
