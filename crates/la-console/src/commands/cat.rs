use super::{check_read_path, Ctx, ExecError, RawOutput};
use crate::parse::{expand_globs, SimpleCommand, DEFAULT_MAX_GLOB_MATCHES};

pub(crate) fn run(cmd: &SimpleCommand, ctx: &Ctx) -> Result<RawOutput, ExecError> {
    let mut paths: Vec<String> = Vec::new();
    for arg in &cmd.argv[1..] {
        if arg.glob {
            let matches = expand_globs(ctx.resolver.root(), &arg.text, DEFAULT_MAX_GLOB_MATCHES)
                .map_err(|err| ExecError::Denied(err.to_string()))?;
            paths.extend(matches);
        } else {
            paths.push(arg.text.clone());
        }
    }
    if paths.is_empty() {
        return Err(ExecError::Fail(
            "cat: missing file operand (stdin is not available)".to_string(),
        ));
    }

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut code = 0u16;
    for path in &paths {
        match read_one(ctx, path) {
            Ok(bytes) => stdout.extend_from_slice(&bytes),
            Err(ExecError::Denied(msg)) => return Err(ExecError::Denied(msg)),
            Err(ExecError::Fail(msg)) => {
                code = 1;
                stderr.extend_from_slice(format!("cat: {msg}\n").as_bytes());
            }
        }
    }
    Ok(RawOutput {
        code,
        stdout,
        stderr,
    })
}

fn read_one(ctx: &Ctx, rel: &str) -> Result<Vec<u8>, ExecError> {
    let target = check_read_path(ctx, rel)?;
    let meta =
        std::fs::metadata(&target).map_err(|err| ExecError::Fail(format!("{rel}: {err}")))?;
    if meta.is_dir() {
        return Err(ExecError::Fail(format!("{rel}: Is a directory")));
    }
    if meta.len() > ctx.max_read_bytes as u64 {
        return Err(ExecError::Denied(format!(
            "{rel}: file too large ({} bytes > {} max)",
            meta.len(),
            ctx.max_read_bytes
        )));
    }
    std::fs::read(&target).map_err(|err| ExecError::Fail(format!("{rel}: {err}")))
}
