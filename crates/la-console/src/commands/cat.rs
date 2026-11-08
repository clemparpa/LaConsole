use super::{collect_paths, read_bounded, Ctx, ExecError, RawOutput};
use crate::parse::SimpleCommand;

pub(crate) fn run(
    cmd: &SimpleCommand,
    input: &[u8],
    ctx: &Ctx,
    _quota: &std::sync::Arc<crate::sink::DiskQuota>,
) -> Result<RawOutput, ExecError> {
    let paths = collect_paths(ctx, &cmd.argv[1..])?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut code = 0u16;
    if paths.is_empty() {
        stdout.extend_from_slice(input);
    }
    for path in &paths {
        match read_bounded(ctx, path) {
            Ok(bytes) => stdout.extend_from_slice(&bytes),
            Err(ExecError::Denied(msg)) => return Err(ExecError::Denied(msg)),
            Err(ExecError::Limit(msg)) => return Err(ExecError::Limit(msg)),
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
