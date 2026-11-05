pub mod cat;

use std::path::Path;

use crate::parse::{Node, Redirect, SimpleCommand};
use crate::resolve::{Denied, Resolver};
use crate::sink::{CallerSink, FileSink, PipeSink, Sink, SinkError, DEFAULT_MAX_WRITE_BYTES};

pub const DEFAULT_MAX_READ_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_output_bytes: usize,
    pub max_read_bytes: usize,
    pub max_write_bytes: usize,
    pub max_glob_matches: usize,
}

pub struct ExecContext {
    pub resolver: Resolver,
    pub sensibles: Vec<regex::Regex>,
    pub secrets: Vec<String>,
    pub limits: Limits,
}

impl ExecContext {
    pub fn new(
        root: &Path,
        max_output_bytes: usize,
        sensibles: Vec<regex::Regex>,
        secrets: Vec<String>,
    ) -> Result<Self, Denied> {
        Ok(Self {
            resolver: Resolver::new(root)?,
            sensibles,
            secrets,
            limits: Limits {
                max_output_bytes,
                max_read_bytes: DEFAULT_MAX_READ_BYTES,
                max_write_bytes: DEFAULT_MAX_WRITE_BYTES,
                max_glob_matches: crate::parse::DEFAULT_MAX_GLOB_MATCHES,
            },
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("unknown command '{0}'")]
    UnknownCommand(String),
    #[error("{0}")]
    Denied(String),
    #[error("sensitive file: {0}")]
    Sensitive(String),
    #[error("file too large: {0} bytes (max {1})")]
    TooLarge(usize, usize),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Sink(#[from] SinkError),
}

#[derive(Debug)]
pub struct SimpleOutput {
    pub code: u16,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug)]
pub struct ExecResult {
    pub ok: bool,
    pub code: u16,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}

pub fn execute(node: &Node, ctx: &ExecContext) -> Result<ExecResult, ExecError> {
    let mut stdout = CallerSink::new(ctx.limits.max_output_bytes, &ctx.secrets);
    let mut stderr = CallerSink::new(ctx.limits.max_output_bytes, &ctx.secrets);
    let code = exec_node(node, ctx, &[], &mut stdout, &mut stderr)?;
    let (out, out_truncated) = stdout.finish();
    let (err, err_truncated) = stderr.finish();
    Ok(ExecResult {
        ok: code == 0,
        code,
        stdout: out,
        stderr: err,
        truncated: out_truncated || err_truncated,
    })
}

fn exec_node(
    node: &Node,
    ctx: &ExecContext,
    input: &[u8],
    stdout: &mut CallerSink,
    stderr: &mut CallerSink,
) -> Result<u16, ExecError> {
    match node {
        Node::Seq(nodes) => {
            let mut code = 0u16;
            for child in nodes {
                code = exec_node(child, ctx, &[], stdout, stderr)?;
                if code != 0 {
                    return Ok(code);
                }
            }
            Ok(code)
        }
        Node::Pipe(cmds) => {
            let Some((last, rest)) = cmds.split_last() else {
                return Ok(0);
            };
            let mut data = input.to_vec();
            for cmd in rest {
                let out = run_simple(cmd, ctx, &data)?;
                stderr.write(&out.stderr)?;
                if out.code != 0 {
                    return Ok(out.code);
                }
                let mut pipe = PipeSink::new(ctx.limits.max_output_bytes);
                pipe.write(&out.stdout)?;
                let (bytes, _) = pipe.finish();
                data = bytes;
            }
            exec_simple(last, ctx, &data, stdout, stderr)
        }
        Node::Simple(cmd) => exec_simple(cmd, ctx, input, stdout, stderr),
    }
}

fn run_simple(
    cmd: &SimpleCommand,
    ctx: &ExecContext,
    input: &[u8],
) -> Result<SimpleOutput, ExecError> {
    match cmd.argv[0].text.as_str() {
        "cat" => cat::run(cmd, ctx, input),
        other => Err(ExecError::UnknownCommand(other.to_string())),
    }
}

fn exec_simple(
    cmd: &SimpleCommand,
    ctx: &ExecContext,
    input: &[u8],
    stdout: &mut CallerSink,
    stderr: &mut CallerSink,
) -> Result<u16, ExecError> {
    let mut out_file: Option<FileSink> = None;
    let mut err_file: Option<FileSink> = None;
    let mut err_to_out = false;
    let mut all_to_out_file = false;
    for redirect in &cmd.redirects {
        match redirect {
            Redirect::Out { path, append } => {
                out_file = Some(FileSink::create(
                    &ctx.resolver,
                    path,
                    *append,
                    &ctx.sensibles,
                    &ctx.secrets,
                    ctx.limits.max_write_bytes,
                )?);
            }
            Redirect::Err { path } => {
                err_file = Some(FileSink::create(
                    &ctx.resolver,
                    path,
                    false,
                    &ctx.sensibles,
                    &ctx.secrets,
                    ctx.limits.max_write_bytes,
                )?);
            }
            Redirect::ErrToOut => err_to_out = true,
            Redirect::All { path, append } => {
                out_file = Some(FileSink::create(
                    &ctx.resolver,
                    path,
                    *append,
                    &ctx.sensibles,
                    &ctx.secrets,
                    ctx.limits.max_write_bytes,
                )?);
                all_to_out_file = true;
            }
        }
    }
    let out = run_simple(cmd, ctx, input)?;
    if let Some(mut sink) = out_file.take() {
        sink.write(&out.stdout)?;
        if err_to_out || all_to_out_file {
            sink.write(&out.stderr)?;
        }
        sink.finish()?;
    } else {
        stdout.write(&out.stdout)?;
        if err_to_out {
            stdout.write(&out.stderr)?;
        }
    }
    if let Some(mut sink) = err_file.take() {
        sink.write(&out.stderr)?;
        sink.finish()?;
    } else if !err_to_out && !all_to_out_file {
        stderr.write(&out.stderr)?;
    }
    Ok(out.code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;

    fn ctx(dir: &tempfile::TempDir) -> ExecContext {
        ExecContext::new(dir.path(), 1024, vec![], vec![]).unwrap()
    }

    fn node(input: &str) -> Node {
        crate::parse::parse_input(input, &HashMap::new()).unwrap()
    }

    #[test]
    fn unknown_command_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        let err = execute(&node("ls src"), &ctx(&dir)).unwrap_err();
        assert!(matches!(err, ExecError::UnknownCommand(ref c) if c == "ls"));
    }

    #[test]
    fn seq_stops_at_first_failure() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("ok.txt"), b"ok").unwrap();
        let res = execute(&node("cat missing.txt && cat ok.txt"), &ctx(&dir)).unwrap();
        assert!(!res.ok);
        assert_eq!(res.code, 1);
        assert_eq!(res.stdout, "");
        assert!(res.stderr.contains("missing.txt"));
    }

    #[test]
    fn seq_runs_all_on_success() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"A").unwrap();
        fs::write(dir.path().join("b.txt"), b"B").unwrap();
        let res = execute(&node("cat a.txt && cat b.txt"), &ctx(&dir)).unwrap();
        assert!(res.ok);
        assert_eq!(res.stdout, "AB");
    }

    #[test]
    fn pipe_threads_stdout_into_next_command() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"hello").unwrap();
        let res = execute(&node("cat a.txt | cat"), &ctx(&dir)).unwrap();
        assert!(res.ok);
        assert_eq!(res.stdout, "hello");
    }

    #[test]
    fn redirect_writes_through_file_sink() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"data").unwrap();
        let res = execute(&node("cat a.txt > b.txt"), &ctx(&dir)).unwrap();
        assert!(res.ok);
        assert_eq!(res.stdout, "");
        assert_eq!(
            fs::read_to_string(dir.path().join("b.txt")).unwrap(),
            "data"
        );
    }

    #[test]
    fn redirect_target_is_validated_before_execution() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"data").unwrap();
        let err = execute(&node("cat a.txt > ../evil.txt"), &ctx(&dir)).unwrap_err();
        assert!(matches!(err, ExecError::Sink(_)));
        assert!(!dir.path().parent().unwrap().join("evil.txt").exists());
    }

    #[test]
    fn output_is_truncated_and_flagged() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("big.txt"), b"0123456789ABCDEF").unwrap();
        let ctx = ExecContext::new(dir.path(), 10, vec![], vec![]).unwrap();
        let res = execute(&node("cat big.txt"), &ctx).unwrap();
        assert!(res.ok);
        assert!(res.truncated);
        assert_eq!(res.stdout.len(), 10);
    }

    #[test]
    fn secrets_are_masked_in_caller_output() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("k.txt"), b"tok-abc123").unwrap();
        let ctx =
            ExecContext::new(dir.path(), 1024, vec![], vec!["tok-abc123".to_string()]).unwrap();
        let res = execute(&node("cat k.txt"), &ctx).unwrap();
        assert_eq!(res.stdout, crate::sink::SECRET_MASK);
    }
}
