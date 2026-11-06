pub mod cat;
pub mod echo;
pub mod grep;
pub mod http;
pub mod ls;
pub mod sub;

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::parse::{expand_globs, Arg, Node, Redirect, SimpleCommand};
use crate::resolve::Resolver;
use crate::sink::{sensitive_match, CallerSink, DiskQuota, FileSink, PipeSink, Sink, SinkError};

pub const DEFAULT_MAX_READ_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_LS_ENTRIES: usize = 10_000;
pub const DEFAULT_COMMAND_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_MAX_COMMAND_WRITE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_output_bytes: usize,
    pub max_read_bytes: usize,
    pub max_write_bytes: usize,
    pub max_glob_matches: usize,
    pub max_ls_entries: usize,
    pub max_grep_files: usize,
    pub max_grep_matches: usize,
    pub max_http_body_bytes: usize,
    pub max_http_response_bytes: usize,
    pub max_http_redirects: usize,
    pub http_timeout_secs: u64,
    pub command_timeout_secs: u64,
    pub max_command_write_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_output_bytes: crate::sink::DEFAULT_MAX_OUTPUT_BYTES,
            max_read_bytes: DEFAULT_MAX_READ_BYTES,
            max_write_bytes: crate::sink::DEFAULT_MAX_WRITE_BYTES,
            max_glob_matches: crate::parse::DEFAULT_MAX_GLOB_MATCHES,
            max_ls_entries: DEFAULT_MAX_LS_ENTRIES,
            max_grep_files: DEFAULT_MAX_LS_ENTRIES,
            max_grep_matches: grep::DEFAULT_MAX_GREP_MATCHES,
            max_http_body_bytes: http::DEFAULT_MAX_HTTP_BODY_BYTES,
            max_http_response_bytes: http::DEFAULT_MAX_HTTP_RESPONSE_BYTES,
            max_http_redirects: http::MAX_REDIRECTS,
            http_timeout_secs: http::DEFAULT_HTTP_TIMEOUT_SECS,
            command_timeout_secs: DEFAULT_COMMAND_TIMEOUT_SECS,
            max_command_write_bytes: DEFAULT_MAX_COMMAND_WRITE_BYTES,
        }
    }
}

#[derive(Clone)]
pub struct Ctx {
    pub resolver: Resolver,
    pub sensibles: Vec<regex::Regex>,
    pub secrets: Vec<String>,
    pub limits: Limits,
    pub trusted: Option<crate::trusted::TrustedRegistry>,
}

#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("{0}")]
    Denied(String),
    #[error("{0}")]
    Fail(String),
}

#[derive(Debug)]
pub struct ExecOutcome {
    pub code: u16,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}

pub(crate) struct RawOutput {
    pub code: u16,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

struct SimpleResult {
    outcome: ExecOutcome,
    pipe_data: Vec<u8>,
}

pub fn execute(node: &Node, ctx: &Ctx) -> Result<ExecOutcome, ExecError> {
    exec_node(node, &[], ctx).map(|r| r.outcome)
}

fn exec_node(node: &Node, input: &[u8], ctx: &Ctx) -> Result<SimpleResult, ExecError> {
    match node {
        Node::Seq(nodes) => {
            let mut last = None;
            for child in nodes {
                let result = exec_node(child, &[], ctx)?;
                let failed = result.outcome.code != 0;
                last = Some(result);
                if failed {
                    break;
                }
            }
            Ok(last.expect("parser guarantees at least one node in a Seq"))
        }
        Node::Pipe(cmds) => {
            let mut data = input.to_vec();
            for (idx, cmd) in cmds.iter().enumerate() {
                let is_last = idx + 1 == cmds.len();
                let result = exec_simple(cmd, &data, ctx, is_last)?;
                if is_last || result.outcome.code != 0 {
                    return Ok(result);
                }
                data = result.pipe_data;
            }
            unreachable!("parser guarantees at least one command in a Pipe")
        }
        Node::Simple(cmd) => exec_simple(cmd, input, ctx, true),
    }
}

fn exec_simple(
    cmd: &SimpleCommand,
    _input: &[u8],
    ctx: &Ctx,
    final_output: bool,
) -> Result<SimpleResult, ExecError> {
    let quota = Arc::new(DiskQuota::new(ctx.limits.max_command_write_bytes));

    let mut out_file: Option<FileSink> = None;
    let mut err_file: Option<FileSink> = None;
    let mut err_to_out = false;
    let mut all_to_out = false;
    for redir in &cmd.redirects {
        match redir {
            Redirect::Out { path, append } => {
                out_file = Some(new_file_sink(ctx, path, *append, quota.clone())?);
            }
            Redirect::All { path, append } => {
                out_file = Some(new_file_sink(ctx, path, *append, quota.clone())?);
                all_to_out = true;
            }
            Redirect::Err { path } => {
                err_file = Some(new_file_sink(ctx, path, false, quota.clone())?);
            }
            Redirect::ErrToOut => err_to_out = true,
        }
    }

    let raw = run_with_timeout(cmd, ctx, quota)?;

    let mut truncated = false;
    let mut pipe_data = Vec::new();
    let mut out_string = String::new();
    let mut err_string = String::new();

    if let Some(sink) = out_file.as_mut() {
        sink.write(&raw.stdout).map_err(sink_to_exec)?;
        if all_to_out || err_to_out {
            sink.write(&raw.stderr).map_err(sink_to_exec)?;
        }
    } else {
        let bytes = if err_to_out {
            let mut combined = raw.stdout.clone();
            combined.extend_from_slice(&raw.stderr);
            combined
        } else {
            raw.stdout.clone()
        };
        if final_output {
            let mut sink = CallerSink::new(ctx.limits.max_output_bytes, &ctx.secrets);
            sink.write(&bytes).map_err(sink_to_exec)?;
            let (text, was_truncated) = sink.finish();
            out_string = text;
            truncated |= was_truncated;
        } else {
            let mut sink = PipeSink::new(ctx.limits.max_output_bytes);
            sink.write(&bytes).map_err(sink_to_exec)?;
            let (bytes, _was_truncated) = sink.finish();
            pipe_data = bytes;
        }
    }

    if !all_to_out && !err_to_out {
        if let Some(sink) = err_file.as_mut() {
            sink.write(&raw.stderr).map_err(sink_to_exec)?;
        } else {
            let mut sink = CallerSink::new(ctx.limits.max_output_bytes, &ctx.secrets);
            sink.write(&raw.stderr).map_err(sink_to_exec)?;
            let (text, was_truncated) = sink.finish();
            err_string = text;
            truncated |= was_truncated;
        }
    }

    if let Some(sink) = out_file.take() {
        sink.finish().map_err(sink_to_exec)?;
    }
    if let Some(sink) = err_file.take() {
        sink.finish().map_err(sink_to_exec)?;
    }

    Ok(SimpleResult {
        outcome: ExecOutcome {
            code: raw.code,
            stdout: out_string,
            stderr: err_string,
            truncated,
        },
        pipe_data,
    })
}

fn dispatch(
    cmd: &SimpleCommand,
    ctx: &Ctx,
    quota: &Arc<DiskQuota>,
) -> Result<RawOutput, ExecError> {
    let name = cmd.argv[0].text.as_str();
    match name {
        "cat" => cat::run(cmd, ctx, quota),
        "echo" => echo::run(cmd, ctx, quota),
        "grep" => grep::run(cmd, ctx, quota),
        "http" => http::run(cmd, ctx, quota),
        "ls" => ls::run(cmd, ctx, quota),
        "sub" => sub::run(cmd, ctx, quota),
        "trusted" => crate::trusted::run(cmd, ctx, quota),
        _ => Err(ExecError::Denied(format!("unknown command: {name}"))),
    }
}

/// Runs one whitelisted command on a worker thread with a hard time bound.
/// On timeout the response is sent immediately; the abandoned worker keeps
/// running but stays capped by the per-file write bound and the shared quota.
fn run_with_timeout(
    cmd: &SimpleCommand,
    ctx: &Ctx,
    quota: Arc<DiskQuota>,
) -> Result<RawOutput, ExecError> {
    let timeout = Duration::from_secs(ctx.limits.command_timeout_secs);
    let (tx, rx) = std::sync::mpsc::channel();
    let owned = ctx.clone();
    let cmd = cmd.clone();
    std::thread::spawn(move || {
        let _ = tx.send(dispatch(&cmd, &owned, &quota));
    });
    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(ExecError::Denied(format!(
            "command timed out after {}s",
            ctx.limits.command_timeout_secs
        ))),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err(ExecError::Fail("command worker panicked".to_string()))
        }
    }
}

fn new_file_sink(
    ctx: &Ctx,
    path: &str,
    append: bool,
    quota: Arc<DiskQuota>,
) -> Result<FileSink, ExecError> {
    FileSink::create(
        &ctx.resolver,
        path,
        append,
        &ctx.sensibles,
        &ctx.secrets,
        ctx.limits.max_write_bytes,
        Some(quota),
    )
    .map_err(sink_to_exec)
}

pub(crate) fn sink_to_exec(err: SinkError) -> ExecError {
    match err {
        SinkError::Denied(denied) => ExecError::Denied(denied.to_string()),
        SinkError::Sensitive(path) => ExecError::Denied(format!("sensitive file: {path}")),
        SinkError::WriteBoundExceeded(max) => {
            ExecError::Denied(format!("write bound exceeded: {max} bytes max"))
        }
        SinkError::QuotaExceeded(max) => {
            ExecError::Denied(format!("disk quota exceeded: {max} bytes max per command"))
        }
        SinkError::Io(io) => ExecError::Fail(format!("i/o error: {io}")),
    }
}

pub(crate) fn check_read_path(ctx: &Ctx, rel: &str) -> Result<std::path::PathBuf, ExecError> {
    let target = ctx
        .resolver
        .resolve(rel)
        .map_err(|err| ExecError::Denied(format!("{rel}: {err}")))?;
    if let Some(sensitive) = sensitive_match(&ctx.sensibles, ctx.resolver.root(), &target) {
        return Err(ExecError::Denied(format!("sensitive file: {sensitive}")));
    }
    Ok(target)
}

pub(crate) fn collect_paths<'a>(
    ctx: &Ctx,
    args: impl IntoIterator<Item = &'a Arg>,
) -> Result<Vec<String>, ExecError> {
    let mut paths = Vec::new();
    for arg in args {
        if arg.glob {
            paths.extend(
                expand_globs(ctx.resolver.root(), &arg.text, ctx.limits.max_glob_matches)
                    .map_err(|err| ExecError::Denied(err.to_string()))?,
            );
        } else {
            paths.push(arg.text.clone());
        }
    }
    Ok(paths)
}

pub(crate) fn resolve_read_target(
    ctx: &Ctx,
    rel: &str,
) -> Result<(PathBuf, fs::Metadata), ExecError> {
    let target = check_read_path(ctx, rel)?;
    let meta = fs::metadata(&target).map_err(|err| ExecError::Fail(format!("{rel}: {err}")))?;
    Ok((target, meta))
}

pub(crate) fn check_read_bound(ctx: &Ctx, rel: &str, meta: &fs::Metadata) -> Result<(), ExecError> {
    if meta.len() > ctx.limits.max_read_bytes as u64 {
        return Err(ExecError::Denied(format!(
            "{rel}: file too large ({} bytes max)",
            ctx.limits.max_read_bytes
        )));
    }
    Ok(())
}

pub(crate) fn read_bounded(ctx: &Ctx, rel: &str) -> Result<Vec<u8>, ExecError> {
    let (target, meta) = resolve_read_target(ctx, rel)?;
    if !meta.is_file() {
        return Err(ExecError::Fail(format!("{rel}: not a regular file")));
    }
    check_read_bound(ctx, rel, &meta)?;
    let bytes = fs::read(&target).map_err(|err| ExecError::Fail(format!("{rel}: {err}")))?;
    if bytes.len() > ctx.limits.max_read_bytes {
        return Err(ExecError::Denied(format!(
            "{rel}: file too large ({} bytes max)",
            ctx.limits.max_read_bytes
        )));
    }
    Ok(bytes)
}

pub(crate) fn write_file(
    ctx: &Ctx,
    rel: &str,
    bytes: &[u8],
    append: bool,
    quota: Arc<DiskQuota>,
) -> Result<(), ExecError> {
    let mut sink = FileSink::create(
        &ctx.resolver,
        rel,
        append,
        &ctx.sensibles,
        &ctx.secrets,
        ctx.limits.max_write_bytes,
        Some(quota),
    )
    .map_err(sink_to_exec)?;
    sink.write(bytes).map_err(sink_to_exec)?;
    sink.finish().map_err(sink_to_exec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_input;
    use std::collections::HashMap;
    use std::fs;

    fn make_ctx(
        resolver: Resolver,
        sensibles: Vec<regex::Regex>,
        secrets: Vec<String>,
        max_read_bytes: usize,
    ) -> Ctx {
        Ctx {
            resolver,
            sensibles,
            secrets,
            limits: Limits {
                max_read_bytes,
                ..Limits::default()
            },
            trusted: None,
        }
    }

    fn run_cmd(dir: &tempfile::TempDir, cmd: &str) -> Result<ExecOutcome, ExecError> {
        let resolver = Resolver::new(dir.path()).unwrap();
        let ctx = make_ctx(resolver, vec![], vec![], DEFAULT_MAX_READ_BYTES);
        let node = parse_input(cmd, &HashMap::new()).unwrap();
        execute(&node, &ctx)
    }

    #[test]
    fn cat_reads_file_within_root() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("hello.txt"), b"hello\n").unwrap();
        let out = run_cmd(&dir, "cat hello.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "hello\n");
        assert_eq!(out.stderr, "");
        assert!(!out.truncated);
    }

    #[test]
    fn cat_denies_parent_dir_escape() {
        let dir = tempfile::tempdir().unwrap();
        let err = run_cmd(&dir, "cat ../evil.txt").unwrap_err();
        assert!(matches!(err, ExecError::Denied(_)));
    }

    #[test]
    fn cat_denies_absolute_path_outside_root() {
        let dir = tempfile::tempdir().unwrap();
        let err = run_cmd(&dir, "cat /etc/passwd").unwrap_err();
        assert!(matches!(err, ExecError::Denied(_)));
    }

    #[test]
    fn cat_denies_sensitive_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".env"), b"SECRET=1").unwrap();
        let resolver = Resolver::new(dir.path()).unwrap();
        let sensibles = vec![regex::Regex::new(r".*\.env$").unwrap()];
        let ctx = make_ctx(resolver, sensibles, vec![], DEFAULT_MAX_READ_BYTES);
        let node = parse_input("cat .env", &HashMap::new()).unwrap();
        let err = execute(&node, &ctx).unwrap_err();
        assert!(matches!(err, ExecError::Denied(_)));
    }

    #[test]
    fn cat_denies_file_over_read_bound() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("big.txt"), b"0123456789").unwrap();
        let resolver = Resolver::new(dir.path()).unwrap();
        let ctx = make_ctx(resolver, vec![], vec![], 4);
        let node = parse_input("cat big.txt", &HashMap::new()).unwrap();
        let err = execute(&node, &ctx).unwrap_err();
        assert!(matches!(err, ExecError::Denied(_)));
    }

    #[test]
    fn cat_missing_file_returns_code_1() {
        let dir = tempfile::tempdir().unwrap();
        let out = run_cmd(&dir, "cat nope.txt").unwrap();
        assert_eq!(out.code, 1);
        assert!(out.stderr.contains("nope.txt"));
    }

    #[test]
    fn cat_expands_glob_within_root() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"A").unwrap();
        fs::write(dir.path().join("b.txt"), b"B").unwrap();
        fs::write(dir.path().join("c.rs"), b"C").unwrap();
        let out = run_cmd(&dir, "cat *.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "AB");
    }

    #[test]
    fn unknown_command_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        let err = run_cmd(&dir, "rm -rf /").unwrap_err();
        assert!(matches!(err, ExecError::Denied(m) if m.contains("unknown command")));
    }

    #[test]
    fn seq_returns_last_command_output() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"A").unwrap();
        fs::write(dir.path().join("b.txt"), b"B").unwrap();
        let out = run_cmd(&dir, "cat a.txt && cat b.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "B");
    }

    #[test]
    fn seq_stops_at_first_failure() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("b.txt"), b"B").unwrap();
        let out = run_cmd(&dir, "cat missing.txt && cat b.txt").unwrap();
        assert_eq!(out.code, 1);
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn pipe_feeds_stdout_to_next_command() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"A").unwrap();
        fs::write(dir.path().join("b.txt"), b"B").unwrap();
        let out = run_cmd(&dir, "cat a.txt | cat b.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "B");
    }

    #[test]
    fn redirect_writes_through_file_sink_with_masking() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("in.txt"), b"token=tok-abc123\n").unwrap();
        let resolver = Resolver::new(dir.path()).unwrap();
        let secrets = vec!["tok-abc123".to_string()];
        let ctx = make_ctx(resolver, vec![], secrets, DEFAULT_MAX_READ_BYTES);
        let node = parse_input("cat in.txt > out.txt", &HashMap::new()).unwrap();
        let out = execute(&node, &ctx).unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "");
        let content = fs::read_to_string(dir.path().join("out.txt")).unwrap();
        assert_eq!(content, "token=***\n");
    }

    #[test]
    fn redirect_target_is_validated_before_execution() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("in.txt"), b"data").unwrap();
        let err = run_cmd(&dir, "cat in.txt > ../evil.txt").unwrap_err();
        assert!(matches!(err, ExecError::Denied(_)));
        assert!(!dir.path().parent().unwrap().join("evil.txt").exists());
    }
}

#[cfg(test)]
mod bound_tests {
    use super::*;
    use crate::parse::parse_input;
    use std::collections::HashMap;

    fn ctx_with(dir: &tempfile::TempDir, limits: Limits) -> Ctx {
        Ctx {
            resolver: Resolver::new(dir.path()).unwrap(),
            sensibles: vec![],
            secrets: vec![],
            limits,
            trusted: None,
        }
    }

    #[test]
    fn command_time_bound_denies_slow_command() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                std::thread::sleep(std::time::Duration::from_secs(30));
                drop(stream);
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let limits = Limits {
            command_timeout_secs: 1,
            ..Limits::default()
        };
        let ctx = ctx_with(&dir, limits);
        let node = parse_input(
            &format!("http GET http://127.0.0.1:{port}/"),
            &HashMap::new(),
        )
        .unwrap();
        let err = execute(&node, &ctx).unwrap_err();
        assert!(
            matches!(err, ExecError::Denied(ref m) if m.contains("timed out")),
            "got {err:?}"
        );
    }

    #[test]
    fn command_time_bound_allows_fast_command() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"fast").unwrap();
        let limits = Limits {
            command_timeout_secs: 5,
            ..Limits::default()
        };
        let ctx = ctx_with(&dir, limits);
        let node = parse_input("cat a.txt", &HashMap::new()).unwrap();
        let out = execute(&node, &ctx).unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "fast");
    }

    #[test]
    fn disk_quota_denies_writes_over_per_command_bound() {
        let dir = tempfile::tempdir().unwrap();
        let limits = Limits {
            max_command_write_bytes: 5,
            ..Limits::default()
        };
        let ctx = ctx_with(&dir, limits);
        let node = parse_input("echo hello > out.txt", &HashMap::new()).unwrap();
        let err = execute(&node, &ctx).unwrap_err();
        assert!(
            matches!(err, ExecError::Denied(ref m) if m.contains("disk quota")),
            "got {err:?}"
        );
    }

    #[test]
    fn disk_quota_allows_writes_under_bound() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("in.txt"), "hi").unwrap();
        let limits = Limits {
            max_command_write_bytes: 100,
            ..Limits::default()
        };
        let ctx = ctx_with(&dir, limits);
        let node = parse_input("cat in.txt > out.txt", &HashMap::new()).unwrap();
        let out = execute(&node, &ctx).unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(
            fs::read_to_string(dir.path().join("out.txt")).unwrap(),
            "hi"
        );
    }

    #[test]
    fn disk_quota_is_per_command_in_a_seq() {
        let dir = tempfile::tempdir().unwrap();
        let limits = Limits {
            max_command_write_bytes: 4,
            ..Limits::default()
        };
        let ctx = ctx_with(&dir, limits);
        let node = parse_input("echo ab > a.txt && echo cd > b.txt", &HashMap::new()).unwrap();
        let out = execute(&node, &ctx).unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(
            fs::read_to_string(dir.path().join("a.txt")).unwrap(),
            "ab\n"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("b.txt")).unwrap(),
            "cd\n"
        );
    }
}

#[cfg(test)]
mod helper_tests {
    use super::*;
    use crate::parse::parse_input;
    use std::collections::HashMap;

    fn make_ctx(
        resolver: Resolver,
        sensibles: Vec<regex::Regex>,
        secrets: Vec<String>,
        limits: Limits,
    ) -> Ctx {
        Ctx {
            resolver,
            sensibles,
            secrets,
            limits,
            trusted: None,
        }
    }

    fn test_quota() -> Arc<DiskQuota> {
        Arc::new(DiskQuota::new(1024))
    }

    fn args(input: &str) -> Vec<Arg> {
        let node = parse_input(input, &HashMap::new()).unwrap();
        let Node::Simple(cmd) = node else {
            panic!("expected Simple");
        };
        cmd.argv
    }

    #[test]
    fn collect_paths_passes_plain_args_and_expands_globs() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"").unwrap();
        fs::write(dir.path().join("b.txt"), b"").unwrap();
        fs::write(dir.path().join("c.rs"), b"").unwrap();
        let resolver = Resolver::new(dir.path()).unwrap();
        let ctx = make_ctx(resolver, vec![], vec![], Limits::default());
        let argv = args("cmd plain.txt *.txt");
        let paths = collect_paths(&ctx, &argv[1..]).unwrap();
        assert_eq!(paths, vec!["plain.txt", "a.txt", "b.txt"]);
    }

    #[test]
    fn collect_paths_denies_glob_overflow() {
        let dir = tempfile::tempdir().unwrap();
        for n in 0..5 {
            fs::write(dir.path().join(format!("f{n}.txt")), b"").unwrap();
        }
        let resolver = Resolver::new(dir.path()).unwrap();
        let limits = Limits {
            max_glob_matches: 3,
            ..Limits::default()
        };
        let ctx = make_ctx(resolver, vec![], vec![], limits);
        let argv = args("cmd *.txt");
        assert!(matches!(
            collect_paths(&ctx, &argv[1..]),
            Err(ExecError::Denied(_))
        ));
    }

    #[test]
    fn read_bounded_reads_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"data").unwrap();
        let resolver = Resolver::new(dir.path()).unwrap();
        let ctx = make_ctx(resolver, vec![], vec![], Limits::default());
        assert_eq!(read_bounded(&ctx, "a.txt").unwrap(), b"data");
    }

    #[test]
    fn read_bounded_rejects_dir_missing_oversize_escape_sensitive() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("big.bin"), vec![0u8; 2048]).unwrap();
        fs::write(dir.path().join(".env"), b"X=1").unwrap();
        let resolver = Resolver::new(dir.path()).unwrap();
        let sensibles = vec![regex::Regex::new(r".*\.env$").unwrap()];
        let limits = Limits {
            max_read_bytes: 1024,
            ..Limits::default()
        };
        let ctx = make_ctx(resolver, sensibles, vec![], limits);
        assert!(matches!(
            read_bounded(&ctx, "sub"),
            Err(ExecError::Fail(m)) if m.contains("not a regular file")
        ));
        assert!(matches!(
            read_bounded(&ctx, "missing.txt"),
            Err(ExecError::Fail(_))
        ));
        assert!(matches!(
            read_bounded(&ctx, "big.bin"),
            Err(ExecError::Denied(_))
        ));
        assert!(matches!(
            read_bounded(&ctx, "../escape.txt"),
            Err(ExecError::Denied(_))
        ));
        assert!(matches!(
            read_bounded(&ctx, ".env"),
            Err(ExecError::Denied(_))
        ));
    }

    #[test]
    fn write_file_writes_appends_and_enforces_rules() {
        let dir = tempfile::tempdir().unwrap();
        let resolver = Resolver::new(dir.path()).unwrap();
        let secrets = vec!["tok-abc123".to_string()];
        let ctx = make_ctx(resolver.clone(), vec![], secrets, Limits::default());
        write_file(&ctx, "out.txt", b"hello ", false, test_quota()).unwrap();
        write_file(&ctx, "out.txt", b"tok-abc123", true, test_quota()).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("out.txt")).unwrap(),
            "hello ***"
        );
        assert!(matches!(
            write_file(&ctx, "../evil.txt", b"x", false, test_quota()),
            Err(ExecError::Denied(_))
        ));
        assert!(!dir.path().parent().unwrap().join("evil.txt").exists());
        let sensibles = vec![regex::Regex::new(r".*\.env$").unwrap()];
        let ctx = make_ctx(resolver.clone(), sensibles, vec![], Limits::default());
        assert!(matches!(
            write_file(&ctx, ".env", b"x", false, test_quota()),
            Err(ExecError::Denied(_))
        ));
        assert!(!dir.path().join(".env").exists());
        let limits = Limits {
            max_write_bytes: 3,
            ..Limits::default()
        };
        let ctx = make_ctx(resolver.clone(), vec![], vec![], limits);
        assert!(matches!(
            write_file(&ctx, "big.txt", b"too long", false, test_quota()),
            Err(ExecError::Denied(_))
        ));
    }

    #[test]
    fn limits_defaults_are_sane() {
        let l = Limits::default();
        assert!(l.max_output_bytes > 0);
        assert!(l.max_read_bytes > 0);
        assert!(l.max_write_bytes > 0);
        assert!(l.max_glob_matches > 0);
        assert!(l.max_ls_entries > 0);
        assert!(l.max_grep_files > 0);
        assert!(l.max_grep_matches > 0);
        assert!(l.max_http_body_bytes > 0);
        assert!(l.max_http_response_bytes > 0);
        assert!(l.max_http_redirects > 0);
        assert!(l.http_timeout_secs > 0);
    }
}
