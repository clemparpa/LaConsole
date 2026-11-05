pub mod cat;
pub mod echo;
pub mod grep;
pub mod http;
pub mod ls;
pub mod sub;

use std::fs;
use std::path::PathBuf;

use crate::parse::{expand_globs, Arg, Node, Redirect, SimpleCommand};
use crate::resolve::Resolver;
use crate::sink::{sensitive_match, CallerSink, FileSink, PipeSink, Sink, SinkError};

pub const DEFAULT_MAX_READ_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_LS_ENTRIES: usize = 10_000;

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
        }
    }
}

pub struct Ctx<'a> {
    pub resolver: &'a Resolver,
    pub sensibles: &'a [regex::Regex],
    pub secrets: &'a [String],
    pub limits: Limits,
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
    let name = cmd.argv[0].text.as_str();
    let raw = match name {
        "cat" => cat::run(cmd, ctx)?,
        "echo" => echo::run(cmd, ctx)?,
        "grep" => grep::run(cmd, ctx)?,
        "http" => http::run(cmd, ctx)?,
        "ls" => ls::run(cmd, ctx)?,
        "sub" => sub::run(cmd, ctx)?,
        _ => return Err(ExecError::Denied(format!("unknown command: {name}"))),
    };

    let mut out_file: Option<FileSink> = None;
    let mut err_file: Option<FileSink> = None;
    let mut err_to_out = false;
    let mut all_to_out = false;
    for redir in &cmd.redirects {
        match redir {
            Redirect::Out { path, append } => {
                out_file = Some(new_file_sink(ctx, path, *append)?);
            }
            Redirect::All { path, append } => {
                out_file = Some(new_file_sink(ctx, path, *append)?);
                all_to_out = true;
            }
            Redirect::Err { path } => {
                err_file = Some(new_file_sink(ctx, path, false)?);
            }
            Redirect::ErrToOut => err_to_out = true,
        }
    }

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
            let mut sink = CallerSink::new(ctx.limits.max_output_bytes, ctx.secrets);
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
            let mut sink = CallerSink::new(ctx.limits.max_output_bytes, ctx.secrets);
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

fn new_file_sink(ctx: &Ctx, path: &str, append: bool) -> Result<FileSink, ExecError> {
    FileSink::create(
        ctx.resolver,
        path,
        append,
        ctx.sensibles,
        ctx.secrets,
        ctx.limits.max_write_bytes,
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
        SinkError::Io(io) => ExecError::Fail(format!("i/o error: {io}")),
    }
}

pub(crate) fn check_read_path(ctx: &Ctx, rel: &str) -> Result<std::path::PathBuf, ExecError> {
    let target = ctx
        .resolver
        .resolve(rel)
        .map_err(|err| ExecError::Denied(format!("{rel}: {err}")))?;
    if let Some(sensitive) = sensitive_match(ctx.sensibles, ctx.resolver.root(), &target) {
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
) -> Result<(), ExecError> {
    let mut sink = FileSink::create(
        ctx.resolver,
        rel,
        append,
        ctx.sensibles,
        ctx.secrets,
        ctx.limits.max_write_bytes,
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

    fn make_ctx<'a>(
        resolver: &'a Resolver,
        sensibles: &'a [regex::Regex],
        secrets: &'a [String],
        max_read_bytes: usize,
    ) -> Ctx<'a> {
        Ctx {
            resolver,
            sensibles,
            secrets,
            limits: Limits {
                max_read_bytes,
                ..Limits::default()
            },
        }
    }

    fn run_cmd(dir: &tempfile::TempDir, cmd: &str) -> Result<ExecOutcome, ExecError> {
        let resolver = Resolver::new(dir.path()).unwrap();
        let ctx = make_ctx(&resolver, &[], &[], DEFAULT_MAX_READ_BYTES);
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
        let ctx = make_ctx(&resolver, &sensibles, &[], DEFAULT_MAX_READ_BYTES);
        let node = parse_input("cat .env", &HashMap::new()).unwrap();
        let err = execute(&node, &ctx).unwrap_err();
        assert!(matches!(err, ExecError::Denied(_)));
    }

    #[test]
    fn cat_denies_file_over_read_bound() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("big.txt"), b"0123456789").unwrap();
        let resolver = Resolver::new(dir.path()).unwrap();
        let ctx = make_ctx(&resolver, &[], &[], 4);
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
        let ctx = make_ctx(&resolver, &[], &secrets, DEFAULT_MAX_READ_BYTES);
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
mod helper_tests {
    use super::*;
    use crate::parse::parse_input;
    use std::collections::HashMap;

    fn make_ctx<'a>(
        resolver: &'a Resolver,
        sensibles: &'a [regex::Regex],
        secrets: &'a [String],
        limits: Limits,
    ) -> Ctx<'a> {
        Ctx {
            resolver,
            sensibles,
            secrets,
            limits,
        }
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
        let ctx = make_ctx(&resolver, &[], &[], Limits::default());
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
        let ctx = make_ctx(&resolver, &[], &[], limits);
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
        let ctx = make_ctx(&resolver, &[], &[], Limits::default());
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
        let ctx = make_ctx(&resolver, &sensibles, &[], limits);
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
        let ctx = make_ctx(&resolver, &[], &secrets, Limits::default());
        write_file(&ctx, "out.txt", b"hello ", false).unwrap();
        write_file(&ctx, "out.txt", b"tok-abc123", true).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("out.txt")).unwrap(),
            "hello ***"
        );
        assert!(matches!(
            write_file(&ctx, "../evil.txt", b"x", false),
            Err(ExecError::Denied(_))
        ));
        assert!(!dir.path().parent().unwrap().join("evil.txt").exists());
        let sensibles = vec![regex::Regex::new(r".*\.env$").unwrap()];
        let ctx = make_ctx(&resolver, &sensibles, &[], Limits::default());
        assert!(matches!(
            write_file(&ctx, ".env", b"x", false),
            Err(ExecError::Denied(_))
        ));
        assert!(!dir.path().join(".env").exists());
        let limits = Limits {
            max_write_bytes: 3,
            ..Limits::default()
        };
        let ctx = make_ctx(&resolver, &[], &[], limits);
        assert!(matches!(
            write_file(&ctx, "big.txt", b"too long", false),
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
