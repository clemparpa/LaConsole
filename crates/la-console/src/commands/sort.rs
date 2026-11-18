use std::sync::Arc;

use super::stream::{read_sources, split_lines, unsupported_opt, utf8};
use super::{Ctx, ExecError, RawOutput};
use crate::parse::{Arg, SimpleCommand};
use crate::sink::DiskQuota;

/// Parses `[-r]` / `--reverse`; `--` ends options. Any other option is a
/// `fail` (fail-closed: no -n, -k, -u, ...).
fn parse_opts<'a>(name: &str, args: &'a [Arg]) -> Result<(bool, Vec<&'a Arg>), ExecError> {
    let mut reverse = false;
    let mut positional = Vec::new();
    let mut i = 0usize;
    let mut opts_done = false;
    while i < args.len() {
        let text = args[i].text.as_str();
        if !opts_done && text == "--" {
            opts_done = true;
        } else if !opts_done && text.starts_with("--") && text.len() > 2 {
            let body = &text[2..];
            let (opt, inline) = match body.find('=') {
                Some(p) => (&body[..p], Some(body[p + 1..].to_string())),
                None => (body, None),
            };
            if opt == "reverse" && inline.is_none() {
                reverse = true;
            } else {
                return Err(unsupported_opt(name, text));
            }
        } else if !opts_done && text.starts_with('-') && text.len() > 1 {
            for c in text[1..].chars() {
                if c == 'r' {
                    reverse = true;
                } else {
                    return Err(unsupported_opt(name, &format!("-{c}")));
                }
            }
        } else {
            positional.push(&args[i]);
        }
        i += 1;
    }
    Ok((reverse, positional))
}

/// `sort [-r] [path...]`: lexicographic UTF-8 sort of all input lines
/// (`-r` reverses). The only buffering filter: the line vector is bounded by
/// `Limits::max_stream_lines` (over = `limit`, code 3). Output lines are
/// always newline-terminated (GNU sort behavior).
pub(crate) fn run(
    cmd: &SimpleCommand,
    input: &[u8],
    ctx: &Ctx,
    _quota: &Arc<DiskQuota>,
) -> Result<RawOutput, ExecError> {
    let (reverse, paths) = parse_opts("sort", &cmd.argv[1..])?;
    let (data, stderr, code) = read_sources("sort", ctx, &paths, input)?;
    let text = utf8("sort", data)?;
    let (mut lines, _trailing) = split_lines(&text);
    if lines.len() > ctx.limits.max_stream_lines {
        return Err(ExecError::Limit(format!(
            "sort: too many lines to buffer (max {})",
            ctx.limits.max_stream_lines
        )));
    }
    if reverse {
        lines.sort_unstable_by(|a, b| b.cmp(a));
    } else {
        lines.sort_unstable();
    }
    let mut stdout = Vec::new();
    for line in lines {
        stdout.extend_from_slice(line.as_bytes());
        stdout.push(b'\n');
    }
    Ok(RawOutput {
        code,
        stdout,
        stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::super::{execute, Ctx, ExecError, ExecOutcome, Limits};
    use crate::parse::parse_input;
    use crate::resolve::Resolver;
    use std::collections::HashMap;
    use std::fs;

    fn run_cmd(dir: &tempfile::TempDir, cmd: &str) -> Result<ExecOutcome, ExecError> {
        run_cmd_limits(dir, cmd, Limits::default())
    }

    fn run_cmd_limits(
        dir: &tempfile::TempDir,
        cmd: &str,
        limits: Limits,
    ) -> Result<ExecOutcome, ExecError> {
        let resolver = Resolver::new(dir.path()).unwrap();
        let ctx = Ctx {
            resolver,
            sensibles: vec![],
            secrets: vec![],
            limits,
            trusted: None,
            sandboxed: false,
            sandbox_shell: None,
        };
        let node = parse_input(cmd, &HashMap::new()).unwrap();
        execute(&node, &ctx)
    }

    #[test]
    fn sort_orders_lines_lexicographically() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "banana\napple\ncherry\n").unwrap();
        let out = run_cmd(&dir, "sort a.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "apple\nbanana\ncherry\n");
        let out = run_cmd(&dir, "sort -r a.txt").unwrap();
        assert_eq!(out.stdout, "cherry\nbanana\napple\n");
        let out = run_cmd(&dir, "sort --reverse a.txt").unwrap();
        assert_eq!(out.stdout, "cherry\nbanana\napple\n");
    }

    #[test]
    fn sort_terminates_last_line_and_handles_empty() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "b\na").unwrap();
        let out = run_cmd(&dir, "sort a.txt").unwrap();
        assert_eq!(out.stdout, "a\nb\n");
        fs::write(dir.path().join("empty.txt"), "").unwrap();
        let out = run_cmd(&dir, "sort empty.txt").unwrap();
        assert_eq!(out.stdout, "");
    }

    #[test]
    fn sort_works_on_pipe_and_redirect() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("in.txt"), "z\ny\nx\n").unwrap();
        let out = run_cmd(&dir, "cat in.txt | sort").unwrap();
        assert_eq!(out.stdout, "x\ny\nz\n");
        let out = run_cmd(&dir, "sort -r < in.txt").unwrap();
        assert_eq!(out.stdout, "z\ny\nx\n");
        let out = run_cmd(&dir, "cat in.txt | sort > out.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(
            fs::read_to_string(dir.path().join("out.txt")).unwrap(),
            "x\ny\nz\n"
        );
    }

    #[test]
    fn sort_unknown_options_are_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        for cmd in [
            "sort -n a.txt",
            "sort -k 1 a.txt",
            "sort -u a.txt",
            "sort --numeric-sort a.txt",
            "sort -q a.txt",
        ] {
            let err = run_cmd(&dir, cmd).unwrap_err();
            assert!(matches!(err, ExecError::Fail(_)), "cmd {cmd}: {err:?}");
        }
    }

    #[test]
    fn sort_buffer_is_bounded_by_max_stream_lines() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "1\n2\n3\n4\n5\n").unwrap();
        let limits = Limits {
            max_stream_lines: 4,
            ..Limits::default()
        };
        let err = run_cmd_limits(&dir, "sort a.txt", limits).unwrap_err();
        assert!(
            matches!(err, ExecError::Limit(ref m) if m.contains("too many lines")),
            "got {err:?}"
        );
        let out = run_cmd_limits(
            &dir,
            "sort a.txt",
            Limits {
                max_stream_lines: 5,
                ..Limits::default()
            },
        )
        .unwrap();
        assert_eq!(out.stdout, "1\n2\n3\n4\n5\n");
    }

    #[test]
    fn sort_denies_escape_and_invalid_utf8() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            run_cmd(&dir, "sort ../evil.txt").unwrap_err(),
            ExecError::Denied(_)
        ));
        fs::write(dir.path().join("bin.dat"), vec![0xff, b'\n']).unwrap();
        let err = run_cmd(&dir, "sort bin.dat").unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("UTF-8")));
    }

    #[test]
    fn sort_missing_file_is_code_1() {
        let dir = tempfile::tempdir().unwrap();
        let out = run_cmd(&dir, "sort nope.txt").unwrap();
        assert_eq!(out.code, 1);
        assert!(out.stderr.contains("nope.txt"));
    }
}
