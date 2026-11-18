use std::sync::Arc;

use super::stream::{lines_inclusive, read_sources, strip_nl, unsupported_opt, utf8};
use super::{Ctx, ExecError, RawOutput};
use crate::parse::{Arg, SimpleCommand};
use crate::sink::DiskQuota;

/// Parses `[-c]` / `--count`; `--` ends options. Any other option is a `fail`.
fn parse_opts<'a>(name: &str, args: &'a [Arg]) -> Result<(bool, Vec<&'a Arg>), ExecError> {
    let mut count = false;
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
            if opt == "count" && inline.is_none() {
                count = true;
            } else {
                return Err(unsupported_opt(name, text));
            }
        } else if !opts_done && text.starts_with('-') && text.len() > 1 {
            for c in text[1..].chars() {
                if c == 'c' {
                    count = true;
                } else {
                    return Err(unsupported_opt(name, &format!("-{c}")));
                }
            }
        } else {
            positional.push(&args[i]);
        }
        i += 1;
    }
    Ok((count, positional))
}

/// `uniq [-c] [path...]`: drops adjacent duplicate lines; `-c` prefixes each
/// kept line with its run count. Streaming: only the previous line is held,
/// so no line buffer at all.
pub(crate) fn run(
    cmd: &SimpleCommand,
    input: &[u8],
    ctx: &Ctx,
    _quota: &Arc<DiskQuota>,
) -> Result<RawOutput, ExecError> {
    let (with_count, paths) = parse_opts("uniq", &cmd.argv[1..])?;
    let (data, stderr, code) = read_sources("uniq", ctx, &paths, input)?;
    let text = utf8("uniq", data)?;
    let pieces = lines_inclusive(&text);
    let mut stdout = Vec::new();
    let mut idx = 0usize;
    while idx < pieces.len() {
        let content = strip_nl(pieces[idx]);
        let mut run = 1usize;
        let mut j = idx + 1;
        while j < pieces.len() && strip_nl(pieces[j]) == content {
            run += 1;
            j += 1;
        }
        if with_count {
            stdout.extend_from_slice(format!("{run} ").as_bytes());
        }
        stdout.extend_from_slice(pieces[idx].as_bytes());
        idx = j;
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
        let resolver = Resolver::new(dir.path()).unwrap();
        let ctx = Ctx {
            resolver,
            sensibles: vec![],
            secrets: vec![],
            limits: Limits::default(),
            trusted: None,
            sandboxed: false,
            sandbox_shell: None,
        };
        let node = parse_input(cmd, &HashMap::new()).unwrap();
        execute(&node, &ctx)
    }

    #[test]
    fn uniq_drops_adjacent_duplicates_only() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\nx\ny\nx\n").unwrap();
        let out = run_cmd(&dir, "uniq a.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "x\ny\nx\n");
    }

    #[test]
    fn uniq_c_prefixes_run_count() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\nx\nx\ny\n").unwrap();
        let out = run_cmd(&dir, "uniq -c a.txt").unwrap();
        assert_eq!(out.stdout, "3 x\n1 y\n");
        let out = run_cmd(&dir, "uniq --count a.txt").unwrap();
        assert_eq!(out.stdout, "3 x\n1 y\n");
    }

    #[test]
    fn uniq_on_pipe_and_redirect_and_empty() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("in.txt"), "a\na\nb\n").unwrap();
        let out = run_cmd(&dir, "cat in.txt | uniq").unwrap();
        assert_eq!(out.stdout, "a\nb\n");
        let out = run_cmd(&dir, "uniq < in.txt > out.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(
            fs::read_to_string(dir.path().join("out.txt")).unwrap(),
            "a\nb\n"
        );
        fs::write(dir.path().join("empty.txt"), "").unwrap();
        let out = run_cmd(&dir, "uniq empty.txt").unwrap();
        assert_eq!(out.stdout, "");
    }

    #[test]
    fn uniq_unknown_option_is_fail_and_escape_denied() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        for cmd in ["uniq -d a.txt", "uniq -s a.txt", "uniq --all a.txt"] {
            let err = run_cmd(&dir, cmd).unwrap_err();
            assert!(matches!(err, ExecError::Fail(_)), "cmd {cmd}: {err:?}");
        }
        assert!(matches!(
            run_cmd(&dir, "uniq ../evil.txt").unwrap_err(),
            ExecError::Denied(_)
        ));
    }

    #[test]
    fn uniq_invalid_utf8_is_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("bin.dat"), vec![0xff, b'\n']).unwrap();
        let err = run_cmd(&dir, "uniq bin.dat").unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("UTF-8")));
    }
}
