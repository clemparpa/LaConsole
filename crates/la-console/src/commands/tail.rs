use std::collections::VecDeque;
use std::sync::Arc;

use super::stream::{lines_inclusive, parse_lines_opt, read_sources, utf8};
use super::{Ctx, ExecError, RawOutput};
use crate::parse::SimpleCommand;
use crate::sink::DiskQuota;

/// `tail [-n N] [path...]`: prints the last N lines of the input (default 10)
/// through a ring buffer of N lines, so memory stays bounded by N.
pub(crate) fn run(
    cmd: &SimpleCommand,
    input: &[u8],
    ctx: &Ctx,
    _quota: &Arc<DiskQuota>,
) -> Result<RawOutput, ExecError> {
    let (n, paths) = parse_lines_opt("tail", &cmd.argv[1..], &ctx.limits)?;
    let (data, stderr, code) = read_sources("tail", ctx, &paths, input)?;
    let text = utf8("tail", data)?;
    let mut ring: VecDeque<&str> = VecDeque::with_capacity(n);
    for piece in lines_inclusive(&text) {
        ring.push_back(piece);
        while ring.len() > n {
            ring.pop_front();
        }
    }
    let mut stdout = Vec::new();
    for piece in &ring {
        stdout.extend_from_slice(piece.as_bytes());
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
        };
        let node = parse_input(cmd, &HashMap::new()).unwrap();
        execute(&node, &ctx)
    }

    #[test]
    fn tail_defaults_to_ten_lines() {
        let dir = tempfile::tempdir().unwrap();
        let content: String = (1..=20).map(|i| format!("line{i}\n")).collect();
        fs::write(dir.path().join("a.txt"), content).unwrap();
        let out = run_cmd(&dir, "tail a.txt").unwrap();
        let expected: String = (11..=20).map(|i| format!("line{i}\n")).collect();
        assert_eq!(out.stdout, expected);
    }

    #[test]
    fn tail_n_flag_forms() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "1\n2\n3\n4\n").unwrap();
        for cmd in [
            "tail -n 2 a.txt",
            "tail -n2 a.txt",
            "tail --lines 2 a.txt",
            "tail --lines=2 a.txt",
        ] {
            let out = run_cmd(&dir, cmd).unwrap();
            assert_eq!(out.stdout, "3\n4\n", "cmd {cmd}");
        }
    }

    #[test]
    fn tail_fewer_lines_than_n_zero_and_pipe() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("in.txt"), "a\nb\n").unwrap();
        let out = run_cmd(&dir, "tail -n 10 in.txt").unwrap();
        assert_eq!(out.stdout, "a\nb\n");
        let out = run_cmd(&dir, "tail -n 0 in.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "");
        let out = run_cmd(&dir, "cat in.txt | tail -n 1").unwrap();
        assert_eq!(out.stdout, "b\n");
        let out = run_cmd(&dir, "tail -n 1 < in.txt").unwrap();
        assert_eq!(out.stdout, "b\n");
    }

    #[test]
    fn tail_preserves_missing_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "a\nb").unwrap();
        let out = run_cmd(&dir, "tail -n 1 a.txt").unwrap();
        assert_eq!(out.stdout, "b");
    }

    #[test]
    fn tail_unknown_option_and_bad_number_are_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        for cmd in [
            "tail -q a.txt",
            "tail --nope a.txt",
            "tail -n x a.txt",
            "tail -n",
        ] {
            let err = run_cmd(&dir, cmd).unwrap_err();
            assert!(matches!(err, ExecError::Fail(_)), "cmd {cmd}: {err:?}");
        }
    }

    #[test]
    fn tail_n_over_bound_is_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        let err = run_cmd(&dir, "tail -n 10001 a.txt").unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("too large")));
    }

    #[test]
    fn tail_denies_escape_and_invalid_utf8() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            run_cmd(&dir, "tail ../evil.txt").unwrap_err(),
            ExecError::Denied(_)
        ));
        fs::write(dir.path().join("bin.dat"), vec![0xff, b'\n']).unwrap();
        let err = run_cmd(&dir, "tail bin.dat").unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("UTF-8")));
    }
}
