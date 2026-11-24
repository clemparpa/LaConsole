use std::sync::Arc;

use super::stream::{lines_inclusive, parse_lines_opt, read_sources, utf8};
use super::{Ctx, ExecError, RawOutput};
use crate::parse::SimpleCommand;
use crate::sink::DiskQuota;

/// `head [-n N] [path...]`: prints the first N lines of the input (default
/// 10). Streaming: stops after N lines, no buffer beyond the input itself.
pub(crate) fn run(
    cmd: &SimpleCommand,
    input: &[u8],
    ctx: &Ctx,
    _quota: &Arc<DiskQuota>,
) -> Result<RawOutput, ExecError> {
    let (n, paths) = parse_lines_opt("head", &cmd.argv[1..], &ctx.limits)?;
    let (data, stderr, code) = read_sources("head", ctx, &paths, input)?;
    let text = utf8("head", data)?;
    let mut stdout = Vec::new();
    for piece in lines_inclusive(&text).into_iter().take(n) {
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
        };
        let node = parse_input(cmd, &HashMap::new()).unwrap();
        execute(&node, &ctx)
    }

    #[test]
    fn head_defaults_to_ten_lines() {
        let dir = tempfile::tempdir().unwrap();
        let content: String = (1..=20).map(|i| format!("line{i}\n")).collect();
        fs::write(dir.path().join("a.txt"), content).unwrap();
        let out = run_cmd(&dir, "head a.txt").unwrap();
        assert_eq!(out.code, 0);
        let expected: String = (1..=10).map(|i| format!("line{i}\n")).collect();
        assert_eq!(out.stdout, expected);
    }

    #[test]
    fn head_n_flag_forms() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "1\n2\n3\n4\n").unwrap();
        for cmd in [
            "head -n 2 a.txt",
            "head -n2 a.txt",
            "head --lines 2 a.txt",
            "head --lines=2 a.txt",
        ] {
            let out = run_cmd(&dir, cmd).unwrap();
            assert_eq!(out.stdout, "1\n2\n", "cmd {cmd}");
        }
    }

    #[test]
    fn head_fewer_lines_than_n_and_zero() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "1\n2\n").unwrap();
        let out = run_cmd(&dir, "head -n 10 a.txt").unwrap();
        assert_eq!(out.stdout, "1\n2\n");
        let out = run_cmd(&dir, "head -n 0 a.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "");
    }

    #[test]
    fn head_reads_pipe_and_stdin_redirect() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("in.txt"), "a\nb\nc\n").unwrap();
        let out = run_cmd(&dir, "cat in.txt | head -n 1").unwrap();
        assert_eq!(out.stdout, "a\n");
        let out = run_cmd(&dir, "head -n 2 < in.txt").unwrap();
        assert_eq!(out.stdout, "a\nb\n");
    }

    #[test]
    fn head_preserves_missing_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "a\nb").unwrap();
        let out = run_cmd(&dir, "head -n 5 a.txt").unwrap();
        assert_eq!(out.stdout, "a\nb");
    }

    #[test]
    fn head_unknown_option_and_bad_number_are_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        for cmd in [
            "head -q a.txt",
            "head --nope a.txt",
            "head -n abc a.txt",
            "head -n",
            "head --lines",
        ] {
            let err = run_cmd(&dir, cmd).unwrap_err();
            assert!(matches!(err, ExecError::Fail(_)), "cmd {cmd}: {err:?}");
        }
    }

    #[test]
    fn head_n_over_bound_is_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        let err = run_cmd(&dir, "head -n 10001 a.txt").unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("too large")));
        let limits = || Limits {
            max_stream_lines: 5,
            ..Limits::default()
        };
        let err = run_cmd_limits(&dir, "head -n 6 a.txt", limits()).unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("too large")));
        let out = run_cmd_limits(&dir, "head -n 5 a.txt", limits()).unwrap();
        assert_eq!(out.stdout, "x\n");
    }

    #[test]
    fn head_denies_escape_sensitive_and_oversize() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            run_cmd(&dir, "head ../evil.txt").unwrap_err(),
            ExecError::Denied(_)
        ));
        assert!(matches!(
            run_cmd(&dir, "head /etc/passwd").unwrap_err(),
            ExecError::Denied(_)
        ));
        fs::write(dir.path().join(".env"), "A=1\n").unwrap();
        let resolver = Resolver::new(dir.path()).unwrap();
        let ctx = Ctx {
            resolver,
            sensibles: vec![regex::Regex::new(r".*\.env$").unwrap()],
            secrets: vec![],
            limits: Limits::default(),
            trusted: None,
        };
        let node = parse_input("head .env", &HashMap::new()).unwrap();
        assert!(matches!(
            execute(&node, &ctx).unwrap_err(),
            ExecError::Denied(_)
        ));
        fs::write(dir.path().join("big.txt"), vec![b'a'; 2048]).unwrap();
        let limits = Limits {
            max_read_bytes: 1024,
            ..Limits::default()
        };
        let err = run_cmd_limits(&dir, "head big.txt", limits).unwrap_err();
        assert!(matches!(err, ExecError::Limit(_)));
    }

    #[test]
    fn head_missing_file_is_code_1_and_invalid_utf8_is_fail() {
        let dir = tempfile::tempdir().unwrap();
        let out = run_cmd(&dir, "head nope.txt").unwrap();
        assert_eq!(out.code, 1);
        assert!(out.stderr.contains("nope.txt"));
        fs::write(dir.path().join("bin.dat"), vec![0xff, 0xfe, b'\n']).unwrap();
        let err = run_cmd(&dir, "head bin.dat").unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("UTF-8")));
    }

    #[test]
    fn head_redirect_and_glob_work() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "1\n2\n3\n").unwrap();
        fs::write(dir.path().join("b.txt"), "4\n5\n").unwrap();
        fs::write(dir.path().join("c.rs"), "6\n").unwrap();
        // Multiple paths are concatenated (like `cat`) before filtering.
        let out = run_cmd(&dir, "head -n 1 *.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "1\n");
        let out = run_cmd(&dir, "head -n 2 a.txt > out.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "");
        assert_eq!(
            fs::read_to_string(dir.path().join("out.txt")).unwrap(),
            "1\n2\n"
        );
    }
}
