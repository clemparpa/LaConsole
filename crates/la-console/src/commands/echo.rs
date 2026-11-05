use super::{Ctx, ExecError, RawOutput};
use crate::parse::SimpleCommand;

pub(crate) fn run(cmd: &SimpleCommand, _ctx: &Ctx) -> Result<RawOutput, ExecError> {
    let mut text = String::new();
    for (idx, arg) in cmd.argv[1..].iter().enumerate() {
        if idx > 0 {
            text.push(' ');
        }
        text.push_str(&arg.text);
    }
    text.push('\n');
    Ok(RawOutput {
        code: 0,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::super::{execute, Ctx, ExecError, ExecOutcome, Limits};
    use crate::parse::parse_input;
    use crate::resolve::Resolver;
    use std::collections::HashMap;
    use std::fs;

    fn make_ctx<'a>(
        resolver: &'a Resolver,
        sensibles: &'a [regex::Regex],
        secrets: &'a [String],
        max_write_bytes: usize,
    ) -> Ctx<'a> {
        Ctx {
            resolver,
            sensibles,
            secrets,
            limits: Limits {
                max_write_bytes,
                ..Limits::default()
            },
        }
    }

    fn run_cmd(dir: &tempfile::TempDir, cmd: &str) -> Result<ExecOutcome, ExecError> {
        let resolver = Resolver::new(dir.path()).unwrap();
        let ctx = make_ctx(&resolver, &[], &[], crate::sink::DEFAULT_MAX_WRITE_BYTES);
        let node = parse_input(cmd, &HashMap::new()).unwrap();
        execute(&node, &ctx)
    }

    #[test]
    fn echo_joins_args_with_spaces_and_newline() {
        let dir = tempfile::tempdir().unwrap();
        let out = run_cmd(&dir, "echo hello world").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "hello world\n");
        assert_eq!(out.stderr, "");
        assert!(!out.truncated);
    }

    #[test]
    fn echo_without_args_prints_newline() {
        let dir = tempfile::tempdir().unwrap();
        let out = run_cmd(&dir, "echo").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "\n");
    }

    #[test]
    fn echo_preserves_quoted_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let out = run_cmd(&dir, "echo \"a  b\" 'c\td'").unwrap();
        assert_eq!(out.stdout, "a  b c\td\n");
    }

    #[test]
    fn echo_does_not_expand_globs() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"").unwrap();
        let out = run_cmd(&dir, "echo *.txt").unwrap();
        assert_eq!(out.stdout, "*.txt\n");
    }

    #[test]
    fn echo_redirect_truncates_through_file_sink() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("out.txt"), "old-content").unwrap();
        let out = run_cmd(&dir, "echo fresh > out.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "");
        assert_eq!(
            fs::read_to_string(dir.path().join("out.txt")).unwrap(),
            "fresh\n"
        );
    }

    #[test]
    fn echo_redirect_append_adds_line() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("log.txt"), "one\n").unwrap();
        let out = run_cmd(&dir, "echo two >> log.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(
            fs::read_to_string(dir.path().join("log.txt")).unwrap(),
            "one\ntwo\n"
        );
    }

    #[test]
    fn echo_redirect_denies_escape_before_creating_file() {
        let dir = tempfile::tempdir().unwrap();
        let err = run_cmd(&dir, "echo x > ../evil.txt").unwrap_err();
        assert!(matches!(err, ExecError::Denied(_)));
        assert!(!dir.path().parent().unwrap().join("evil.txt").exists());
    }

    #[test]
    fn echo_redirect_denies_sensitive_target() {
        let dir = tempfile::tempdir().unwrap();
        let resolver = Resolver::new(dir.path()).unwrap();
        let sensibles = vec![regex::Regex::new(r".*\.env$").unwrap()];
        let ctx = make_ctx(
            &resolver,
            &sensibles,
            &[],
            crate::sink::DEFAULT_MAX_WRITE_BYTES,
        );
        let node = parse_input(r#"echo "KEY=1" > .env"#, &HashMap::new()).unwrap();
        let err = execute(&node, &ctx).unwrap_err();
        assert!(matches!(err, ExecError::Denied(_)));
        assert!(!dir.path().join(".env").exists());
    }

    #[test]
    fn echo_redirect_enforces_write_bound() {
        let dir = tempfile::tempdir().unwrap();
        let resolver = Resolver::new(dir.path()).unwrap();
        let ctx = make_ctx(&resolver, &[], &[], 3);
        let node = parse_input("echo too-long > out.txt", &HashMap::new()).unwrap();
        let err = execute(&node, &ctx).unwrap_err();
        assert!(matches!(err, ExecError::Denied(m) if m.contains("write bound")));
    }

    #[test]
    fn echo_redirect_masks_secrets_before_persisting() {
        let dir = tempfile::tempdir().unwrap();
        let resolver = Resolver::new(dir.path()).unwrap();
        let secrets = vec!["tok-abc123".to_string()];
        let ctx = make_ctx(
            &resolver,
            &[],
            &secrets,
            crate::sink::DEFAULT_MAX_WRITE_BYTES,
        );
        let node = parse_input(r#"echo "token=tok-abc123" > out.txt"#, &HashMap::new()).unwrap();
        let out = execute(&node, &ctx).unwrap();
        assert_eq!(out.code, 0);
        let content = fs::read_to_string(dir.path().join("out.txt")).unwrap();
        assert_eq!(content, "token=***\n");
    }

    #[test]
    fn echo_masks_secrets_in_caller_output() {
        let dir = tempfile::tempdir().unwrap();
        let resolver = Resolver::new(dir.path()).unwrap();
        let secrets = vec!["tok-abc123".to_string()];
        let ctx = make_ctx(
            &resolver,
            &[],
            &secrets,
            crate::sink::DEFAULT_MAX_WRITE_BYTES,
        );
        let node = parse_input("echo tok-abc123", &HashMap::new()).unwrap();
        let out = execute(&node, &ctx).unwrap();
        assert_eq!(out.stdout, "***\n");
    }

    #[test]
    fn echo_stderr_redirect_creates_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let out = run_cmd(&dir, "echo hi 2> err.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "hi\n");
        assert_eq!(fs::read_to_string(dir.path().join("err.txt")).unwrap(), "");
    }

    #[test]
    fn echo_err_to_out_merges_streams() {
        let dir = tempfile::tempdir().unwrap();
        let out = run_cmd(&dir, "echo hi 2>&1").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "hi\n");
        assert_eq!(out.stderr, "");
    }

    #[test]
    fn echo_all_redirect_writes_single_file() {
        let dir = tempfile::tempdir().unwrap();
        let out = run_cmd(&dir, "echo hi &> all.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "");
        assert_eq!(
            fs::read_to_string(dir.path().join("all.txt")).unwrap(),
            "hi\n"
        );
    }

    #[test]
    fn echo_in_pipe_feeds_next_command() {
        let dir = tempfile::tempdir().unwrap();
        let out = run_cmd(&dir, "echo first | echo second").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "second\n");
    }

    #[test]
    fn echo_in_seq_runs_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let out = run_cmd(&dir, "echo a && echo b").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "b\n");
    }

    #[test]
    fn trusted_is_still_denied() {
        let dir = tempfile::tempdir().unwrap();
        let err = run_cmd(&dir, "trusted build").unwrap_err();
        assert!(
            matches!(err, ExecError::Denied(m) if m.contains("unknown command") && m.contains("trusted"))
        );
    }
}
