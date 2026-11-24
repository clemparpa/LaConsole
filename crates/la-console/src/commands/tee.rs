use std::sync::Arc;

use super::stream::unsupported_opt;
use super::{write_file, Ctx, ExecError, RawOutput};
use crate::parse::SimpleCommand;
use crate::sink::DiskQuota;

const USAGE: &str =
    "tee: usage: <cmd> | tee <path> (stream position only, after '|'; exactly one target path, no options in v1)";

/// `tee <path>`: copies the pipe/`<` input to a file **and** passes it through
/// unchanged to the rest of the pipe. The target goes through `FileSink`
/// (resolve + sensibles + `max_write_bytes` + shared `DiskQuota` + secret
/// masking), created and validated **before** any byte is written, exactly
/// like a `>`/`>>` redirection target. Position rule enforced at parse
/// (`TeeNeedsPipe`): `tee` is only accepted after `|` in a pipe, because the
/// protocol has no terminal stdin at position 0. Any option (`-a`, …) and any
/// glob in the target path are a `fail`.
pub(crate) fn run(
    cmd: &SimpleCommand,
    input: &[u8],
    ctx: &Ctx,
    quota: &Arc<DiskQuota>,
) -> Result<RawOutput, ExecError> {
    let args = &cmd.argv[1..];
    if let Some(first) = args.first() {
        if first.text.starts_with('-') {
            return Err(unsupported_opt("tee", &first.text));
        }
    }
    if args.len() != 1 {
        return Err(ExecError::Fail(USAGE.to_string()));
    }
    let target = &args[0];
    if target.glob {
        return Err(ExecError::Fail(
            "tee: glob patterns are not allowed in the target path".to_string(),
        ));
    }
    write_file(ctx, &target.text, input, false, quota.clone())?;
    Ok(RawOutput {
        code: 0,
        stdout: input.to_vec(),
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

    fn ctx_with(dir: &tempfile::TempDir, limits: Limits) -> Ctx {
        Ctx {
            resolver: Resolver::new(dir.path()).unwrap(),
            sensibles: vec![],
            secrets: vec![],
            limits,
            trusted: None,
        }
    }

    fn run_cmd(dir: &tempfile::TempDir, cmd: &str) -> Result<ExecOutcome, ExecError> {
        run_cmd_limits(dir, cmd, Limits::default())
    }

    fn run_cmd_limits(
        dir: &tempfile::TempDir,
        cmd: &str,
        limits: Limits,
    ) -> Result<ExecOutcome, ExecError> {
        let node = parse_input(cmd, &HashMap::new()).unwrap();
        execute(&node, &ctx_with(dir, limits))
    }

    #[test]
    fn tee_copies_stream_to_file_and_passes_through() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "one\ntwo\n").unwrap();
        let out = run_cmd(&dir, "cat a.txt | tee b.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "one\ntwo\n");
        assert_eq!(
            fs::read_to_string(dir.path().join("b.txt")).unwrap(),
            "one\ntwo\n"
        );
    }

    #[test]
    fn tee_chains_with_downstream_filters() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("app.log"), "INFO x\nERROR boom\nINFO y\n").unwrap();
        let out = run_cmd(&dir, "cat app.log | tee copy.txt | grep ERROR | tail -n 1").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "(stdin):2:ERROR boom\n");
        assert_eq!(
            fs::read_to_string(dir.path().join("copy.txt")).unwrap(),
            "INFO x\nERROR boom\nINFO y\n"
        );
    }

    #[test]
    fn tee_as_last_pipe_element_with_redirect_writes_both_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "data\n").unwrap();
        let out = run_cmd(&dir, "cat a.txt | tee b.txt > c.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "");
        assert_eq!(
            fs::read_to_string(dir.path().join("b.txt")).unwrap(),
            "data\n"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("c.txt")).unwrap(),
            "data\n"
        );
    }

    #[test]
    fn tee_stdin_redirect_overrides_pipe_input() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "from-pipe\n").unwrap();
        fs::write(dir.path().join("in.txt"), "from-file\n").unwrap();
        let out = run_cmd(&dir, "cat a.txt | tee b.txt < in.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "from-file\n");
        assert_eq!(
            fs::read_to_string(dir.path().join("b.txt")).unwrap(),
            "from-file\n"
        );
    }

    #[test]
    fn tee_overwrites_existing_target() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "new\n").unwrap();
        fs::write(dir.path().join("b.txt"), "old-content").unwrap();
        let out = run_cmd(&dir, "cat a.txt | tee b.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(
            fs::read_to_string(dir.path().join("b.txt")).unwrap(),
            "new\n"
        );
    }

    #[test]
    fn tee_denies_escape_and_absolute_outside_root_without_creating() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        assert!(matches!(
            run_cmd(&dir, "cat a.txt | tee ../evil.txt").unwrap_err(),
            ExecError::Denied(_)
        ));
        assert!(!dir.path().parent().unwrap().join("evil.txt").exists());
        assert!(matches!(
            run_cmd(&dir, "cat a.txt | tee /etc/passwd").unwrap_err(),
            ExecError::Denied(_)
        ));
    }

    #[test]
    fn tee_denies_sensitive_target_before_opening() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "A=1\n").unwrap();
        fs::write(dir.path().join(".env"), "ORIGINAL=1\n").unwrap();
        let resolver = Resolver::new(dir.path()).unwrap();
        let ctx = Ctx {
            resolver,
            sensibles: vec![regex::Regex::new(r".*\.env$").unwrap()],
            secrets: vec![],
            limits: Limits::default(),
            trusted: None,
        };
        let node = parse_input("cat a.txt | tee .env", &HashMap::new()).unwrap();
        assert!(matches!(execute(&node, &ctx), Err(ExecError::Denied(_))));
        assert_eq!(
            fs::read_to_string(dir.path().join(".env")).unwrap(),
            "ORIGINAL=1\n"
        );
    }

    #[test]
    fn tee_masks_secrets_in_the_written_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "token=tok-abc123\n").unwrap();
        let resolver = Resolver::new(dir.path()).unwrap();
        let ctx = Ctx {
            resolver,
            sensibles: vec![],
            secrets: vec!["tok-abc123".to_string()],
            limits: Limits::default(),
            trusted: None,
        };
        let node = parse_input("cat a.txt | tee out.txt", &HashMap::new()).unwrap();
        let out = execute(&node, &ctx).unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "token=***\n");
        let content = fs::read_to_string(dir.path().join("out.txt")).unwrap();
        assert_eq!(content, "token=***\n");
        assert!(!content.contains("tok-abc123"));
    }

    #[test]
    fn tee_shares_disk_quota_with_the_redirect_of_the_same_command() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "hello\n").unwrap();
        let limits = Limits {
            max_command_write_bytes: 10,
            ..Limits::default()
        };
        let err = run_cmd_limits(&dir, "cat a.txt | tee b.txt > c.txt", limits).unwrap_err();
        assert!(
            matches!(err, ExecError::Limit(ref m) if m.contains("disk quota")),
            "got {err:?}"
        );
    }

    #[test]
    fn tee_enforces_write_bound() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("big.txt"), vec![b'x'; 2048]).unwrap();
        let limits = Limits {
            max_write_bytes: 1024,
            ..Limits::default()
        };
        let err = run_cmd_limits(&dir, "cat big.txt | tee out.txt", limits).unwrap_err();
        assert!(matches!(err, ExecError::Limit(_)));
    }

    #[test]
    fn tee_unknown_option_is_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        for cmd in [
            "cat a.txt | tee -a out.txt",
            "cat a.txt | tee --append out.txt",
            "cat a.txt | tee - out.txt",
        ] {
            let err = run_cmd(&dir, cmd).unwrap_err();
            assert!(
                matches!(err, ExecError::Fail(ref m) if m.contains("unsupported option")),
                "cmd {cmd}: {err:?}"
            );
        }
    }

    #[test]
    fn tee_glob_target_is_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        let err = run_cmd(&dir, "cat a.txt | tee *.txt").unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("glob")));
        assert!(!dir.path().join("*.txt").exists());
    }

    #[test]
    fn tee_wrong_arg_count_is_usage_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        for cmd in ["cat a.txt | tee", "cat a.txt | tee a.txt b.txt"] {
            let err = run_cmd(&dir, cmd).unwrap_err();
            assert!(
                matches!(err, ExecError::Fail(ref m) if m.contains("usage")),
                "cmd {cmd}: {err:?}"
            );
        }
    }

    #[test]
    fn tee_outside_stream_position_is_rejected_at_parse() {
        for cmd in ["tee out.txt", "tee out.txt | grep x", "ls && tee out.txt"] {
            assert!(
                matches!(
                    parse_input(cmd, &HashMap::new()),
                    Err(crate::parse::ParseError::TeeNeedsPipe)
                ),
                "{cmd}"
            );
        }
    }
}
