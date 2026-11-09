use super::{collect_paths, read_bounded, write_file, Ctx, ExecError, RawOutput};
use crate::parse::SimpleCommand;

pub(crate) fn run(
    cmd: &SimpleCommand,
    _input: &[u8],
    ctx: &Ctx,
    quota: &std::sync::Arc<crate::sink::DiskQuota>,
) -> Result<RawOutput, ExecError> {
    let args: Vec<&str> = cmd.argv[1..].iter().map(|a| a.text.as_str()).collect();
    if args.len() < 3 {
        return Err(ExecError::Fail(
            "sub: usage: sub <pattern> <replacement> <path...>".to_string(),
        ));
    }
    let pattern = regex::Regex::new(args[0])
        .map_err(|err| ExecError::Fail(format!("sub: invalid pattern: {err}")))?;
    let repl = args[1];

    let targets = collect_paths(ctx, &cmd.argv[3..])?;

    let mut stderr = Vec::new();
    let mut code = 0u16;
    for rel in &targets {
        match substitute_one(ctx, &pattern, repl, rel, quota) {
            Ok(()) => {}
            Err(ExecError::Denied(msg)) => return Err(ExecError::Denied(msg)),
            Err(ExecError::Limit(msg)) => return Err(ExecError::Limit(msg)),
            Err(ExecError::Fail(msg)) => {
                code = 1;
                stderr.extend_from_slice(format!("sub: {msg}\n").as_bytes());
            }
        }
    }
    Ok(RawOutput {
        code,
        stdout: Vec::new(),
        stderr,
    })
}

fn substitute_one(
    ctx: &Ctx,
    pattern: &regex::Regex,
    repl: &str,
    rel: &str,
    quota: &std::sync::Arc<crate::sink::DiskQuota>,
) -> Result<(), ExecError> {
    let bytes = read_bounded(ctx, rel)?;
    let content =
        String::from_utf8(bytes).map_err(|_| ExecError::Fail(format!("{rel}: not valid UTF-8")))?;
    let replaced = pattern.replace_all(&content, repl).into_owned();
    write_file(ctx, rel, replaced.as_bytes(), false, quota.clone())
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
    fn sub_replaces_all_occurrences() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "foo bar foo\n").unwrap();
        let out = run_cmd(&dir, "sub foo baz a.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(
            fs::read_to_string(dir.path().join("a.txt")).unwrap(),
            "baz bar baz\n"
        );
    }

    #[test]
    fn sub_supports_regex_pattern_quoted() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "hello world\n").unwrap();
        let out = run_cmd(&dir, r#"sub "h.llo" "bye" a.txt"#).unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(
            fs::read_to_string(dir.path().join("a.txt")).unwrap(),
            "bye world\n"
        );
    }

    #[test]
    fn sub_supports_glob_targets() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        fs::write(dir.path().join("b.txt"), "x\n").unwrap();
        fs::write(dir.path().join("c.rs"), "x\n").unwrap();
        let out = run_cmd(&dir, "sub x y *.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(fs::read_to_string(dir.path().join("a.txt")).unwrap(), "y\n");
        assert_eq!(fs::read_to_string(dir.path().join("b.txt")).unwrap(), "y\n");
        assert_eq!(fs::read_to_string(dir.path().join("c.rs")).unwrap(), "x\n");
    }

    #[test]
    fn sub_denies_escape_and_sensitive() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            run_cmd(&dir, "sub a b ../evil.txt").unwrap_err(),
            ExecError::Denied(_)
        ));
        fs::write(dir.path().join(".env"), "A=1\n").unwrap();
        let resolver = Resolver::new(dir.path()).unwrap();
        let sensibles = vec![regex::Regex::new(r".*\.env$").unwrap()];
        let ctx = Ctx {
            resolver,
            sensibles,
            secrets: vec![],
            limits: Limits::default(),
            trusted: None,
            sandboxed: false,
            sandbox_shell: None,
        };
        let node = parse_input("sub A B .env", &HashMap::new()).unwrap();
        assert!(matches!(
            execute(&node, &ctx).unwrap_err(),
            ExecError::Denied(_)
        ));
        assert_eq!(
            fs::read_to_string(dir.path().join(".env")).unwrap(),
            "A=1\n"
        );
    }

    #[test]
    fn sub_denies_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("big.txt"), vec![b'a'; 2048]).unwrap();
        let resolver = Resolver::new(dir.path()).unwrap();
        let ctx = Ctx {
            resolver,
            sensibles: vec![],
            secrets: vec![],
            limits: Limits {
                max_read_bytes: 1024,
                ..Limits::default()
            },
            trusted: None,
            sandboxed: false,
            sandbox_shell: None,
        };
        let node = parse_input("sub a b big.txt", &HashMap::new()).unwrap();
        assert!(matches!(
            execute(&node, &ctx).unwrap_err(),
            ExecError::Limit(_)
        ));
    }

    #[test]
    fn sub_invalid_pattern_is_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        let err = run_cmd(&dir, "sub '[' y a.txt").unwrap_err();
        assert!(matches!(err, ExecError::Fail(m) if m.contains("invalid pattern")));
    }

    #[test]
    fn sub_usage_error_without_three_args() {
        let dir = tempfile::tempdir().unwrap();
        let err = run_cmd(&dir, "sub foo").unwrap_err();
        assert!(matches!(err, ExecError::Fail(m) if m.contains("usage")));
    }

    #[test]
    fn sub_missing_file_is_code_1_and_does_not_create() {
        let dir = tempfile::tempdir().unwrap();
        let out = run_cmd(&dir, "sub a b nope.txt").unwrap();
        assert_eq!(out.code, 1);
        assert!(out.stderr.contains("nope.txt"));
        assert!(!dir.path().join("nope.txt").exists());
    }

    #[test]
    fn sub_masks_secrets_in_rewritten_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "key tok-abc123 end\n").unwrap();
        let resolver = Resolver::new(dir.path()).unwrap();
        let secrets = vec!["tok-abc123".to_string()];
        let ctx = Ctx {
            resolver,
            sensibles: vec![],
            secrets,
            limits: Limits::default(),
            trusted: None,
            sandboxed: false,
            sandbox_shell: None,
        };
        let node = parse_input("sub key value a.txt", &HashMap::new()).unwrap();
        let out = execute(&node, &ctx).unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(
            fs::read_to_string(dir.path().join("a.txt")).unwrap(),
            "value *** end\n"
        );
    }
}
