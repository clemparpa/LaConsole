use std::fs;
use std::io::Read;

use crate::parse::{self, SimpleCommand};
use crate::sink::sensitive_match;

use super::{ExecContext, ExecError, SimpleOutput};

pub fn run(
    cmd: &SimpleCommand,
    ctx: &ExecContext,
    input: &[u8],
) -> Result<SimpleOutput, ExecError> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut code = 0u16;
    let args = &cmd.argv[1..];
    if args.is_empty() {
        stdout.extend_from_slice(input);
        return Ok(SimpleOutput {
            code,
            stdout,
            stderr,
        });
    }
    for arg in args {
        let paths = if arg.glob {
            parse::expand_globs(ctx.resolver.root(), &arg.text, ctx.limits.max_glob_matches)
                .map_err(|e| ExecError::Denied(e.to_string()))?
        } else {
            vec![arg.text.clone()]
        };
        for rel in paths {
            match read_one(ctx, &rel, &mut stdout) {
                Ok(()) => {}
                Err(ExecError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
                    stderr.extend_from_slice(
                        format!("cat: {rel}: No such file or directory\n").as_bytes(),
                    );
                    code = 1;
                }
                Err(err) => return Err(err),
            }
        }
    }
    Ok(SimpleOutput {
        code,
        stdout,
        stderr,
    })
}

fn read_one(ctx: &ExecContext, rel: &str, out: &mut Vec<u8>) -> Result<(), ExecError> {
    let target = ctx
        .resolver
        .resolve(rel)
        .map_err(|e| ExecError::Denied(e.to_string()))?;
    if let Some(hit) = sensitive_match(&ctx.sensibles, ctx.resolver.root(), &target) {
        return Err(ExecError::Sensitive(hit));
    }
    let meta = fs::metadata(&target)?;
    if !meta.is_file() {
        return Err(ExecError::Denied(format!("not a file: {rel}")));
    }
    if meta.len() > ctx.limits.max_read_bytes as u64 {
        return Err(ExecError::TooLarge(
            meta.len() as usize,
            ctx.limits.max_read_bytes,
        ));
    }
    let file = fs::File::open(&target)?;
    let mut buf = Vec::new();
    file.take(ctx.limits.max_read_bytes as u64 + 1)
        .read_to_end(&mut buf)?;
    if buf.len() > ctx.limits.max_read_bytes {
        return Err(ExecError::TooLarge(buf.len(), ctx.limits.max_read_bytes));
    }
    out.extend_from_slice(&buf);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;
    use std::collections::HashMap;
    use std::fs;

    fn ctx(dir: &tempfile::TempDir) -> ExecContext {
        ExecContext::new(dir.path(), 1024, vec![], vec![]).unwrap()
    }

    fn cmd(input: &str) -> SimpleCommand {
        let node = parse::parse_input(input, &HashMap::new()).unwrap();
        let parse::Node::Simple(cmd) = node else {
            panic!("expected Simple");
        };
        cmd
    }

    #[test]
    fn reads_file_within_root() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"hello").unwrap();
        let out = run(&cmd("cat a.txt"), &ctx(&dir), &[]).unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, b"hello");
        assert!(out.stderr.is_empty());
    }

    #[test]
    fn concatenates_multiple_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"A").unwrap();
        fs::write(dir.path().join("b.txt"), b"B").unwrap();
        let out = run(&cmd("cat a.txt b.txt"), &ctx(&dir), &[]).unwrap();
        assert_eq!(out.stdout, b"AB");
    }

    #[test]
    fn no_args_echoes_pipe_input() {
        let dir = tempfile::tempdir().unwrap();
        let out = run(&cmd("cat"), &ctx(&dir), b"piped").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, b"piped");
    }

    #[test]
    fn denies_parent_dir_escape() {
        let dir = tempfile::tempdir().unwrap();
        let err = run(&cmd("cat ../secret.txt"), &ctx(&dir), &[]).unwrap_err();
        assert!(matches!(err, ExecError::Denied(_)));
    }

    #[test]
    fn denies_absolute_path_outside_root() {
        let dir = tempfile::tempdir().unwrap();
        let err = run(&cmd("cat /etc/passwd"), &ctx(&dir), &[]).unwrap_err();
        assert!(matches!(err, ExecError::Denied(_)));
    }

    #[test]
    fn denies_symlink_escape() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), b"s").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret.txt"),
            dir.path().join("link.txt"),
        )
        .unwrap();
        let err = run(&cmd("cat link.txt"), &ctx(&dir), &[]).unwrap_err();
        assert!(matches!(err, ExecError::Denied(_)));
    }

    #[test]
    fn denies_sensitive_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".env"), b"KEY=1").unwrap();
        let sensibles = vec![regex::Regex::new(r".*\.env$").unwrap()];
        let ctx = ExecContext::new(dir.path(), 1024, sensibles, vec![]).unwrap();
        let err = run(&cmd("cat .env"), &ctx, &[]).unwrap_err();
        assert!(matches!(err, ExecError::Sensitive(_)));
    }

    #[test]
    fn denies_file_over_read_bound() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("big.bin"), vec![0u8; 2048]).unwrap();
        let mut ctx = ctx(&dir);
        ctx.limits.max_read_bytes = 1024;
        let err = run(&cmd("cat big.bin"), &ctx, &[]).unwrap_err();
        assert!(matches!(err, ExecError::TooLarge(2048, 1024)));
    }

    #[test]
    fn missing_file_is_code_1_not_denied() {
        let dir = tempfile::tempdir().unwrap();
        let out = run(&cmd("cat nope.txt"), &ctx(&dir), &[]).unwrap();
        assert_eq!(out.code, 1);
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains("nope.txt"));
    }

    #[test]
    fn expands_globs_with_each_match_resolved() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"A").unwrap();
        fs::write(dir.path().join("b.txt"), b"B").unwrap();
        fs::write(dir.path().join("c.rs"), b"C").unwrap();
        let out = run(&cmd("cat *.txt"), &ctx(&dir), &[]).unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, b"AB");
    }

    #[test]
    fn glob_escape_match_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("evil.txt"), b"E").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("sub")).unwrap();
        let err = run(&cmd("cat sub/*.txt"), &ctx(&dir), &[]).unwrap_err();
        assert!(matches!(err, ExecError::Denied(_)));
    }
}
