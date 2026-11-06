use std::fs;

use super::{check_read_path, collect_paths, Ctx, ExecError, RawOutput};
use crate::parse::{Arg, SimpleCommand};

pub(crate) fn run(
    cmd: &SimpleCommand,
    ctx: &Ctx,
    _quota: &std::sync::Arc<crate::sink::DiskQuota>,
) -> Result<RawOutput, ExecError> {
    let mut all = false;
    let mut positional: Vec<&Arg> = Vec::new();
    for arg in &cmd.argv[1..] {
        if !arg.glob && (arg.text == "--all" || arg.text == "-a") {
            all = true;
        } else if !arg.glob && arg.text.starts_with('-') && arg.text.len() > 1 {
            return Err(ExecError::Fail(format!(
                "ls: unrecognized option '{}'",
                arg.text
            )));
        } else {
            positional.push(arg);
        }
    }
    let mut paths = collect_paths(ctx, positional.iter().copied())?;
    if paths.is_empty() {
        paths.push(".".to_string());
    }

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut code = 0u16;
    for path in &paths {
        match list_one(ctx, path, all, &mut stdout) {
            Ok(()) => {}
            Err(ExecError::Denied(msg)) => return Err(ExecError::Denied(msg)),
            Err(ExecError::Fail(msg)) => {
                code = 1;
                stderr.extend_from_slice(format!("ls: {msg}\n").as_bytes());
            }
        }
    }
    Ok(RawOutput {
        code,
        stdout,
        stderr,
    })
}

fn list_one(ctx: &Ctx, rel: &str, all: bool, out: &mut Vec<u8>) -> Result<(), ExecError> {
    let target = check_read_path(ctx, rel)?;
    let meta = fs::metadata(&target).map_err(|err| ExecError::Fail(format!("{rel}: {err}")))?;
    if !meta.is_dir() {
        out.extend_from_slice(format!("{rel}\n").as_bytes());
        return Ok(());
    }
    let mut walker = ignore::WalkBuilder::new(&target);
    walker
        .max_depth(Some(1))
        .follow_links(false)
        .parents(false)
        .require_git(false)
        .hidden(!all)
        .ignore(!all)
        .git_ignore(!all)
        .git_global(!all)
        .git_exclude(!all);
    let mut names: Vec<String> = Vec::new();
    for entry in walker.build() {
        let entry = entry.map_err(|err| ExecError::Fail(format!("{rel}: {err}")))?;
        if entry.depth() == 0 {
            continue;
        }
        let Some(name) = entry.file_name().to_str() else {
            continue;
        };
        let entry_rel = entry
            .path()
            .strip_prefix(ctx.resolver.root())
            .ok()
            .and_then(|p| p.to_str())
            .map(str::to_string);
        if let Some(entry_rel) = entry_rel {
            if ctx.resolver.resolve(&entry_rel).is_err() {
                continue;
            }
        }
        names.push(name.to_string());
        if names.len() > ctx.limits.max_ls_entries {
            return Err(ExecError::Denied(format!(
                "ls: too many entries (max {})",
                ctx.limits.max_ls_entries
            )));
        }
    }
    names.sort();
    for name in names {
        out.extend_from_slice(format!("{name}\n").as_bytes());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::{execute, Limits};
    use crate::parse::parse_input;
    use crate::resolve::Resolver;
    use std::collections::HashMap;

    fn run_cmd(dir: &tempfile::TempDir, cmd: &str) -> Result<super::super::ExecOutcome, ExecError> {
        let resolver = Resolver::new(dir.path()).unwrap();
        let ctx = Ctx {
            resolver,
            sensibles: vec![],
            secrets: vec![],
            limits: Limits::default(),
        };
        let node = parse_input(cmd, &HashMap::new()).unwrap();
        execute(&node, &ctx)
    }

    #[test]
    fn lists_root_entries_sorted() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("b.txt"), b"").unwrap();
        fs::write(dir.path().join("a.txt"), b"").unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        let out = run_cmd(&dir, "ls").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "a.txt\nb.txt\nsub\n");
    }

    #[test]
    fn lists_subdirectory() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/x.rs"), b"").unwrap();
        let out = run_cmd(&dir, "ls src").unwrap();
        assert_eq!(out.stdout, "x.rs\n");
    }

    #[test]
    fn file_argument_prints_its_path() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"").unwrap();
        let out = run_cmd(&dir, "ls a.txt").unwrap();
        assert_eq!(out.stdout, "a.txt\n");
    }

    #[test]
    fn hidden_entries_only_with_all() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("visible.txt"), b"").unwrap();
        fs::write(dir.path().join(".hidden"), b"").unwrap();
        let out = run_cmd(&dir, "ls").unwrap();
        assert_eq!(out.stdout, "visible.txt\n");
        let out = run_cmd(&dir, "ls --all").unwrap();
        assert_eq!(out.stdout, ".hidden\nvisible.txt\n");
    }

    #[test]
    fn respects_gitignore_unless_all() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("keep.txt"), b"").unwrap();
        fs::write(dir.path().join("target.log"), b"").unwrap();
        fs::write(dir.path().join(".gitignore"), "target.log\n").unwrap();
        let out = run_cmd(&dir, "ls").unwrap();
        assert_eq!(out.stdout, "keep.txt\n");
        let out = run_cmd(&dir, "ls --all").unwrap();
        assert!(out.stdout.contains("target.log"));
        assert!(out.stdout.contains("keep.txt"));
    }

    #[test]
    fn denies_parent_dir_escape() {
        let dir = tempfile::tempdir().unwrap();
        let err = run_cmd(&dir, "ls ..").unwrap_err();
        assert!(matches!(err, ExecError::Denied(_)));
    }

    #[test]
    fn denies_sensitive_target() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".env"), b"X=1").unwrap();
        let resolver = Resolver::new(dir.path()).unwrap();
        let sensibles = vec![regex::Regex::new(r".*\.env$").unwrap()];
        let ctx = Ctx {
            resolver,
            sensibles,
            secrets: vec![],
            limits: Limits::default(),
        };
        let node = parse_input("ls .env", &HashMap::new()).unwrap();
        let err = execute(&node, &ctx).unwrap_err();
        assert!(matches!(err, ExecError::Denied(_)));
    }

    #[test]
    fn missing_path_is_code_1() {
        let dir = tempfile::tempdir().unwrap();
        let out = run_cmd(&dir, "ls nope").unwrap();
        assert_eq!(out.code, 1);
        assert!(out.stderr.contains("nope"));
    }

    #[test]
    fn unknown_option_is_fail() {
        let dir = tempfile::tempdir().unwrap();
        let err = run_cmd(&dir, "ls --bogus").unwrap_err();
        assert!(matches!(err, ExecError::Fail(m) if m.contains("--bogus")));
    }

    #[test]
    fn supports_glob_arguments() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/a.rs"), b"").unwrap();
        fs::write(dir.path().join("src/b.rs"), b"").unwrap();
        fs::write(dir.path().join("top.txt"), b"").unwrap();
        let out = run_cmd(&dir, "ls src/*.rs").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "src/a.rs\nsrc/b.rs\n");
    }
}
