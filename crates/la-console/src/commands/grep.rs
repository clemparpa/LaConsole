use std::fs;

use super::{check_read_bound, collect_paths, resolve_read_target, Ctx, ExecError, RawOutput};
use crate::parse::{Arg, SimpleCommand};

pub const DEFAULT_MAX_GREP_MATCHES: usize = 10_000;

pub(crate) fn run(
    cmd: &SimpleCommand,
    input: &[u8],
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
                "grep: unrecognized option '{}'",
                arg.text
            )));
        } else {
            positional.push(arg);
        }
    }
    if positional.is_empty() {
        return Err(ExecError::Fail(
            "grep: missing pattern (stdin is not available)".to_string(),
        ));
    }
    let pattern = positional[0].text.clone();
    let matcher = grep::regex::RegexMatcher::new(&pattern)
        .map_err(|err| ExecError::Fail(format!("grep: invalid pattern: {err}")))?;

    let targets = collect_paths(ctx, positional[1..].iter().copied())?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut code = 0u16;
    let mut match_count = 0usize;
    if targets.is_empty() {
        let found = search_slice(
            &matcher,
            "(stdin)",
            input,
            &mut stdout,
            &mut match_count,
            ctx.limits.max_grep_matches,
        )?;
        if !found {
            code = 1;
        }
    }
    for rel in &targets {
        match search_target(ctx, &matcher, rel, all, &mut stdout, &mut match_count) {
            Ok(found) => {
                if !found {
                    code = 1;
                }
            }
            Err(ExecError::Denied(msg)) => return Err(ExecError::Denied(msg)),
            Err(ExecError::Limit(msg)) => return Err(ExecError::Limit(msg)),
            Err(ExecError::Fail(msg)) => {
                code = 1;
                stderr.extend_from_slice(format!("grep: {msg}\n").as_bytes());
            }
        }
    }
    Ok(RawOutput {
        code,
        stdout,
        stderr,
    })
}

fn search_target(
    ctx: &Ctx,
    matcher: &grep::regex::RegexMatcher,
    rel: &str,
    all: bool,
    out: &mut Vec<u8>,
    match_count: &mut usize,
) -> Result<bool, ExecError> {
    let (target, meta) = resolve_read_target(ctx, rel)?;
    if meta.is_dir() {
        let mut walker = ignore::WalkBuilder::new(&target);
        walker
            .follow_links(false)
            .parents(false)
            .require_git(false)
            .hidden(!all)
            .ignore(!all)
            .git_ignore(!all)
            .git_global(!all)
            .git_exclude(!all);
        let mut files: Vec<(String, std::path::PathBuf)> = Vec::new();
        for entry in walker.build() {
            let entry = entry.map_err(|err| ExecError::Fail(format!("{rel}: {err}")))?;
            if entry.depth() == 0 || !entry.file_type().is_some_and(|ft| ft.is_file()) {
                continue;
            }
            if files.len() > ctx.limits.max_grep_files {
                return Err(ExecError::Limit(format!(
                    "grep: too many files (max {})",
                    ctx.limits.max_grep_files
                )));
            }
            let Some(entry_rel) = entry
                .path()
                .strip_prefix(ctx.resolver.root())
                .ok()
                .and_then(|p| p.to_str())
                .map(str::to_string)
            else {
                continue;
            };
            if ctx.resolver.resolve(&entry_rel).is_err() {
                continue;
            }
            files.push((entry_rel, entry.path().to_path_buf()));
        }
        files.sort();
        let mut found_any = false;
        for (entry_rel, entry_path) in files {
            let fmeta = fs::metadata(&entry_path)
                .map_err(|err| ExecError::Fail(format!("{entry_rel}: {err}")))?;
            check_read_bound(ctx, &entry_rel, &fmeta)?;
            let found = search_file(
                matcher,
                &entry_rel,
                &entry_path,
                out,
                match_count,
                ctx.limits.max_grep_matches,
            )?;
            found_any |= found;
        }
        Ok(found_any)
    } else if meta.is_file() {
        check_read_bound(ctx, rel, &meta)?;
        search_file(
            matcher,
            rel,
            &target,
            out,
            match_count,
            ctx.limits.max_grep_matches,
        )
    } else {
        Err(ExecError::Fail(format!("{rel}: not a regular file")))
    }
}

fn search_slice(
    matcher: &grep::regex::RegexMatcher,
    rel: &str,
    data: &[u8],
    out: &mut Vec<u8>,
    match_count: &mut usize,
    limit: usize,
) -> Result<bool, ExecError> {
    let mut searcher = grep::searcher::Searcher::new();
    searcher.set_binary_detection(grep::searcher::BinaryDetection::quit(b'\0'));
    let mut sink = CollectSink {
        rel: rel.to_string(),
        out,
        match_count,
        found: false,
        overflow: false,
        limit,
    };
    searcher
        .search_slice(matcher, data, &mut sink)
        .map_err(|err| ExecError::Fail(format!("{rel}: {err}")))?;
    if sink.overflow {
        return Err(ExecError::Limit(format!(
            "grep: too many matches (max {limit})"
        )));
    }
    Ok(sink.found)
}

fn search_file(
    matcher: &grep::regex::RegexMatcher,
    rel: &str,
    path: &std::path::Path,
    out: &mut Vec<u8>,
    match_count: &mut usize,
    limit: usize,
) -> Result<bool, ExecError> {
    let mut searcher = grep::searcher::Searcher::new();
    searcher.set_binary_detection(grep::searcher::BinaryDetection::quit(b'\0'));
    let mut sink = CollectSink {
        rel: rel.to_string(),
        out,
        match_count,
        found: false,
        overflow: false,
        limit,
    };
    searcher
        .search_path(matcher, path, &mut sink)
        .map_err(|err| ExecError::Fail(format!("{rel}: {err}")))?;
    if sink.overflow {
        return Err(ExecError::Limit(format!(
            "grep: too many matches (max {limit})"
        )));
    }
    Ok(sink.found)
}

struct CollectSink<'a> {
    rel: String,
    out: &'a mut Vec<u8>,
    match_count: &'a mut usize,
    found: bool,
    overflow: bool,
    limit: usize,
}

impl grep::searcher::Sink for CollectSink<'_> {
    type Error = std::io::Error;

    fn matched(
        &mut self,
        _searcher: &grep::searcher::Searcher,
        mat: &grep::searcher::SinkMatch<'_>,
    ) -> Result<bool, Self::Error> {
        self.found = true;
        *self.match_count += 1;
        if *self.match_count > self.limit {
            self.overflow = true;
            return Ok(false);
        }
        let line = String::from_utf8_lossy(mat.bytes());
        let line_no = mat.line_number().unwrap_or(0);
        self.out
            .extend_from_slice(format!("{}:{line_no}:{}\n", self.rel, line.trim_end()).as_bytes());
        Ok(true)
    }
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
    fn grep_finds_matches_in_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "foo one\nbar\nfoo two\n").unwrap();
        let out = run_cmd(&dir, "grep foo a.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "a.txt:1:foo one\na.txt:3:foo two\n");
    }

    #[test]
    fn grep_no_match_is_code_1() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "nothing\n").unwrap();
        let out = run_cmd(&dir, "grep zzz a.txt").unwrap();
        assert_eq!(out.code, 1);
        assert_eq!(out.stdout, "");
    }

    #[test]
    fn grep_searches_directories_recursively() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/a.rs"), "let x = 1;\n").unwrap();
        fs::write(dir.path().join("b.txt"), "let y = 2;\n").unwrap();
        let out = run_cmd(&dir, "grep let .").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "b.txt:1:let y = 2;\nsrc/a.rs:1:let x = 1;\n");
    }

    #[test]
    fn grep_respects_gitignore_unless_all() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("keep.txt"), "hit\n").unwrap();
        fs::write(dir.path().join("ignored.log"), "hit\n").unwrap();
        fs::write(dir.path().join(".gitignore"), "ignored.log\n").unwrap();
        let out = run_cmd(&dir, "grep hit .").unwrap();
        assert_eq!(out.stdout, "keep.txt:1:hit\n");
        let out = run_cmd(&dir, "grep --all hit .").unwrap();
        assert!(out.stdout.contains("ignored.log:1:hit"));
        assert!(out.stdout.contains("keep.txt:1:hit"));
    }

    #[test]
    fn grep_supports_glob_paths() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "hit\n").unwrap();
        fs::write(dir.path().join("b.rs"), "hit\n").unwrap();
        let out = run_cmd(&dir, "grep hit *.txt").unwrap();
        assert_eq!(out.stdout, "a.txt:1:hit\n");
    }

    #[test]
    fn grep_denies_escape_and_sensitive() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            run_cmd(&dir, "grep x ../secret.txt").unwrap_err(),
            ExecError::Denied(_)
        ));
        fs::write(dir.path().join(".env"), "SECRET=1\n").unwrap();
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
        let node = parse_input("grep SECRET .env", &HashMap::new()).unwrap();
        assert!(matches!(
            execute(&node, &ctx).unwrap_err(),
            ExecError::Denied(_)
        ));
    }

    #[test]
    fn grep_denies_oversized_file() {
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
        let node = parse_input("grep a big.txt", &HashMap::new()).unwrap();
        assert!(matches!(
            execute(&node, &ctx).unwrap_err(),
            ExecError::Limit(_)
        ));
    }

    #[test]
    fn grep_invalid_pattern_is_fail() {
        let dir = tempfile::tempdir().unwrap();
        let err = run_cmd(&dir, "grep '[' a.txt").unwrap_err();
        assert!(matches!(err, ExecError::Fail(m) if m.contains("invalid pattern")));
    }

    #[test]
    fn grep_missing_operands() {
        let dir = tempfile::tempdir().unwrap();
        let err = run_cmd(&dir, "grep").unwrap_err();
        assert!(matches!(err, ExecError::Fail(m) if m.contains("missing pattern")));
    }

    #[test]
    fn grep_reads_stdin_when_no_file_operand() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("in.txt"), "hello world\nfoo bar\n").unwrap();
        let out = run_cmd(&dir, "grep foo < in.txt").unwrap();
        assert_eq!(out.code, 0);
        assert!(out.stdout.contains("foo bar"));
        assert!(!out.stdout.contains("hello world"));
    }

    #[test]
    fn grep_skips_binary_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("bin.dat"), b"hit\0hit\n").unwrap();
        fs::write(dir.path().join("text.txt"), "hit\n").unwrap();
        let out = run_cmd(&dir, "grep hit .").unwrap();
        assert_eq!(out.stdout, "text.txt:1:hit\n");
    }
}
