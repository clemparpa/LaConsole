use std::fs;

use super::{check_read_path, Ctx, ExecError, RawOutput, DEFAULT_MAX_LS_ENTRIES};
use crate::parse::{expand_globs, SimpleCommand, DEFAULT_MAX_GLOB_MATCHES};

pub const DEFAULT_MAX_GREP_MATCHES: usize = 10_000;

pub(crate) fn run(cmd: &SimpleCommand, ctx: &Ctx) -> Result<RawOutput, ExecError> {
    let mut all = false;
    let mut positional: Vec<&crate::parse::Arg> = Vec::new();
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

    let mut targets: Vec<String> = Vec::new();
    for arg in &positional[1..] {
        if arg.glob {
            let matches = expand_globs(ctx.resolver.root(), &arg.text, DEFAULT_MAX_GLOB_MATCHES)
                .map_err(|err| ExecError::Denied(err.to_string()))?;
            targets.extend(matches);
        } else {
            targets.push(arg.text.clone());
        }
    }
    if targets.is_empty() {
        return Err(ExecError::Fail(
            "grep: missing file operand (stdin is not available)".to_string(),
        ));
    }

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut code = 0u16;
    let mut match_count = 0usize;
    for rel in &targets {
        match search_target(ctx, &matcher, rel, all, &mut stdout, &mut match_count) {
            Ok(found) => {
                if !found {
                    code = 1;
                }
            }
            Err(ExecError::Denied(msg)) => return Err(ExecError::Denied(msg)),
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
    let target = check_read_path(ctx, rel)?;
    let meta = fs::metadata(&target).map_err(|err| ExecError::Fail(format!("{rel}: {err}")))?;
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
            if files.len() > DEFAULT_MAX_LS_ENTRIES {
                return Err(ExecError::Denied(format!(
                    "grep: too many files (max {DEFAULT_MAX_LS_ENTRIES})"
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
            if fs::metadata(&entry_path)
                .map(|m| m.len() > ctx.max_read_bytes as u64)
                .unwrap_or(true)
            {
                return Err(ExecError::Denied(format!(
                    "grep: {entry_rel}: file too large ({} bytes max)",
                    ctx.max_read_bytes
                )));
            }
            let found = search_file(matcher, &entry_rel, &entry_path, out, match_count)?;
            found_any |= found;
        }
        Ok(found_any)
    } else if meta.is_file() {
        if meta.len() > ctx.max_read_bytes as u64 {
            return Err(ExecError::Denied(format!(
                "grep: {rel}: file too large ({} bytes max)",
                ctx.max_read_bytes
            )));
        }
        search_file(matcher, rel, &target, out, match_count)
    } else {
        Err(ExecError::Fail(format!("{rel}: not a regular file")))
    }
}

fn search_file(
    matcher: &grep::regex::RegexMatcher,
    rel: &str,
    path: &std::path::Path,
    out: &mut Vec<u8>,
    match_count: &mut usize,
) -> Result<bool, ExecError> {
    let mut searcher = grep::searcher::Searcher::new();
    searcher.set_binary_detection(grep::searcher::BinaryDetection::quit(b'\0'));
    let mut sink = CollectSink {
        rel: rel.to_string(),
        out,
        match_count,
        found: false,
        overflow: false,
    };
    searcher
        .search_path(matcher, path, &mut sink)
        .map_err(|err| ExecError::Fail(format!("{rel}: {err}")))?;
    if sink.overflow {
        return Err(ExecError::Denied(format!(
            "grep: too many matches (max {DEFAULT_MAX_GREP_MATCHES})"
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
        if *self.match_count > DEFAULT_MAX_GREP_MATCHES {
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
    use super::super::{execute, Ctx, ExecError, ExecOutcome, DEFAULT_MAX_READ_BYTES};
    use crate::parse::parse_input;
    use crate::resolve::Resolver;
    use crate::sink::{DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_MAX_WRITE_BYTES};
    use std::collections::HashMap;
    use std::fs;

    fn run_cmd(dir: &tempfile::TempDir, cmd: &str) -> Result<ExecOutcome, ExecError> {
        let resolver = Resolver::new(dir.path()).unwrap();
        let ctx = Ctx {
            resolver: &resolver,
            sensibles: &[],
            secrets: &[],
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_read_bytes: DEFAULT_MAX_READ_BYTES,
            max_write_bytes: DEFAULT_MAX_WRITE_BYTES,
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
            resolver: &resolver,
            sensibles: &sensibles,
            secrets: &[],
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_read_bytes: DEFAULT_MAX_READ_BYTES,
            max_write_bytes: DEFAULT_MAX_WRITE_BYTES,
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
            resolver: &resolver,
            sensibles: &[],
            secrets: &[],
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_read_bytes: 1024,
            max_write_bytes: DEFAULT_MAX_WRITE_BYTES,
        };
        let node = parse_input("grep a big.txt", &HashMap::new()).unwrap();
        assert!(matches!(
            execute(&node, &ctx).unwrap_err(),
            ExecError::Denied(_)
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
        let err = run_cmd(&dir, "grep foo").unwrap_err();
        assert!(matches!(err, ExecError::Fail(m) if m.contains("missing file")));
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
