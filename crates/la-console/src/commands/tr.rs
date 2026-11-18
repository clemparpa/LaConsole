use std::collections::HashMap;
use std::sync::Arc;

use super::stream::{read_sources, unsupported_opt, utf8, MAX_TR_SET_CHARS};
use super::{Ctx, ExecError, RawOutput};
use crate::parse::{Arg, SimpleCommand};
use crate::sink::DiskQuota;

const USAGE: &str = "tr: usage: tr <from> <to> [path...]";

/// Expands a `tr` set: literal chars, `\n`/`\t`/`\r`/`\\` escapes, and simple
/// `a-z` ranges. The expanded set is bounded by `MAX_TR_SET_CHARS`.
fn expand_set(name: &str, s: &str) -> Result<Vec<char>, ExecError> {
    let chars: Vec<char> = s.chars().collect();
    let mut out: Vec<char> = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        if i + 2 < chars.len() && chars[i + 1] == '-' {
            let lo = chars[i];
            let hi = chars[i + 2];
            if lo > hi {
                return Err(ExecError::Fail(format!(
                    "{name}: invalid range '{lo}-{hi}' in set"
                )));
            }
            let mut c = lo;
            loop {
                out.push(c);
                if out.len() > MAX_TR_SET_CHARS {
                    return Err(ExecError::Fail(format!(
                        "{name}: set too large (max {MAX_TR_SET_CHARS} chars after expansion)"
                    )));
                }
                if c == hi {
                    break;
                }
                match char::from_u32(c as u32 + 1) {
                    Some(next) => c = next,
                    None => {
                        return Err(ExecError::Fail(format!(
                            "{name}: invalid range '{lo}-{hi}' (surrogate boundary)"
                        )))
                    }
                }
            }
            i += 3;
        } else if chars[i] == '\\' {
            if i + 1 >= chars.len() {
                return Err(ExecError::Fail(format!(
                    "{name}: trailing backslash in set"
                )));
            }
            let e = match chars[i + 1] {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                '\\' => '\\',
                other => {
                    return Err(ExecError::Fail(format!(
                        "{name}: unsupported escape '\\{other}' in set"
                    )))
                }
            };
            out.push(e);
            i += 2;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    if out.is_empty() {
        return Err(ExecError::Fail(format!("{name}: empty set")));
    }
    if out.len() > MAX_TR_SET_CHARS {
        return Err(ExecError::Fail(format!(
            "{name}: set too large (max {MAX_TR_SET_CHARS} chars after expansion)"
        )));
    }
    Ok(out)
}

/// Parses the two positional set operands; `--` ends options, any other
/// option is a `fail` (no -d/-s).
fn parse_opts<'a>(
    name: &str,
    args: &'a [Arg],
) -> Result<(String, String, Vec<&'a Arg>), ExecError> {
    let mut positional: Vec<&Arg> = Vec::new();
    let mut opts_done = false;
    for arg in args {
        let text = arg.text.as_str();
        if !opts_done && text == "--" {
            opts_done = true;
        } else if !opts_done && text.starts_with('-') && text.len() > 1 {
            return Err(unsupported_opt(name, text));
        } else {
            positional.push(arg);
        }
    }
    if positional.len() < 2 {
        return Err(ExecError::Fail(USAGE.to_string()));
    }
    let rest = positional.split_off(2);
    Ok((positional[0].text.clone(), positional[1].text.clone(), rest))
}

/// `tr <from> <to> [path...]`: character translation over the whole input.
/// Like GNU tr, when `from` is longer than `to`, the extra `from` chars map to
/// the last char of `to`. UTF-8 in and out (chars, not bytes).
pub(crate) fn run(
    cmd: &SimpleCommand,
    input: &[u8],
    ctx: &Ctx,
    _quota: &Arc<DiskQuota>,
) -> Result<RawOutput, ExecError> {
    let (from_s, to_s, paths) = parse_opts("tr", &cmd.argv[1..])?;
    let from = expand_set("tr", &from_s)?;
    let to = expand_set("tr", &to_s)?;
    let (data, stderr, code) = read_sources("tr", ctx, &paths, input)?;
    let text = utf8("tr", data)?;
    let last_to = *to.last().expect("to set is non-empty");
    let mut map: HashMap<char, char> = HashMap::with_capacity(from.len());
    for (idx, &f) in from.iter().enumerate() {
        map.insert(f, to.get(idx).copied().unwrap_or(last_to));
    }
    let translated: String = text
        .chars()
        .map(|c| map.get(&c).copied().unwrap_or(c))
        .collect();
    Ok(RawOutput {
        code,
        stdout: translated.into_bytes(),
        stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::super::{execute, Ctx, ExecError, ExecOutcome, Limits};
    use crate::commands::stream::MAX_TR_SET_CHARS;
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
    fn tr_translates_ranges_and_single_chars() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "hello world\n").unwrap();
        let out = run_cmd(&dir, "tr a-z A-Z a.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "HELLO WORLD\n");
        let out = run_cmd(&dir, "tr l L a.txt").unwrap();
        assert_eq!(out.stdout, "heLLo worLd\n");
    }

    #[test]
    fn tr_longer_from_pads_with_last_to_char() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "abc\n").unwrap();
        let out = run_cmd(&dir, "tr abc X a.txt").unwrap();
        assert_eq!(out.stdout, "XXX\n");
        let out = run_cmd(&dir, "tr ab XY a.txt").unwrap();
        assert_eq!(out.stdout, "XYc\n");
    }

    #[test]
    fn tr_escapes_and_pipe() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("in.txt"), "a b\n").unwrap();
        let out = run_cmd(&dir, r#"cat in.txt | tr " " "\n""#).unwrap();
        assert_eq!(out.stdout, "a\nb\n");
        let out = run_cmd(&dir, r#"tr "a" "\t" < in.txt"#).unwrap();
        assert_eq!(out.stdout, "\t b\n");
    }

    #[test]
    fn tr_usage_and_set_errors_are_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        for cmd in [
            "tr a",
            "tr '' x a.txt",
            "tr z-a b a.txt",
            "tr a b -d a.txt",
            "tr 'a\\' b a.txt",
            r#"tr "a\q" b a.txt"#,
        ] {
            let err = run_cmd(&dir, cmd).unwrap_err();
            assert!(matches!(err, ExecError::Fail(_)), "cmd {cmd}: {err:?}");
        }
    }

    #[test]
    fn tr_oversized_set_and_bad_range_are_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        let big_from = "a".repeat(MAX_TR_SET_CHARS + 1);
        let err = run_cmd(&dir, &format!("tr \"{big_from}\" x a.txt")).unwrap_err();
        assert!(
            matches!(err, ExecError::Fail(ref m) if m.contains("too large")),
            "got {err:?}"
        );
        let err = run_cmd(&dir, "tr z-a b a.txt").unwrap_err();
        assert!(
            matches!(err, ExecError::Fail(ref m) if m.contains("invalid range")),
            "got {err:?}"
        );
    }

    #[test]
    fn tr_denies_escape_and_invalid_utf8() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            run_cmd(&dir, "tr a b ../evil.txt").unwrap_err(),
            ExecError::Denied(_)
        ));
        fs::write(dir.path().join("bin.dat"), vec![0xff, b'\n']).unwrap();
        let err = run_cmd(&dir, "tr a b bin.dat").unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("UTF-8")));
    }
}
