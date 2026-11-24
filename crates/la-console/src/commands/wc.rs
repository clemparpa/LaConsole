use std::sync::Arc;

use super::stream::{read_sources, unsupported_opt, utf8};
use super::{Ctx, ExecError, RawOutput};
use crate::parse::{Arg, SimpleCommand};
use crate::sink::DiskQuota;

struct WcOpts {
    lines: bool,
    words: bool,
    bytes: bool,
}

/// Parses `[-l] [-w] [-c]` (combinable, plus long forms); `--` ends options.
fn parse_opts<'a>(name: &str, args: &'a [Arg]) -> Result<(WcOpts, Vec<&'a Arg>), ExecError> {
    let mut o = WcOpts {
        lines: false,
        words: false,
        bytes: false,
    };
    let mut positional = Vec::new();
    let mut i = 0usize;
    let mut opts_done = false;
    while i < args.len() {
        let text = args[i].text.as_str();
        if !opts_done && text == "--" {
            opts_done = true;
        } else if !opts_done && text.starts_with("--") && text.len() > 2 {
            let body = &text[2..];
            let (opt, inline) = match body.find('=') {
                Some(p) => (&body[..p], Some(body[p + 1..].to_string())),
                None => (body, None),
            };
            match opt {
                "lines" => {
                    reject_value(name, "--lines", inline)?;
                    o.lines = true;
                }
                "words" => {
                    reject_value(name, "--words", inline)?;
                    o.words = true;
                }
                "bytes" | "chars" => {
                    reject_value(name, &format!("--{opt}"), inline)?;
                    o.bytes = true;
                }
                _ => return Err(unsupported_opt(name, text)),
            }
        } else if !opts_done && text.starts_with('-') && text.len() > 1 {
            for c in text[1..].chars() {
                match c {
                    'l' => o.lines = true,
                    'w' => o.words = true,
                    'c' => o.bytes = true,
                    other => return Err(unsupported_opt(name, &format!("-{other}"))),
                }
            }
        } else {
            positional.push(&args[i]);
        }
        i += 1;
    }
    Ok((o, positional))
}

fn reject_value(name: &str, opt: &str, inline: Option<String>) -> Result<(), ExecError> {
    if inline.is_some() {
        return Err(ExecError::Fail(format!(
            "{name}: option {opt} doesn't take a value"
        )));
    }
    Ok(())
}

/// `wc [-l|-w|-c] [path...]`: counts lines/words/bytes of the whole input (the
/// three counts by default), printed space-separated on one line. Streaming.
pub(crate) fn run(
    cmd: &SimpleCommand,
    input: &[u8],
    ctx: &Ctx,
    _quota: &Arc<DiskQuota>,
) -> Result<RawOutput, ExecError> {
    let (opts, paths) = parse_opts("wc", &cmd.argv[1..])?;
    let (data, stderr, code) = read_sources("wc", ctx, &paths, input)?;
    let text = utf8("wc", data)?;
    let any = opts.lines || opts.words || opts.bytes;
    let mut counts = Vec::new();
    if opts.lines || !any {
        counts.push(text.bytes().filter(|b| *b == b'\n').count().to_string());
    }
    if opts.words || !any {
        counts.push(text.split_whitespace().count().to_string());
    }
    if opts.bytes || !any {
        counts.push(text.len().to_string());
    }
    let mut stdout = counts.join(" ").into_bytes();
    stdout.push(b'\n');
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
    fn wc_defaults_to_lines_words_bytes() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "one two\nthree\n").unwrap();
        let out = run_cmd(&dir, "wc a.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "2 3 14\n");
    }

    #[test]
    fn wc_selected_flags_and_combinations() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "a b\nc\n").unwrap();
        assert_eq!(run_cmd(&dir, "wc -l a.txt").unwrap().stdout, "2\n");
        assert_eq!(run_cmd(&dir, "wc -w a.txt").unwrap().stdout, "3\n");
        assert_eq!(run_cmd(&dir, "wc -c a.txt").unwrap().stdout, "6\n");
        assert_eq!(run_cmd(&dir, "wc -lw a.txt").unwrap().stdout, "2 3\n");
        assert_eq!(
            run_cmd(&dir, "wc --lines --bytes a.txt").unwrap().stdout,
            "2 6\n"
        );
        assert_eq!(run_cmd(&dir, "wc --words a.txt").unwrap().stdout, "3\n");
    }

    #[test]
    fn wc_empty_input_and_pipe() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("empty.txt"), "").unwrap();
        let out = run_cmd(&dir, "wc empty.txt").unwrap();
        assert_eq!(out.stdout, "0 0 0\n");
        fs::write(dir.path().join("in.txt"), "x y\n").unwrap();
        let out = run_cmd(&dir, "cat in.txt | wc -l").unwrap();
        assert_eq!(out.stdout, "1\n");
        let out = run_cmd(&dir, "wc -c < in.txt").unwrap();
        assert_eq!(out.stdout, "4\n");
    }

    #[test]
    fn wc_unknown_option_is_fail() {
        let dir = tempfile::tempdir().unwrap();
        for cmd in ["wc -q", "wc --nope", "wc -l --lines=3"] {
            let err = run_cmd(&dir, cmd).unwrap_err();
            assert!(matches!(err, ExecError::Fail(_)), "cmd {cmd}: {err:?}");
        }
    }

    #[test]
    fn wc_denies_escape_and_invalid_utf8() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            run_cmd(&dir, "wc ../evil.txt").unwrap_err(),
            ExecError::Denied(_)
        ));
        fs::write(dir.path().join("bin.dat"), vec![0xff, b'\n']).unwrap();
        let err = run_cmd(&dir, "wc bin.dat").unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("UTF-8")));
    }

    #[test]
    fn wc_missing_file_is_code_1() {
        let dir = tempfile::tempdir().unwrap();
        let out = run_cmd(&dir, "wc nope.txt").unwrap();
        assert_eq!(out.code, 1);
        assert!(out.stderr.contains("nope.txt"));
        assert_eq!(out.stdout, "0 0 0\n");
    }
}
