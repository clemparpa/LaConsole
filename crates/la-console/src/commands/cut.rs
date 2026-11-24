use std::sync::Arc;

use super::stream::{
    lines_inclusive, opt_value, parse_usize, read_sources, strip_nl, unsupported_opt, utf8,
    MAX_CUT_FIELDS,
};
use super::{Ctx, ExecError, RawOutput};
use crate::parse::{Arg, SimpleCommand};
use crate::sink::DiskQuota;

const USAGE: &str = "cut: usage: cut -d <sep> -f <n[,m...]> [path...]";

struct CutOpts {
    delim: char,
    fields: Vec<usize>,
}

/// Parses `-d SEP` / `--delimiter=SEP` (required, exactly one char, not `\n`)
/// and `-f LIST` / `--fields=LIST` (required, comma-separated 1-based field
/// numbers, bounded by `MAX_CUT_FIELDS`). `--` ends options; any other
/// option is a `fail`.
fn parse_opts<'a>(name: &str, args: &'a [Arg]) -> Result<(CutOpts, Vec<&'a Arg>), ExecError> {
    let mut delim: Option<char> = None;
    let mut fields: Option<Vec<usize>> = None;
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
                "delimiter" => {
                    let v = opt_value(name, "--delimiter", inline, args, &mut i)?;
                    delim = Some(parse_delim(name, &v)?);
                }
                "fields" => {
                    let v = opt_value(name, "--fields", inline, args, &mut i)?;
                    fields = Some(parse_field_list(name, &v)?);
                }
                _ => return Err(unsupported_opt(name, text)),
            }
        } else if !opts_done && text.starts_with('-') && text.len() > 1 {
            let chars: Vec<char> = text[1..].chars().collect();
            match chars[0] {
                'd' | 'f' => {
                    let rest: String = chars[1..].iter().collect();
                    let opt = if chars[0] == 'd' { "-d" } else { "-f" };
                    let v = if !rest.is_empty() {
                        rest
                    } else {
                        opt_value(name, opt, None, args, &mut i)?
                    };
                    if chars[0] == 'd' {
                        delim = Some(parse_delim(name, &v)?);
                    } else {
                        fields = Some(parse_field_list(name, &v)?);
                    }
                }
                c => return Err(unsupported_opt(name, &format!("-{c}"))),
            }
        } else {
            positional.push(&args[i]);
        }
        i += 1;
    }
    let delim = delim.ok_or_else(|| ExecError::Fail(USAGE.to_string()))?;
    let fields = fields.ok_or_else(|| ExecError::Fail(USAGE.to_string()))?;
    Ok((CutOpts { delim, fields }, positional))
}

fn parse_delim(name: &str, v: &str) -> Result<char, ExecError> {
    let mut chars = v.chars();
    let c = chars.next();
    if chars.next().is_some() || c.is_none() {
        return Err(ExecError::Fail(format!(
            "{name}: -d delimiter must be exactly one character"
        )));
    }
    let c = c.unwrap();
    if c == '\n' {
        return Err(ExecError::Fail(format!(
            "{name}: -d delimiter cannot be a newline"
        )));
    }
    Ok(c)
}

fn parse_field_list(name: &str, v: &str) -> Result<Vec<usize>, ExecError> {
    if v.is_empty() {
        return Err(ExecError::Fail(format!("{name}: empty -f field list")));
    }
    let mut fields = Vec::new();
    for part in v.split(',') {
        let n = parse_usize(name, "-f", part)?;
        if n == 0 {
            return Err(ExecError::Fail(format!(
                "{name}: invalid field number '0' in -f (fields are 1-based)"
            )));
        }
        fields.push(n);
    }
    if fields.len() > MAX_CUT_FIELDS {
        return Err(ExecError::Fail(format!(
            "{name}: too many fields in -f (max {MAX_CUT_FIELDS})"
        )));
    }
    Ok(fields)
}

/// `cut -d <sep> -f <n[,m...]> [path...]`: extracts fields from each line.
/// Streaming. A line without the delimiter is printed whole (GNU behavior
/// without `-s`); a missing field yields an empty field.
pub(crate) fn run(
    cmd: &SimpleCommand,
    input: &[u8],
    ctx: &Ctx,
    _quota: &Arc<DiskQuota>,
) -> Result<RawOutput, ExecError> {
    let (opts, paths) = parse_opts("cut", &cmd.argv[1..])?;
    let (data, stderr, code) = read_sources("cut", ctx, &paths, input)?;
    let text = utf8("cut", data)?;
    let mut stdout = Vec::new();
    for piece in lines_inclusive(&text) {
        let content = strip_nl(piece);
        if !content.contains(opts.delim) {
            stdout.extend_from_slice(piece.as_bytes());
            continue;
        }
        let fields: Vec<&str> = content.split(opts.delim).collect();
        let mut selected: Vec<&str> = Vec::with_capacity(opts.fields.len());
        for n in &opts.fields {
            selected.push(fields.get(n - 1).copied().unwrap_or(""));
        }
        let mut line = selected.join(&opts.delim.to_string());
        if piece.ends_with('\n') {
            line.push('\n');
        }
        stdout.extend_from_slice(line.as_bytes());
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
    fn cut_extracts_fields() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "a;b;c\nx;y\nno-delim\n").unwrap();
        let out = run_cmd(&dir, "cut -d ';' -f 1,3 a.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "a;c\nx;\nno-delim\n");
    }

    #[test]
    fn cut_flag_forms() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "a:b:c\n").unwrap();
        for cmd in [
            "cut -d: -f2 a.txt",
            "cut -d ':' -f 2 a.txt",
            "cut --delimiter=: --fields=2 a.txt",
            "cut --delimiter ':' --fields 2 a.txt",
        ] {
            let out = run_cmd(&dir, cmd).unwrap();
            assert_eq!(out.stdout, "b\n", "cmd {cmd}");
        }
    }

    #[test]
    fn cut_missing_field_is_empty_and_pipe_works() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("in.txt"), "a:b\n").unwrap();
        let out = run_cmd(&dir, "cat in.txt | cut -d: -f1,5").unwrap();
        assert_eq!(out.stdout, "a:\n");
        let out = run_cmd(&dir, "cut -d: -f2 < in.txt").unwrap();
        assert_eq!(out.stdout, "b\n");
    }

    #[test]
    fn cut_usage_errors_are_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "a:b\n").unwrap();
        for cmd in [
            "cut a.txt",
            "cut -d: a.txt",
            "cut -f1 a.txt",
            "cut -d ab -f1 a.txt",
            "cut -d: -f0 a.txt",
            "cut -d: -f1,x a.txt",
            "cut -d: -f a.txt",
            "cut -d: -f1 -s a.txt",
            "cut --delimiter a.txt",
        ] {
            let err = run_cmd(&dir, cmd).unwrap_err();
            assert!(matches!(err, ExecError::Fail(_)), "cmd {cmd}: {err:?}");
        }
    }

    #[test]
    fn cut_too_many_fields_and_newline_delim_are_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "a:b\n").unwrap();
        let mut list = String::new();
        for i in 1..=258 {
            if i > 1 {
                list.push(',');
            }
            list.push_str(&i.to_string());
        }
        let err = run_cmd(&dir, &format!("cut -d: -f{list} a.txt")).unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("too many fields")));
        let err = run_cmd(&dir, &format!("cut -d '{}' -f1 a.txt", '\n')).unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("newline")));
    }

    #[test]
    fn cut_denies_escape_and_invalid_utf8() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            run_cmd(&dir, "cut -d: -f1 ../evil.txt").unwrap_err(),
            ExecError::Denied(_)
        ));
        fs::write(dir.path().join("bin.dat"), vec![0xff, b'\n']).unwrap();
        let err = run_cmd(&dir, "cut -d: -f1 bin.dat").unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("UTF-8")));
    }
}
