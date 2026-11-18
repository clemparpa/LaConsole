//! Shared helpers for the in-process stream filters (whitelist-expansion
//! package B: `head`/`tail`/`wc`/`sort`/`uniq`/`cut`/`tr`).
//!
//! Every filter reads the pipe/`<` input when no path is given, otherwise the
//! concatenation of its path operands read through the secured pipeline
//! (`read_bounded` = `resolve()` + sensitive files + `max_read_bytes`).
//! Invalid UTF-8 is a `fail`, unknown options are a `fail`, and no filter
//! ever writes to disk or executes code.

use super::{collect_paths, read_bounded, Ctx, ExecError, Limits};
use crate::parse::Arg;

/// Hard bound on `head`/`tail -n N`: `tail` holds a ring buffer of N lines.
pub(crate) const MAX_HEAD_TAIL_LINES: usize = 10_000;
/// Hard bound on the number of fields in a `cut -f` list.
pub(crate) const MAX_CUT_FIELDS: usize = 256;
/// Hard bound on the expanded size (chars) of a `tr` set.
pub(crate) const MAX_TR_SET_CHARS: usize = 1024;

/// Reads the input of a stream filter: the pipe/`<` data when no path operand
/// is present, otherwise the concatenation of every path through the secured
/// read pipeline. `Denied`/`Limit` abort the command; a per-file `Fail` is
/// collected on stderr with code 1 (same semantics as `cat`).
pub(crate) fn read_sources(
    name: &str,
    ctx: &Ctx,
    path_args: &[&Arg],
    input: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, u16), ExecError> {
    let paths = collect_paths(ctx, path_args.iter().copied())?;
    let mut data = Vec::new();
    let mut stderr = Vec::new();
    let mut code = 0u16;
    if paths.is_empty() {
        data.extend_from_slice(input);
    }
    for rel in &paths {
        match read_bounded(ctx, rel) {
            Ok(bytes) => data.extend_from_slice(&bytes),
            Err(ExecError::Denied(msg)) => return Err(ExecError::Denied(msg)),
            Err(ExecError::Limit(msg)) => return Err(ExecError::Limit(msg)),
            Err(ExecError::Fail(msg)) => {
                code = 1;
                stderr.extend_from_slice(format!("{name}: {msg}\n").as_bytes());
            }
        }
    }
    Ok((data, stderr, code))
}

/// Strict UTF-8 decode of the gathered input: invalid UTF-8 = `fail`
/// (common rule of the stream filters, same as `sed`).
pub(crate) fn utf8(name: &str, data: Vec<u8>) -> Result<String, ExecError> {
    String::from_utf8(data)
        .map_err(|_| ExecError::Fail(format!("{name}: input is not valid UTF-8")))
}

/// Splits text into lines keeping each line's original `\n` terminator on its
/// piece, so joining the pieces reproduces the input byte for byte.
pub(crate) fn lines_inclusive(text: &str) -> Vec<&str> {
    text.split_inclusive('\n').collect()
}

/// Splits into line contents (without terminator) plus whether the input ended
/// with a newline. `""` yields zero lines.
pub(crate) fn split_lines(text: &str) -> (Vec<&str>, bool) {
    if text.is_empty() {
        return (Vec::new(), false);
    }
    let trailing = text.ends_with('\n');
    let mut parts: Vec<&str> = text.split('\n').collect();
    if trailing {
        parts.pop();
    }
    (parts, trailing)
}

/// Strips one trailing `\n` if present.
pub(crate) fn strip_nl(piece: &str) -> &str {
    piece.strip_suffix('\n').unwrap_or(piece)
}

pub(crate) fn unsupported_opt(name: &str, opt: &str) -> ExecError {
    ExecError::Fail(format!("{name}: unsupported option '{opt}'"))
}

pub(crate) fn missing_value(name: &str, opt: &str) -> ExecError {
    ExecError::Fail(format!("{name}: option '{opt}' requires an argument"))
}

/// Option value: inline (`--opt=v`) or the next argument.
pub(crate) fn opt_value(
    name: &str,
    opt: &str,
    inline: Option<String>,
    args: &[Arg],
    i: &mut usize,
) -> Result<String, ExecError> {
    if let Some(v) = inline {
        return Ok(v);
    }
    *i += 1;
    if *i >= args.len() {
        return Err(missing_value(name, opt));
    }
    Ok(args[*i].text.clone())
}

pub(crate) fn parse_usize(name: &str, opt: &str, v: &str) -> Result<usize, ExecError> {
    v.parse::<usize>()
        .map_err(|_| ExecError::Fail(format!("{name}: invalid number '{v}' for {opt}")))
}

/// Parses the `[-n N]` / `--lines[=N]` option shared by `head` and `tail`.
/// Returns `(n, positional path args)`. N is bounded by
/// `min(MAX_HEAD_TAIL_LINES, Limits::max_stream_lines)`.
pub(crate) fn parse_lines_opt<'a>(
    name: &str,
    args: &'a [Arg],
    limits: &Limits,
) -> Result<(usize, Vec<&'a Arg>), ExecError> {
    let mut n = 10usize;
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
            if opt != "lines" {
                return Err(unsupported_opt(name, text));
            }
            let v = opt_value(name, "--lines", inline, args, &mut i)?;
            n = parse_usize(name, "--lines", &v)?;
        } else if !opts_done && text.starts_with('-') && text.len() > 1 {
            let chars: Vec<char> = text[1..].chars().collect();
            if chars[0] != 'n' {
                return Err(unsupported_opt(name, &format!("-{}", chars[0])));
            }
            let rest: String = chars[1..].iter().collect();
            let v = if !rest.is_empty() {
                rest
            } else {
                opt_value(name, "-n", None, args, &mut i)?
            };
            n = parse_usize(name, "-n", &v)?;
        } else {
            positional.push(&args[i]);
        }
        i += 1;
    }
    let cap = MAX_HEAD_TAIL_LINES.min(limits.max_stream_lines);
    if n > cap {
        return Err(ExecError::Fail(format!("{name}: -n too large (max {cap})")));
    }
    Ok((n, positional))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_inclusive_is_lossless() {
        for text in ["", "a", "a\n", "a\nb", "a\nb\n", "\n", "a\n\nb\n"] {
            let pieces = lines_inclusive(text);
            assert_eq!(pieces.concat(), text);
        }
    }

    #[test]
    fn split_lines_counts_and_trailing_flag() {
        assert_eq!(split_lines(""), (vec![], false));
        assert_eq!(split_lines("a"), (vec!["a"], false));
        assert_eq!(split_lines("a\n"), (vec!["a"], true));
        assert_eq!(split_lines("a\nb\n"), (vec!["a", "b"], true));
        assert_eq!(split_lines("\n"), (vec![""], true));
    }

    #[test]
    fn strip_nl_removes_one_newline() {
        assert_eq!(strip_nl("a\n"), "a");
        assert_eq!(strip_nl("a"), "a");
        assert_eq!(strip_nl("\n"), "");
    }
}
