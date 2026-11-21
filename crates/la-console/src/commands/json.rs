use std::sync::Arc;

use super::stream::unsupported_opt;
use super::{collect_paths, read_bounded, Ctx, ExecError, RawOutput};
use crate::parse::{Arg, SimpleCommand};
use crate::sink::DiskQuota;

const USAGE: &str =
    "json: usage: json <selector> [path...] (selector ex. body.items[0].name, '.' = whole document; without path: reads pipe/'<' input)";

/// Hard bound on the selector length in bytes.
pub(crate) const MAX_SELECTOR_BYTES: usize = 4096;

const NULL: serde_json::Value = serde_json::Value::Null;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    Key(String),
    Index(usize),
}

/// `json <selector> [path...]`: extracts a field from JSON documents and
/// prints it as compact JSON, one line per source. Without a path operand the
/// pipe/`<` input is parsed; with paths, each file goes through the secured
/// read pipeline (`read_bounded` = `resolve()` + sensibles + `max_read_bytes`).
/// Fail-closed: invalid JSON, invalid selector, unknown option or type
/// mismatch on the path are `fail`; oversized input or excessive depth are
/// `limit`; path escapes and sensitive files are `denied`.
pub(crate) fn run(
    cmd: &SimpleCommand,
    input: &[u8],
    ctx: &Ctx,
    _quota: &Arc<DiskQuota>,
) -> Result<RawOutput, ExecError> {
    let args = &cmd.argv[1..];
    if args.is_empty() {
        return Err(ExecError::Fail(USAGE.to_string()));
    }
    if args[0].text.starts_with('-') {
        return Err(unsupported_opt("json", &args[0].text));
    }
    let selector = &args[0].text;
    if selector.len() > MAX_SELECTOR_BYTES {
        return Err(ExecError::Fail(format!(
            "json: selector too long ({} bytes max)",
            MAX_SELECTOR_BYTES
        )));
    }
    let steps = parse_selector(selector)?;
    if steps.len() > ctx.limits.max_json_depth {
        return Err(ExecError::Fail(format!(
            "json: selector too deep ({} steps max)",
            ctx.limits.max_json_depth
        )));
    }
    let path_args: Vec<&Arg> = args[1..].iter().collect();

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut code = 0u16;
    if path_args.is_empty() {
        let line = extract_from_bytes(input, &steps, ctx).map_err(|err| match err {
            ExecError::Denied(m) => ExecError::Denied(m),
            ExecError::Limit(m) => ExecError::Limit(m),
            ExecError::Fail(m) => ExecError::Fail(format!("json: (stdin): {m}")),
        })?;
        stdout.extend_from_slice(&line);
    } else {
        let paths = collect_paths(ctx, path_args)?;
        for rel in &paths {
            match read_bounded(ctx, rel) {
                Ok(bytes) => match extract_from_bytes(&bytes, &steps, ctx) {
                    Ok(line) => stdout.extend_from_slice(&line),
                    Err(ExecError::Denied(m)) => return Err(ExecError::Denied(m)),
                    Err(ExecError::Limit(m)) => return Err(ExecError::Limit(m)),
                    Err(ExecError::Fail(m)) => {
                        code = 1;
                        stderr.extend_from_slice(format!("json: {rel}: {m}\n").as_bytes());
                    }
                },
                Err(ExecError::Denied(m)) => return Err(ExecError::Denied(m)),
                Err(ExecError::Limit(m)) => return Err(ExecError::Limit(m)),
                Err(ExecError::Fail(m)) => {
                    code = 1;
                    stderr.extend_from_slice(format!("json: {m}\n").as_bytes());
                }
            }
        }
    }
    Ok(RawOutput {
        code,
        stdout,
        stderr,
    })
}

/// Parses one JSON document (bounded depth) and returns the selected value
/// serialized as one compact JSON line.
fn extract_from_bytes(bytes: &[u8], steps: &[Step], ctx: &Ctx) -> Result<Vec<u8>, ExecError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|err| ExecError::Fail(format!("invalid JSON: {err}")))?;
    let depth = json_depth(&value);
    if depth > ctx.limits.max_json_depth {
        return Err(ExecError::Limit(format!(
            "JSON nesting too deep ({depth} > {} max)",
            ctx.limits.max_json_depth
        )));
    }
    let selected = extract(&value, steps)?;
    let mut line = serde_json::to_vec(selected)
        .map_err(|err| ExecError::Fail(format!("serialization failed: {err}")))?;
    line.push(b'\n');
    Ok(line)
}

/// jq-like selection: a missing object key or an out-of-range array index
/// yields `null`; indexing `null` yields `null`; indexing any other
/// incompatible type is a `fail`.
fn extract<'a>(
    value: &'a serde_json::Value,
    steps: &[Step],
) -> Result<&'a serde_json::Value, ExecError> {
    let mut cur = value;
    for step in steps {
        cur = match (step, cur) {
            (Step::Key(key), serde_json::Value::Object(map)) => map.get(key).unwrap_or(&NULL),
            (Step::Index(i), serde_json::Value::Array(arr)) => arr.get(*i).unwrap_or(&NULL),
            (_, serde_json::Value::Null) => &NULL,
            (Step::Key(key), other) => {
                return Err(ExecError::Fail(format!(
                    "cannot index {} with key '{key}'",
                    type_name(other)
                )))
            }
            (Step::Index(i), other) => {
                return Err(ExecError::Fail(format!(
                    "cannot index {} with [{i}]",
                    type_name(other)
                )))
            }
        };
    }
    Ok(cur)
}

fn type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Depth of a parsed JSON value (a scalar is depth 1). Bounded by serde_json's
/// own recursion limit at parse time, so this recursion cannot overflow.
fn json_depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(map) => map.values().map(json_depth).max().unwrap_or(0) + 1,
        serde_json::Value::Array(arr) => arr.iter().map(json_depth).max().unwrap_or(0) + 1,
        _ => 1,
    }
}

/// Parses a selector like `body.items[0].name`, `.` (whole document) or ``
/// (whole document) into steps. Strict: empty segments (`a..b`), a trailing
/// dot, an empty or non-numeric index and a missing `.` after `]` are all a
/// `fail`.
fn parse_selector(selector: &str) -> Result<Vec<Step>, ExecError> {
    fn invalid(sel: &str) -> ExecError {
        ExecError::Fail(format!(
            "json: invalid selector '{sel}': expected forms like .a.b[0].c ('.' = whole document)"
        ))
    }
    let chars: Vec<char> = selector.chars().collect();
    let mut steps = Vec::new();
    let mut i = 0usize;
    if chars.first() == Some(&'.') {
        i = 1;
    }
    while i < chars.len() {
        match chars[i] {
            '.' => {
                i += 1;
                if i >= chars.len() || chars[i] == '.' {
                    return Err(invalid(selector));
                }
            }
            '[' => {
                i += 1;
                let start = i;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
                if i == start || i >= chars.len() || chars[i] != ']' {
                    return Err(invalid(selector));
                }
                let n: usize = chars[start..i]
                    .iter()
                    .collect::<String>()
                    .parse()
                    .map_err(|_| invalid(selector))?;
                i += 1;
                if i < chars.len() && chars[i] != '.' {
                    return Err(invalid(selector));
                }
                steps.push(Step::Index(n));
            }
            _ => {
                let start = i;
                while i < chars.len() && chars[i] != '.' && chars[i] != '[' {
                    if chars[i] == ']' {
                        return Err(invalid(selector));
                    }
                    i += 1;
                }
                let name: String = chars[start..i].iter().collect();
                if name.is_empty() {
                    return Err(invalid(selector));
                }
                steps.push(Step::Key(name));
            }
        }
    }
    Ok(steps)
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
            sandboxed: false,
            sandbox_shell: None,
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

    const DOC: &str = r#"{"body":{"items":[{"name":"first"},{"name":"second"}],"n":3},"ok":true}"#;

    #[test]
    fn json_extracts_nested_field_from_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("data.json"), DOC).unwrap();
        let out = run_cmd(&dir, "json body.items[0].name data.json").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "\"first\"\n");
    }

    #[test]
    fn json_selector_may_start_with_dot_and_root_is_whole_document() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("data.json"), DOC).unwrap();
        let out = run_cmd(&dir, "json .body.n data.json").unwrap();
        assert_eq!(out.stdout, "3\n");
        let out = run_cmd(&dir, "json . data.json").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(out.stdout.trim()).unwrap(),
            serde_json::from_str::<serde_json::Value>(DOC).unwrap()
        );
        let out = run_cmd(&dir, r#"json "" data.json"#).unwrap();
        assert_eq!(out.code, 0);
        assert!(out.stdout.contains("\"items\""));
    }

    #[test]
    fn json_reads_pipe_input_and_chains() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("data.json"), DOC).unwrap();
        let out = run_cmd(&dir, "cat data.json | json body.items[1].name").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "\"second\"\n");
        let out = run_cmd(
            &dir,
            "cat data.json | json body | json items[0] | json name",
        )
        .unwrap();
        assert_eq!(out.stdout, "\"first\"\n");
    }

    #[test]
    fn json_reads_stdin_redirect() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("in.json"), DOC).unwrap();
        let out = run_cmd(&dir, "json ok < in.json").unwrap();
        assert_eq!(out.stdout, "true\n");
    }

    #[test]
    fn json_missing_key_or_index_yields_null() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("data.json"), DOC).unwrap();
        let out = run_cmd(&dir, "json body.nope data.json").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "null\n");
        let out = run_cmd(&dir, "json body.items[9] data.json").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "null\n");
        let out = run_cmd(&dir, "json body.nope.deeper data.json").unwrap();
        assert_eq!(out.stdout, "null\n");
    }

    #[test]
    fn json_type_mismatch_is_fail_code_1() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("data.json"), DOC).unwrap();
        let out = run_cmd(&dir, "json body.n.name data.json").unwrap();
        assert_eq!(out.code, 1);
        assert!(out.stderr.contains("cannot index number with key 'name'"));
        let out = run_cmd(&dir, "json body[0] data.json").unwrap();
        assert_eq!(out.code, 1);
        assert!(out.stderr.contains("cannot index object with [0]"));
    }

    #[test]
    fn json_invalid_json_is_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("bad.json"), b"{not json").unwrap();
        let out = run_cmd(&dir, "json a bad.json").unwrap();
        assert_eq!(out.code, 1);
        assert!(out.stderr.contains("invalid JSON"));
        let err = run_cmd(&dir, "cat bad.json | json a").unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("invalid JSON")));
    }

    #[test]
    fn json_empty_stream_input_is_fail() {
        let dir = tempfile::tempdir().unwrap();
        let err = run_cmd(&dir, "json a").unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("invalid JSON")));
    }

    #[test]
    fn json_invalid_selectors_are_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("data.json"), DOC).unwrap();
        for sel in [
            "a..b", "a.", ".", "..", "a[]", "a[x]", "a[1", "a[0]b", "a]b", "a[-1]",
        ] {
            if sel == "." {
                continue; // '.' alone is the whole document
            }
            let err = run_cmd(&dir, &format!("json \"{sel}\" data.json")).unwrap_err();
            assert!(
                matches!(err, ExecError::Fail(ref m) if m.contains("invalid selector")),
                "selector {sel:?}: {err:?}"
            );
        }
    }

    #[test]
    fn json_unknown_option_is_fail() {
        let dir = tempfile::tempdir().unwrap();
        for cmd in ["json -r a", "json --raw a", "json -h", "json -- a"] {
            let err = run_cmd(&dir, cmd).unwrap_err();
            assert!(
                matches!(err, ExecError::Fail(ref m) if m.contains("unsupported option")),
                "cmd {cmd}: {err:?}"
            );
        }
    }

    #[test]
    fn json_missing_selector_is_usage_fail() {
        let dir = tempfile::tempdir().unwrap();
        let err = run_cmd(&dir, "json").unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("usage")));
    }

    #[test]
    fn json_multiple_files_one_line_each() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.json"), r#"{"v":1}"#).unwrap();
        fs::write(dir.path().join("b.json"), r#"{"v":2}"#).unwrap();
        let out = run_cmd(&dir, "json v a.json b.json").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "1\n2\n");
        let out = run_cmd(&dir, "json v *.json").unwrap();
        assert_eq!(out.stdout, "1\n2\n");
    }

    #[test]
    fn json_missing_file_is_code_1_and_continues() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.json"), r#"{"v":1}"#).unwrap();
        let out = run_cmd(&dir, "json v nope.json a.json").unwrap();
        assert_eq!(out.code, 1);
        assert_eq!(out.stdout, "1\n");
        assert!(out.stderr.contains("nope.json"));
    }

    #[test]
    fn json_denies_escape_and_sensitive() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            run_cmd(&dir, "json a ../evil.json").unwrap_err(),
            ExecError::Denied(_)
        ));
        assert!(matches!(
            run_cmd(&dir, "json a /etc/passwd").unwrap_err(),
            ExecError::Denied(_)
        ));
        fs::write(dir.path().join(".env"), "{}").unwrap();
        let resolver = Resolver::new(dir.path()).unwrap();
        let ctx = Ctx {
            resolver,
            sensibles: vec![regex::Regex::new(r".*\.env$").unwrap()],
            secrets: vec![],
            limits: Limits::default(),
            trusted: None,
            sandboxed: false,
            sandbox_shell: None,
        };
        let node = parse_input("json a .env", &HashMap::new()).unwrap();
        assert!(matches!(execute(&node, &ctx), Err(ExecError::Denied(_))));
        let node = parse_input("json a < .env", &HashMap::new()).unwrap();
        assert!(matches!(execute(&node, &ctx), Err(ExecError::Denied(_))));
    }

    #[test]
    fn json_oversized_file_is_limit() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("big.json"), vec![b' '; 2048]).unwrap();
        let limits = Limits {
            max_read_bytes: 1024,
            ..Limits::default()
        };
        let err = run_cmd_limits(&dir, "json a big.json", limits).unwrap_err();
        assert!(matches!(err, ExecError::Limit(_)));
    }

    #[test]
    fn json_depth_over_limit_is_limit() {
        let dir = tempfile::tempdir().unwrap();
        let mut doc = String::from("1");
        for _ in 0..9 {
            doc = format!("{{\"a\":{doc}}}");
        }
        fs::write(dir.path().join("deep.json"), &doc).unwrap();
        let limits = Limits {
            max_json_depth: 4,
            ..Limits::default()
        };
        let err = run_cmd_limits(&dir, "json a deep.json", limits).unwrap_err();
        assert!(
            matches!(err, ExecError::Limit(ref m) if m.contains("nesting too deep")),
            "got {err:?}"
        );
        let out = run_cmd(&dir, "json a.a.a.a.a.a.a.a.a deep.json").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "1\n");
    }

    #[test]
    fn json_beyond_serde_recursion_limit_is_fail_not_crash() {
        let dir = tempfile::tempdir().unwrap();
        let mut doc = String::from("1");
        for _ in 0..500 {
            doc = format!("[{doc}]");
        }
        fs::write(dir.path().join("deep.json"), &doc).unwrap();
        let out = run_cmd(&dir, "json a deep.json").unwrap();
        assert_eq!(out.code, 1);
        assert!(out.stderr.contains("invalid JSON"));
    }

    #[test]
    fn json_selector_too_long_or_too_deep_is_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("data.json"), DOC).unwrap();
        let long = "a.".repeat(3000);
        let err = run_cmd(&dir, &format!("json \"{long}\" data.json")).unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("selector too long")));
        let limits = Limits {
            max_json_depth: 2,
            ..Limits::default()
        };
        let err = run_cmd_limits(&dir, "json a.b.c data.json", limits).unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("selector too deep")));
    }

    #[test]
    fn json_redirect_out_goes_through_file_sink() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("data.json"), DOC).unwrap();
        let out = run_cmd(&dir, "json body.n data.json > out.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "");
        assert_eq!(
            fs::read_to_string(dir.path().join("out.txt")).unwrap(),
            "3\n"
        );
    }

    #[test]
    fn json_output_masks_secrets() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("data.json"), r#"{"key":"tok-abc123"}"#).unwrap();
        let resolver = Resolver::new(dir.path()).unwrap();
        let ctx = Ctx {
            resolver,
            sensibles: vec![],
            secrets: vec!["tok-abc123".to_string()],
            limits: Limits::default(),
            trusted: None,
            sandboxed: false,
            sandbox_shell: None,
        };
        let node = parse_input("json key data.json", &HashMap::new()).unwrap();
        let out = execute(&node, &ctx).unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "\"***\"\n");
    }

    #[test]
    fn json_scalars_and_arrays_output_compact_json() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("data.json"), DOC).unwrap();
        let out = run_cmd(&dir, "json body.items data.json").unwrap();
        assert_eq!(out.stdout, "[{\"name\":\"first\"},{\"name\":\"second\"}]\n");
        let out = run_cmd(&dir, "json ok data.json").unwrap();
        assert_eq!(out.stdout, "true\n");
    }
}
