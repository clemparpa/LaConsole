use super::{collect_paths, read_bounded, write_file, Ctx, ExecError, RawOutput};
use crate::parse::SimpleCommand;
use std::sync::Arc;

const USAGE: &str =
    "sed: usage: sed [-i] s/<pat>/<repl>/[g] <path...> (without path: pipe stream only, after '|')";

struct Sub {
    pattern: regex::Regex,
    repl: String,
    global: bool,
}

pub(crate) fn run(
    cmd: &SimpleCommand,
    input: &[u8],
    ctx: &Ctx,
    quota: &Arc<crate::sink::DiskQuota>,
) -> Result<RawOutput, ExecError> {
    let mut args = &cmd.argv[1..];
    let mut in_place = false;
    while let Some(first) = args.first() {
        if first.text == "-i" {
            in_place = true;
            args = &args[1..];
        } else if first.text.starts_with('-') {
            return Err(ExecError::Fail(format!(
                "sed: unsupported option '{}': only -i is supported",
                first.text
            )));
        } else {
            break;
        }
    }
    if args.is_empty() {
        return Err(ExecError::Fail(USAGE.to_string()));
    }
    let sub = parse_script(&args[0].text)?;
    let path_args = &args[1..];
    if path_args.is_empty() {
        if in_place {
            return Err(ExecError::Fail(USAGE.to_string()));
        }
        let content = String::from_utf8(input.to_vec())
            .map_err(|_| ExecError::Fail("sed: input is not valid UTF-8".to_string()))?;
        let replaced = apply(&sub.pattern, &sub.repl, &content, sub.global);
        return Ok(RawOutput {
            code: 0,
            stdout: replaced.into_bytes(),
            stderr: Vec::new(),
        });
    }
    let targets = collect_paths(ctx, path_args)?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut code = 0u16;
    for rel in &targets {
        match process_one(ctx, &sub, rel, in_place, quota) {
            Ok(Some(bytes)) => stdout.extend_from_slice(&bytes),
            Ok(None) => {}
            Err(ExecError::Denied(msg)) => return Err(ExecError::Denied(msg)),
            Err(ExecError::Limit(msg)) => return Err(ExecError::Limit(msg)),
            Err(ExecError::Fail(msg)) => {
                code = 1;
                stderr.extend_from_slice(format!("sed: {msg}\n").as_bytes());
            }
        }
    }
    Ok(RawOutput {
        code,
        stdout,
        stderr,
    })
}

fn process_one(
    ctx: &Ctx,
    sub: &Sub,
    rel: &str,
    in_place: bool,
    quota: &Arc<crate::sink::DiskQuota>,
) -> Result<Option<Vec<u8>>, ExecError> {
    let bytes = read_bounded(ctx, rel)?;
    let content =
        String::from_utf8(bytes).map_err(|_| ExecError::Fail(format!("{rel}: not valid UTF-8")))?;
    let replaced = apply(&sub.pattern, &sub.repl, &content, sub.global);
    if in_place {
        write_file(ctx, rel, replaced.as_bytes(), false, quota.clone())?;
        Ok(None)
    } else {
        Ok(Some(replaced.into_bytes()))
    }
}

fn parse_script(script: &str) -> Result<Sub, ExecError> {
    let mut chars = script.chars();
    match chars.next() {
        None => return Err(ExecError::Fail(USAGE.to_string())),
        Some(c) if c != 's' => {
            return Err(ExecError::Fail(format!(
                "sed: unsupported command '{c}': only s/<pat>/<repl>/[g] is supported"
            )))
        }
        _ => {}
    }
    let delim = match chars.next() {
        Some(d) if !d.is_alphanumeric() && d != '\\' && !d.is_whitespace() => d,
        _ => {
            return Err(ExecError::Fail(
                "sed: invalid s command: expected a delimiter after 's' (e.g. s/a/b/g)".to_string(),
            ))
        }
    };
    let body = &script['s'.len_utf8() + delim.len_utf8()..];
    let fields = split_unescaped(body, delim);
    if fields.len() < 3 {
        return Err(ExecError::Fail(
            "sed: unterminated s command: expected s<delim>pat<delim>repl<delim>[flags]"
                .to_string(),
        ));
    }
    let flags = &fields[2];
    let mut global = false;
    for c in flags.chars() {
        match c {
            'g' => global = true,
            ';' | '\n' => {
                return Err(ExecError::Fail(
                    "sed: multi-command scripts are not supported: one s/// per invocation"
                        .to_string(),
                ))
            }
            other => {
                return Err(ExecError::Fail(format!(
                    "sed: unsupported flag '{other}' in s///: only 'g' is supported"
                )))
            }
        }
    }
    if fields.len() > 3 {
        return Err(ExecError::Fail(
            "sed: unexpected content after s/// flags (multi-command scripts are not supported)"
                .to_string(),
        ));
    }
    let pattern = regex::Regex::new(&format!("(?m){}", fields[0]))
        .map_err(|err| ExecError::Fail(format!("sed: invalid pattern: {err}")))?;
    Ok(Sub {
        pattern,
        repl: translate_repl(&fields[1]),
        global,
    })
}

fn split_unescaped(body: &str, delim: char) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut escaped = false;
    for c in body.chars() {
        if escaped {
            if c == delim {
                cur.push(c);
            } else {
                cur.push('\\');
                cur.push(c);
            }
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == delim {
            fields.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    if escaped {
        cur.push('\\');
    }
    fields.push(cur);
    fields
}

fn translate_repl(repl: &str) -> String {
    let mut out = String::with_capacity(repl.len());
    let mut chars = repl.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(d) if d.is_ascii_digit() => {
                    out.push('$');
                    out.push(d);
                }
                Some('&') => out.push('&'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            },
            '&' => out.push_str("$0"),
            '$' => out.push_str("$$"),
            other => out.push(other),
        }
    }
    out
}

fn apply(pattern: &regex::Regex, repl: &str, content: &str, global: bool) -> String {
    if global {
        pattern.replace_all(content, repl).into_owned()
    } else {
        let mut out = String::with_capacity(content.len());
        for line in content.split_inclusive('\n') {
            out.push_str(&pattern.replacen(line, 1, repl));
        }
        out
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
    fn sed_print_mode_outputs_transformed_content_and_keeps_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "foo bar foo\n").unwrap();
        let out = run_cmd(&dir, r#"sed "s/foo/baz/g" a.txt"#).unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "baz bar baz\n");
        assert_eq!(
            fs::read_to_string(dir.path().join("a.txt")).unwrap(),
            "foo bar foo\n"
        );
    }

    #[test]
    fn sed_in_place_rewrites_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "foo bar foo\n").unwrap();
        let out = run_cmd(&dir, r#"sed -i "s/foo/baz/g" a.txt"#).unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "");
        assert_eq!(
            fs::read_to_string(dir.path().join("a.txt")).unwrap(),
            "baz bar baz\n"
        );
    }

    #[test]
    fn sed_without_g_replaces_first_occurrence_per_line_only() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "a a\na a\n").unwrap();
        let out = run_cmd(&dir, r#"sed "s/a/b/" a.txt"#).unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "b a\nb a\n");
    }

    #[test]
    fn sed_anchors_are_per_line_like_real_sed() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "foo x\nbar foo\n").unwrap();
        let out = run_cmd(&dir, r#"sed "s/^foo/>/" a.txt"#).unwrap();
        assert_eq!(out.stdout, "> x\nbar foo\n");
    }

    #[test]
    fn sed_backreference_and_ampersand_in_replacement() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "foobar foo\n").unwrap();
        let out = run_cmd(&dir, r#"sed "s/(foo)(bar)/\2-\1/" a.txt"#).unwrap();
        assert_eq!(out.stdout, "bar-foo foo\n");
        let out = run_cmd(&dir, r#"sed "s/foo/[&]/g" a.txt"#).unwrap();
        assert_eq!(out.stdout, "[foo]bar [foo]\n");
    }

    #[test]
    fn sed_supports_custom_delimiter_and_escaped_delim() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "a/b c\n").unwrap();
        let out = run_cmd(&dir, r#"sed "s@a/b@X@g" a.txt"#).unwrap();
        assert_eq!(out.stdout, "X c\n");
        let out = run_cmd(&dir, r#"sed "s/a\/b/X/" a.txt"#).unwrap();
        assert_eq!(out.stdout, "X c\n");
    }

    #[test]
    fn sed_glob_targets_in_place() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        fs::write(dir.path().join("b.txt"), "x\n").unwrap();
        fs::write(dir.path().join("c.rs"), "x\n").unwrap();
        let out = run_cmd(&dir, r#"sed -i "s/x/y/g" *.txt"#).unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(fs::read_to_string(dir.path().join("a.txt")).unwrap(), "y\n");
        assert_eq!(fs::read_to_string(dir.path().join("b.txt")).unwrap(), "y\n");
        assert_eq!(fs::read_to_string(dir.path().join("c.rs")).unwrap(), "x\n");
    }

    #[test]
    fn sed_unsupported_flag_is_precise_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        let err = run_cmd(&dir, r#"sed "s/a/b/i" a.txt"#).unwrap_err();
        assert!(
            matches!(err, ExecError::Fail(ref m) if m.contains("unsupported flag 'i'") && m.contains("only 'g'"))
        );
    }

    #[test]
    fn sed_dangerous_flags_are_rejected_with_precise_message() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        for flag in ["w", "e", "p"] {
            let err = run_cmd(&dir, &format!(r#"sed "s/a/b/{flag}" a.txt"#)).unwrap_err();
            assert!(
                matches!(err, ExecError::Fail(ref m) if m.contains(&format!("unsupported flag '{flag}'"))),
                "flag {flag}: {err:?}"
            );
        }
    }

    #[test]
    fn sed_unsupported_command_letter_is_precise_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        let err = run_cmd(&dir, r#"sed "2d" a.txt"#).unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("unsupported command '2'")));
        let err = run_cmd(&dir, r#"sed "y/a/b/" a.txt"#).unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("unsupported command 'y'")));
    }

    #[test]
    fn sed_multi_command_script_is_precise_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        let err = run_cmd(&dir, r#"sed "s/a/b/;s/c/d/" a.txt"#).unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("multi-command")));
    }

    #[test]
    fn sed_unsupported_option_is_precise_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        for opt in ["-n", "-E", "-e", "--expression"] {
            let err = run_cmd(&dir, &format!(r#"sed "{opt}" "s/a/b/" a.txt"#)).unwrap_err();
            assert!(
                matches!(err, ExecError::Fail(ref m) if m.contains(&format!("unsupported option '{opt}'"))),
                "opt {opt}: {err:?}"
            );
        }
    }

    #[test]
    fn sed_without_path_outside_stream_position_is_rejected_at_parse() {
        for cmd in [
            "sed",
            r#"sed "s/a/b/""#,
            "sed -i",
            r#"sed "s/a/b/" | grep x"#,
            r#"sed -i "s/a/b/""#,
        ] {
            assert!(
                matches!(
                    parse_input(cmd, &HashMap::new()),
                    Err(crate::parse::ParseError::SedStreamNeedsPipe)
                ),
                "{cmd}"
            );
        }
    }

    #[test]
    fn sed_dash_i_and_sub_in_stream_position_are_rejected_at_parse() {
        assert!(matches!(
            parse_input(r#"cat a.txt | sed -i "s/a/b/" a.txt"#, &HashMap::new()),
            Err(crate::parse::ParseError::SedInPlaceInPipe)
        ));
        assert!(matches!(
            parse_input(r#"cat a.txt | sed -i "s/a/b/""#, &HashMap::new()),
            Err(crate::parse::ParseError::SedInPlaceInPipe)
        ));
        assert!(matches!(
            parse_input("cat a.txt | sub a b c.txt", &HashMap::new()),
            Err(crate::parse::ParseError::SubInPipe)
        ));
        assert!(parse_input(r#"cat a.txt | sed "s/a/b/""#, &HashMap::new()).is_ok());
        assert!(parse_input(r#"sed -i "s/a/b/" a.txt"#, &HashMap::new()).is_ok());
        assert!(parse_input("sub a b c.txt | grep x", &HashMap::new()).is_ok());
    }

    #[test]
    fn sed_in_place_without_path_stays_fail_closed_at_exec() {
        let dir = tempfile::tempdir().unwrap();
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
        let quota = std::sync::Arc::new(crate::sink::DiskQuota::new(
            ctx.limits.max_command_write_bytes,
        ));
        let cmd = crate::parse::SimpleCommand {
            argv: vec![
                crate::parse::Arg {
                    text: "sed".to_string(),
                    glob: false,
                },
                crate::parse::Arg {
                    text: "-i".to_string(),
                    glob: false,
                },
            ],
            redirects: vec![],
        };
        let err = super::run(&cmd, b"data", &ctx, &quota).unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("usage")));
    }

    #[test]
    fn sed_stream_transforms_pipe_input_and_keeps_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "foo bar foo\n").unwrap();
        let out = run_cmd(&dir, r#"cat a.txt | sed "s/foo/baz/g""#).unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "baz bar baz\n");
        assert_eq!(
            fs::read_to_string(dir.path().join("a.txt")).unwrap(),
            "foo bar foo\n"
        );
    }

    #[test]
    fn sed_stream_without_g_replaces_first_occurrence_per_line() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "a a\na a\n").unwrap();
        let out = run_cmd(&dir, r#"cat a.txt | sed "s/a/b/""#).unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "b a\nb a\n");
    }

    #[test]
    fn sed_stream_chains_with_other_pipe_stages() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "foo 1\nbar 2\nfoo 3\n").unwrap();
        let out = run_cmd(
            &dir,
            r#"cat a.txt | sed "s/foo/bar/g" | grep bar | tail -n 1"#,
        )
        .unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "(stdin):3:bar 3\n");
    }

    #[test]
    fn sed_stream_with_redirect_out_writes_via_file_sink() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "foo bar foo\n").unwrap();
        let out = run_cmd(&dir, r#"cat a.txt | sed "s/foo/baz/g" > out.txt"#).unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "");
        assert_eq!(
            fs::read_to_string(dir.path().join("out.txt")).unwrap(),
            "baz bar baz\n"
        );
    }

    #[test]
    fn sed_stream_redirect_in_overrides_pipe_input() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "aaa\n").unwrap();
        fs::write(dir.path().join("b.txt"), "bbb\n").unwrap();
        let out = run_cmd(&dir, r#"cat a.txt | sed "s/b/c/g" < b.txt"#).unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "ccc\n");
    }

    #[test]
    fn sed_stream_invalid_utf8_input_is_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("f.bin"), [0xff, 0xfe, b'a']).unwrap();
        let err = run_cmd(&dir, r#"cat f.bin | sed "s/a/b/""#).unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("not valid UTF-8")));
    }

    #[test]
    fn sed_stream_output_masks_secrets() {
        let dir = tempfile::tempdir().unwrap();
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
        let node = parse_input(
            r#"echo "key tok-abc123 end" | sed "s/key/value/""#,
            &HashMap::new(),
        )
        .unwrap();
        let out = execute(&node, &ctx).unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "value *** end\n");
    }

    #[test]
    fn sed_stream_redirect_to_sensitive_file_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "A=1\n").unwrap();
        fs::write(dir.path().join(".env"), "A=1\n").unwrap();
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
        let node = parse_input(r#"cat a.txt | sed "s/A/B/" > .env"#, &HashMap::new()).unwrap();
        assert!(matches!(execute(&node, &ctx), Err(ExecError::Denied(_))));
        assert_eq!(
            fs::read_to_string(dir.path().join(".env")).unwrap(),
            "A=1\n"
        );
    }

    #[test]
    fn sed_unterminated_script_is_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        let err = run_cmd(&dir, r#"sed "s/a/b" a.txt"#).unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("unterminated")));
    }

    #[test]
    fn sed_invalid_pattern_is_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        let err = run_cmd(&dir, r#"sed "s/[/x/" a.txt"#).unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("invalid pattern")));
    }

    #[test]
    fn sed_denies_escape_and_sensitive() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            run_cmd(&dir, r#"sed -i "s/a/b/" ../evil.txt"#).unwrap_err(),
            ExecError::Denied(_)
        ));
        fs::write(dir.path().join(".env"), "A=1\n").unwrap();
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
        let node = parse_input(r#"sed -i "s/A/B/" .env"#, &HashMap::new()).unwrap();
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
    fn sed_denies_oversized_file() {
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
        let node = parse_input(r#"sed "s/a/b/g" big.txt"#, &HashMap::new()).unwrap();
        assert!(matches!(
            execute(&node, &ctx).unwrap_err(),
            ExecError::Limit(_)
        ));
    }

    #[test]
    fn sed_missing_file_is_code_1_and_does_not_create() {
        let dir = tempfile::tempdir().unwrap();
        let out = run_cmd(&dir, r#"sed -i "s/a/b/g" nope.txt"#).unwrap();
        assert_eq!(out.code, 1);
        assert!(out.stderr.contains("nope.txt"));
        assert!(!dir.path().join("nope.txt").exists());
    }

    #[test]
    fn sed_print_mode_concatenates_multiple_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "foo\n").unwrap();
        fs::write(dir.path().join("b.txt"), "foo\n").unwrap();
        let out = run_cmd(&dir, r#"sed "s/foo/bar/g" a.txt b.txt"#).unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "bar\nbar\n");
    }
}
