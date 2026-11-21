use la_console::parse::{
    all_commands, has_glob, parse_input, pipe_has_misplaced_trusted, pipe_has_stream_forbidden,
    pipe_has_trusted, ParseError,
};
use proptest::prelude::*;
use std::collections::HashMap;

fn no_vars() -> HashMap<String, String> {
    HashMap::new()
}

#[test]
fn trusted_is_allowed_only_as_pipe_head() {
    assert!(matches!(
        parse_input("cat a | trusted x", &no_vars()),
        Err(ParseError::TrustedInPipe)
    ));
    assert!(matches!(
        parse_input("cat a | trusted x | cat b", &no_vars()),
        Err(ParseError::TrustedInPipe)
    ));
    assert!(matches!(
        parse_input("trusted a | trusted b", &no_vars()),
        Err(ParseError::TrustedInPipe)
    ));
    assert!(parse_input("trusted x | cat a", &no_vars()).is_ok());
}

#[test]
fn sed_without_path_is_only_allowed_in_stream_position() {
    for cmd in [
        "sed",
        r#"sed "s/a/b/""#,
        "sed -i",
        r#"sed -i "s/a/b/""#,
        r#"sed "s/a/b/" | grep x"#,
        r#"sed "s/a/b/" < f.txt"#,
    ] {
        assert!(
            matches!(
                parse_input(cmd, &no_vars()),
                Err(ParseError::SedStreamNeedsPipe)
            ),
            "{cmd}"
        );
    }
    assert!(parse_input(r#"cat x | sed "s/a/b/""#, &no_vars()).is_ok());
    assert!(parse_input(r#"cat x | sed "s/a/b/" | grep b"#, &no_vars()).is_ok());
    assert!(parse_input(r#"cat x | sed "s/a/b/" > out.txt"#, &no_vars()).is_ok());
    assert!(parse_input(r#"sed "s/a/b/" f.txt"#, &no_vars()).is_ok());
    assert!(parse_input(r#"sed -i "s/a/b/" f.txt"#, &no_vars()).is_ok());
    assert!(parse_input(r#"sed "s/a/b/" f.txt | grep x"#, &no_vars()).is_ok());
}

#[test]
fn tee_is_only_allowed_in_stream_position() {
    for cmd in [
        "tee out.txt",
        "tee out.txt | grep x",
        "tee out.txt < in.txt",
        "ls && tee out.txt",
    ] {
        assert!(
            matches!(parse_input(cmd, &no_vars()), Err(ParseError::TeeNeedsPipe)),
            "{cmd}"
        );
    }
    assert!(parse_input("cat a | tee out.txt", &no_vars()).is_ok());
    assert!(parse_input("cat a | tee out.txt | grep x", &no_vars()).is_ok());
    assert!(parse_input("cat a | tee out.txt > out2.txt", &no_vars()).is_ok());
    assert!(parse_input("cat a | tee out.txt < in.txt", &no_vars()).is_ok());
}

#[test]
fn sed_dash_i_and_sub_are_denied_in_stream_position() {
    assert!(matches!(
        parse_input(r#"cat x | sed -i "s/a/b/" f.txt"#, &no_vars()),
        Err(ParseError::SedInPlaceInPipe)
    ));
    assert!(matches!(
        parse_input(r#"cat x | sed -i "s/a/b/""#, &no_vars()),
        Err(ParseError::SedInPlaceInPipe)
    ));
    assert!(matches!(
        parse_input("cat x | sub a b f.txt", &no_vars()),
        Err(ParseError::SubInPipe)
    ));
    assert!(matches!(
        parse_input("cat x | sub a b", &no_vars()),
        Err(ParseError::SubInPipe)
    ));
    assert!(parse_input("sub a b f.txt | grep x", &no_vars()).is_ok());
    assert!(parse_input(r#"sed -i "s/a/b/" f.txt | grep x"#, &no_vars()).is_ok());
}

mod proptests {
    use super::*;

    proptest! {
        #[test]
        fn never_trusted_after_a_pipe_head(input in any::<String>()) {
            if let Ok(node) = parse_input(&input, &no_vars()) {
                prop_assert!(
                    !pipe_has_misplaced_trusted(&node),
                    "trusted after pipe head for {input:?}"
                );
            }
        }

        #[test]
        fn never_stream_forbidden_command(input in any::<String>()) {
            if let Ok(node) = parse_input(&input, &no_vars()) {
                prop_assert!(
                    !pipe_has_stream_forbidden(&node),
                    "sub/sed -i/tee misplaced in a pipe or path-less sed/tee outside stream for {input:?}"
                );
            }
        }

        #[test]
        fn never_sub_execution(input in any::<String>()) {
            if input.contains('`') {
                prop_assert!(
                    parse_input(&input, &no_vars()).is_err(),
                    "backticks accepted for {input:?}"
                );
            }
            if let Ok(node) = parse_input(&input, &no_vars()) {
                for cmd in all_commands(&node) {
                    for arg in &cmd.argv {
                        prop_assert!(!arg.text.contains('`'), "backtick in arg for {input:?}");
                        prop_assert!(!arg.text.contains("$("), "unresolved $( in arg for {input:?}");
                    }
                }
            }
        }

        #[test]
        fn parser_never_panics(input in any::<String>()) {
            let _ = parse_input(&input, &no_vars());
        }

        #[test]
        fn glob_args_are_flagged(input in any::<String>()) {
            if let Ok(node) = parse_input(&input, &no_vars()) {
                for cmd in all_commands(&node) {
                    for arg in &cmd.argv {
                        prop_assert_eq!(arg.glob, has_glob(&arg.text));
                    }
                }
            }
        }
    }
}

#[test]
fn fuzz_crash_escaped_backtick_in_double_quotes() {
    // Cas minimal : un backtick échappé dans des doubles quotes ne doit jamais
    // produire un arg contenant un backtick.
    assert!(matches!(
        parse_input("echo \"a\\`b\"", &no_vars()),
        Err(ParseError::Backticks)
    ));
    // Cas exact trouvé par le fuzzer (run nightly 42305933996) :
    // bytes [103,6,34,43,77,1,63,37,101,1,1,92,92,91,92,97,92,91,92,96,92,91,92,92,0,34]
    let bytes: &[u8] = &[
        103, 6, 34, 43, 77, 1, 63, 37, 101, 1, 1, 92, 92, 91, 92, 97, 92, 91, 92, 96, 92, 91, 92,
        92, 0, 34,
    ];
    let input: String = bytes.iter().map(|&b| b as char).collect();
    match parse_input(&input, &no_vars()) {
        Err(_) => {}
        Ok(node) => {
            for cmd in all_commands(&node) {
                for arg in &cmd.argv {
                    assert!(
                        !arg.text.contains('`') && !arg.text.contains("$("),
                        "sub-execution marker in arg for input {input:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn stray_paren_close_is_rejected() {
    assert!(matches!(
        parse_input("echo a)b", &no_vars()),
        Err(ParseError::SubshellParens)
    ));
}

#[test]
fn stray_brace_close_is_rejected() {
    assert!(matches!(
        parse_input("echo a}b", &no_vars()),
        Err(ParseError::UnexpectedOperator(_))
    ));
}

#[test]
fn backslash_outside_quotes_escapes_next_char() {
    let node = parse_input("echo a\\b c", &no_vars()).unwrap();
    let cmds = all_commands(&node);
    assert_eq!(cmds[0].argv.len(), 3);
    assert_eq!(cmds[0].argv[1].text, "ab");
    assert_eq!(cmds[0].argv[2].text, "c");
}

#[test]
fn backslash_is_literal_in_single_quotes() {
    let node = parse_input("echo 'a\\b'", &no_vars()).unwrap();
    let cmds = all_commands(&node);
    assert_eq!(cmds[0].argv[1].text, "a\\b");
}

#[test]
fn var_expands_inside_double_quotes() {
    let mut vars = no_vars();
    vars.insert("X".to_string(), "hello world".to_string());
    let node = parse_input("echo \"$X\"", &vars).unwrap();
    let cmds = all_commands(&node);
    assert_eq!(cmds[0].argv[1].text, "hello world");
}

#[test]
fn all_commands_collects_seq_and_pipe() {
    let node = parse_input("ls && cat a | grep b; echo done", &no_vars()).unwrap();
    let names: Vec<&str> = all_commands(&node)
        .iter()
        .map(|c| c.argv[0].text.as_str())
        .collect();
    assert_eq!(names, ["ls", "cat", "grep", "echo"]);
}

#[test]
fn pipe_has_trusted_flags_pipe_and_seq() {
    use la_console::parse::{Arg, Node, SimpleCommand};
    let trusted = || SimpleCommand {
        argv: vec![Arg {
            text: "trusted".to_string(),
            glob: false,
        }],
        redirects: vec![],
    };
    let plain = || SimpleCommand {
        argv: vec![Arg {
            text: "cat".to_string(),
            glob: false,
        }],
        redirects: vec![],
    };
    assert!(pipe_has_trusted(&Node::Pipe(vec![plain(), trusted()])));
    assert!(pipe_has_trusted(&Node::Seq(vec![Node::Pipe(vec![
        trusted()
    ])])));
    assert!(!pipe_has_trusted(&Node::Simple(trusted())));
    assert!(!pipe_has_trusted(&Node::Pipe(vec![plain(), plain()])));
}
