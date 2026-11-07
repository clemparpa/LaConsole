use la_console::parse::{all_commands, has_glob, parse_input, pipe_has_trusted, ParseError};
use proptest::prelude::*;
use std::collections::HashMap;

fn no_vars() -> HashMap<String, String> {
    HashMap::new()
}

#[test]
fn pipe_never_contains_trusted() {
    assert!(matches!(
        parse_input("cat a | trusted x", &no_vars()),
        Err(ParseError::TrustedInPipe)
    ));
}

mod proptests {
    use super::*;

    proptest! {
        #[test]
        fn never_trusted_in_a_pipe(input in any::<String>()) {
            if let Ok(node) = parse_input(&input, &no_vars()) {
                prop_assert!(!pipe_has_trusted(&node), "trusted in pipe for {input:?}");
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
