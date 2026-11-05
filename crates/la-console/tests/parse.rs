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
