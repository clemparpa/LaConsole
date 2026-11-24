//! Property-based invariants for the stream filters (whitelist-expansion
//! package B): unknown options are never accepted, random path operands never
//! yield a successful read outside the root, and invalid UTF-8 is always a
//! `fail`.

use la_console::commands::{execute, Ctx, ExecError, Limits};
use la_console::parse::parse_input;
use la_console::resolve::Resolver;
use proptest::prelude::*;
use std::collections::HashMap;

const FILTERS: [&str; 7] = ["head", "tail", "wc", "sort", "uniq", "cut", "tr"];

fn ctx_for(dir: &tempfile::TempDir) -> Ctx {
    Ctx {
        resolver: Resolver::new(dir.path()).unwrap(),
        sensibles: vec![],
        secrets: vec![],
        limits: Limits::default(),
        trusted: None,
    }
}

fn exec(
    dir: &tempfile::TempDir,
    line: &str,
) -> Result<la_console::commands::ExecOutcome, ExecError> {
    let node = parse_input(line, &HashMap::new()).unwrap();
    execute(&node, &ctx_for(dir))
}

proptest! {
    #[test]
    fn unknown_short_option_is_never_accepted(suffix in "[a-z0-9]{0,6}") {
        let dir = tempfile::tempdir().unwrap();
        for cmd in FILTERS {
            let line = format!("{cmd} -q{suffix}");
            prop_assert!(
                matches!(exec(&dir, &line), Err(ExecError::Fail(_))),
                "unknown option accepted: {line:?}"
            );
        }
    }

    #[test]
    fn unknown_long_option_is_never_accepted(suffix in "[a-z]{2,9}") {
        let dir = tempfile::tempdir().unwrap();
        for cmd in FILTERS {
            let line = format!("{cmd} --q{suffix}");
            prop_assert!(
                matches!(exec(&dir, &line), Err(ExecError::Fail(_))),
                "unknown long option accepted: {line:?}"
            );
        }
    }

    #[test]
    fn random_path_operand_never_succeeds_in_empty_root(path in "[a-zA-Z0-9._/][a-zA-Z0-9._/-]{0,23}") {
        // Empty root: any path operand must be denied or fail (missing file),
        // never a successful read. The first char cannot be '-': a leading
        // dash is an option, not a path operand (regression: the old generator
        // could produce "-r", a valid flag of `sort`).
        let dir = tempfile::tempdir().unwrap();
        for cmd in FILTERS {
            let line = format!("{cmd} {path}");
            if let Ok(node) = parse_input(&line, &HashMap::new()) {
                if let Ok(out) = execute(&node, &ctx_for(&dir)) {
                    prop_assert!(
                        out.code != 0,
                        "filter {cmd} succeeded with path {path:?} in an empty root"
                    );
                }
            }
        }
    }

    #[test]
    fn invalid_utf8_input_is_always_a_fail(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("f.bin"), &bytes).unwrap();
        if String::from_utf8(bytes.clone()).is_err() {
            for cmd in ["head f.bin", "tail f.bin", "wc f.bin", "sort f.bin", "uniq f.bin", "cut -d: -f1 f.bin", "tr a b f.bin"] {
                prop_assert!(
                    matches!(exec(&dir, cmd), Err(ExecError::Fail(_))),
                    "invalid UTF-8 accepted by {cmd}"
                );
            }
        }
    }
}

#[test]
fn leading_dash_is_an_option_not_a_path_operand() {
    // Deterministic regression for the flaky proptest above: `sort -r`
    // parses `-r` as a flag, reads the (empty) stdin and succeeds — that
    // is correct behavior, so the random generator must never produce a
    // leading '-' as a "path".
    let dir = tempfile::tempdir().unwrap();
    let node = parse_input("sort -r", &HashMap::new()).unwrap();
    let la_console::parse::Node::Simple(ref cmd) = node else {
        panic!("expected simple command");
    };
    assert!(cmd.argv[1..].iter().all(|a| a.text.starts_with('-')));
    let out = execute(&node, &ctx_for(&dir)).unwrap();
    assert_eq!(out.code, 0);
}
