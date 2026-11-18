//! Property-based invariants for the `json` extractor (whitelist-expansion
//! package D): unknown options are never accepted, random selectors and random
//! JSON inputs never panic and a successful extraction always emits valid
//! JSON, and random path operands never yield a successful read outside the
//! root.

use la_console::commands::{execute, Ctx, ExecError, Limits};
use la_console::parse::parse_input;
use la_console::resolve::Resolver;
use proptest::prelude::*;
use std::collections::HashMap;

fn ctx_for(dir: &tempfile::TempDir) -> Ctx {
    Ctx {
        resolver: Resolver::new(dir.path()).unwrap(),
        sensibles: vec![],
        secrets: vec![],
        limits: Limits::default(),
        trusted: None,
        sandboxed: false,
        sandbox_shell: None,
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
    fn unknown_option_is_never_accepted(suffix in "[a-zA-Z0-9-]{0,8}") {
        let dir = tempfile::tempdir().unwrap();
        for line in [format!("json -{suffix} a"), format!("json --{suffix} a")] {
            prop_assert!(
                matches!(exec(&dir, &line), Err(ExecError::Fail(_))),
                "unknown option accepted: {line:?}"
            );
        }
    }

    #[test]
    fn random_selector_never_panics_and_success_emits_valid_json(selector in "[a-zA-Z0-9.\\[\\]_-]{0,40}") {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("data.json"),
            r#"{"body":{"items":[{"name":"first"}],"n":3},"ok":true}"#,
        )
        .unwrap();
        let line = format!("json \"{selector}\" data.json");
        if let Ok(out) = exec(&dir, &line) {
            if out.code == 0 && !out.truncated {
                prop_assert!(
                    serde_json::from_str::<serde_json::Value>(out.stdout.trim_end()).is_ok(),
                    "non-JSON stdout for selector {selector:?}: {:?}",
                    out.stdout
                );
            }
        }
    }

    #[test]
    fn random_json_input_never_panics_and_success_emits_valid_json(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("f.json"), &bytes).unwrap();
        if let Ok(out) = exec(&dir, "json a.b[0] f.json") {
            if out.code == 0 && !out.truncated {
                prop_assert!(
                    serde_json::from_str::<serde_json::Value>(out.stdout.trim_end()).is_ok(),
                    "non-JSON stdout for input {bytes:?}: {:?}",
                    out.stdout
                );
            }
        }
    }

    #[test]
    fn random_path_operand_never_succeeds_in_empty_root(path in "[a-zA-Z0-9._/-]{1,24}") {
        let dir = tempfile::tempdir().unwrap();
        let line = format!("json a {path}");
        if let Ok(node) = parse_input(&line, &HashMap::new()) {
            if let Ok(out) = execute(&node, &ctx_for(&dir)) {
                prop_assert!(
                    out.code != 0,
                    "json succeeded with path {path:?} in an empty root"
                );
            }
        }
    }
}
