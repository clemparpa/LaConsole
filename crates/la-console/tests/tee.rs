//! Property-based invariants for `tee` (whitelist-expansion package E):
//! unknown options are never accepted, target paths containing `..` or
//! absolute outside the root are always `denied` (fail-closed, nothing is
//! created), and a successful `tee` always writes the exact input inside the
//! root while passing the stream through unchanged.

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
        std::fs::write(dir.path().join("a.txt"), b"data\n").unwrap();
        for line in [
            format!("cat a.txt | tee -{suffix} out.txt"),
            format!("cat a.txt | tee --{suffix} out.txt"),
            format!("cat a.txt | tee out.txt -{suffix}"),
        ] {
            prop_assert!(
                matches!(exec(&dir, &line), Err(ExecError::Fail(_))),
                "unknown option accepted: {line:?}"
            );
        }
    }

    #[test]
    fn escaping_or_absolute_target_is_always_denied(path in "(\\.\\./|/)[a-zA-Z0-9._/-]{0,24}") {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"data\n").unwrap();
        prop_assume!(
            !(path.starts_with('/') && path.starts_with(dir.path().to_str().unwrap()))
        );
        let line = format!("cat a.txt | tee {path}");
        prop_assert!(
            matches!(exec(&dir, &line), Err(ExecError::Denied(_))),
            "tee to escaping/absolute path accepted: {line:?}"
        );
    }

    #[test]
    fn successful_tee_writes_exact_input_inside_root_and_passes_through(path in "[a-zA-Z0-9._][a-zA-Z0-9._-]{0,15}\\.txt") {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"hello\n").unwrap();
        let line = format!("cat a.txt | tee {path}");
        let out = exec(&dir, &line).expect("tee in stream position must execute");
        prop_assert_eq!(out.code, 0, "tee failed for {:?}", path);
        prop_assert_eq!(out.stdout, "hello\n");
        prop_assert_eq!(
            std::fs::read(dir.path().join(&path)).unwrap(),
            b"hello\n",
            "tee file content mismatch for {:?}",
            path
        );
    }

    #[test]
    fn tee_never_accepts_a_glob_target(suffix in "[*?][a-zA-Z0-9.*?-]{0,10}") {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"data\n").unwrap();
        let line = format!("cat a.txt | tee {suffix}");
        prop_assert!(
            matches!(exec(&dir, &line), Err(ExecError::Fail(_))),
            "glob target accepted: {line:?}"
        );
    }
}
