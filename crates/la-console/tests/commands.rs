use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

fn session(root: &Path, extra_args: &[&str], cmds: &[&str]) -> Vec<serde_json::Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_la-console"))
        .arg("--root")
        .arg(root)
        .args(extra_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    for cmd in cmds {
        let line = format!(
            r#"{{"op": "exec", "cmd": {}}}"#,
            serde_json::to_string(cmd).unwrap()
        );
        writeln!(stdin, "{line}").unwrap();
    }
    stdin.flush().unwrap();
    drop(stdin);
    let mut responses = Vec::new();
    let mut line = String::new();
    while stdout.read_line(&mut line).unwrap() > 0 {
        responses.push(serde_json::from_str(&line).unwrap());
        line.clear();
    }
    assert!(child.wait().unwrap().success());
    responses
}

#[test]
fn e2e_cat_reads_file_within_root() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("hello.txt"), "bonjour\n").unwrap();
    let res = session(dir.path(), &[], &["cat hello.txt"]);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0]["ok"], true);
    assert_eq!(res[0]["code"], 0);
    assert_eq!(res[0]["stdout"], "bonjour\n");
    assert_eq!(res[0]["stderr"], "");
    assert_eq!(res[0]["truncated"], false);
}

#[test]
fn e2e_unknown_command_is_denied_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let res = session(dir.path(), &[], &["rm -rf /", "ls src", "trusted build"]);
    for resp in &res {
        assert_eq!(resp["ok"], false);
        assert_eq!(resp["code"], 2);
        assert_eq!(resp["stdout"], "");
        assert!(resp["stderr"].as_str().unwrap().starts_with("denied:"));
        assert_eq!(resp["truncated"], false);
    }
}

#[test]
fn e2e_cat_path_evasion_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("ok.txt"), "ok").unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret.txt"), "secret").unwrap();
    let res = session(
        dir.path(),
        &[],
        &[
            "cat ../secret.txt",
            "cat /etc/passwd",
            "cat ok.txt/../../secret.txt",
            "cat sub/../ok.txt",
            "cat ./ok.txt && cat ok.txt",
        ],
    );
    assert_eq!(res[0]["ok"], false);
    assert_eq!(res[0]["code"], 2);
    assert!(res[0]["stderr"].as_str().unwrap().starts_with("denied:"));
    assert_eq!(res[1]["code"], 2);
    assert_eq!(res[2]["code"], 2);
    assert_eq!(res[3]["code"], 2);
    assert_eq!(res[4]["ok"], true);
    assert_eq!(res[4]["stdout"], "okok");
}

#[test]
fn e2e_cat_missing_file_returns_code_1() {
    let dir = tempfile::tempdir().unwrap();
    let res = session(dir.path(), &[], &["cat nope.txt"]);
    assert_eq!(res[0]["ok"], false);
    assert_eq!(res[0]["code"], 1);
    assert!(res[0]["stderr"].as_str().unwrap().contains("nope.txt"));
}

#[test]
fn e2e_cat_glob_and_sequence_and_pipe() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "A").unwrap();
    std::fs::write(dir.path().join("b.txt"), "B").unwrap();
    std::fs::write(dir.path().join("c.rs"), "C").unwrap();
    let res = session(
        dir.path(),
        &[],
        &["cat *.txt", "cat a.txt && cat b.txt", "cat a.txt | cat"],
    );
    assert_eq!(res[0]["stdout"], "AB");
    assert_eq!(res[1]["stdout"], "AB");
    assert_eq!(res[2]["stdout"], "A");
    assert!(res.iter().all(|r| r["ok"] == true));
}

#[test]
fn e2e_redirect_writes_within_root_only() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("in.txt"), "data").unwrap();
    let res = session(
        dir.path(),
        &[],
        &[
            "cat in.txt > out.txt",
            "cat out.txt",
            "cat in.txt > ../evil.txt",
        ],
    );
    assert_eq!(res[0]["ok"], true);
    assert_eq!(res[0]["stdout"], "");
    assert_eq!(res[1]["stdout"], "data");
    assert_eq!(res[2]["ok"], false);
    assert_eq!(res[2]["code"], 2);
    assert!(!dir.path().parent().unwrap().join("evil.txt").exists());
}

#[test]
fn e2e_sensitive_file_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".env"), "KEY=1").unwrap();
    let cfg = tempfile::tempdir().unwrap();
    let cfg_path = cfg.path().join("sensibles.txt");
    std::fs::write(&cfg_path, ".*\\.env$\n").unwrap();
    let res = session(
        dir.path(),
        &["--sensitives-file", cfg_path.to_str().unwrap()],
        &["cat .env", "cat .env > copy.txt"],
    );
    assert_eq!(res[0]["ok"], false);
    assert_eq!(res[0]["code"], 2);
    assert!(res[0]["stderr"].as_str().unwrap().contains("sensitive"));
    assert_eq!(res[1]["code"], 2);
    let copy = std::fs::read_to_string(dir.path().join("copy.txt")).unwrap_or_default();
    assert!(!copy.contains("KEY=1"));
}

#[test]
fn e2e_output_truncation_is_flagged() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("big.txt"), "0123456789ABCDEF").unwrap();
    let res = session(dir.path(), &["--max-output-bytes", "10"], &["cat big.txt"]);
    assert_eq!(res[0]["ok"], true);
    assert_eq!(res[0]["truncated"], true);
    assert_eq!(res[0]["stdout"].as_str().unwrap().len(), 10);
}
