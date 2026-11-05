use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn e2e_json_line_protocol() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_la-console"))
        .arg("--root")
        .arg(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(stdin, r#"{{"op": "exec", "cmd": "rm -rf /"}}"#).unwrap();
    writeln!(stdin, "ceci n'est pas du JSON").unwrap();
    stdin.flush().unwrap();

    for _ in 0..2 {
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(resp["ok"], false);
        assert_eq!(resp["code"], 2);
        assert!(resp["stdout"].is_string());
        assert!(resp["stderr"].is_string());
        assert_eq!(resp["truncated"], false);
    }

    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[test]
fn e2e_rejects_sub_execution_at_parse_time() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_la-console"))
        .arg("--root")
        .arg(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(stdin, r#"{{"op": "exec", "cmd": "ls `rm -rf /`"}}"#).unwrap();
    writeln!(stdin, r#"{{"op": "exec", "cmd": "cat a | trusted build"}}"#).unwrap();
    stdin.flush().unwrap();

    for _ in 0..2 {
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(resp["ok"], false);
        assert_eq!(resp["code"], 2);
        assert!(resp["stderr"].as_str().unwrap().starts_with("denied:"));
    }

    drop(stdin);
    assert!(child.wait().unwrap().success());
}
