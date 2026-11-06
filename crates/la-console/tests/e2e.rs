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

struct TrustedFixture {
    root: tempfile::TempDir,
    _trusted_dir: tempfile::TempDir,
    trusted_file: std::path::PathBuf,
    sha256: String,
}

fn trusted_fixture(content: &str) -> TrustedFixture {
    let root = tempfile::tempdir().unwrap();
    let trusted_dir = tempfile::tempdir().unwrap();
    let trusted_file = trusted_dir.path().join("trusted.txt");
    std::fs::write(&trusted_file, content).unwrap();
    let sha256 = la_console::trusted::sha256_hex(content.as_bytes());
    TrustedFixture {
        root,
        _trusted_dir: trusted_dir,
        trusted_file,
        sha256,
    }
}

fn spawn_console(fx: &TrustedFixture, sha: &str) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_la-console"))
        .arg("--root")
        .arg(fx.root.path())
        .arg("--trusted-file")
        .arg(&fx.trusted_file)
        .arg("--trusted-sha256")
        .arg(sha)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap()
}

#[test]
fn e2e_trusted_executes_with_valid_checksum() {
    let fx = trusted_fixture("hello = echo hi-from-trusted\n");
    let mut child = spawn_console(&fx, &fx.sha256);
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(stdin, r#"{{"op": "exec", "cmd": "trusted hello"}}"#).unwrap();
    writeln!(stdin, r#"{{"op": "exec", "cmd": "trusted unknown-name"}}"#).unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["code"], 0);
    assert_eq!(resp["stdout"], "hi-from-trusted\n");

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 2);
    assert!(resp["stderr"]
        .as_str()
        .unwrap()
        .contains("unknown trusted command"));

    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[test]
fn e2e_trusted_denied_on_checksum_mismatch() {
    let fx = trusted_fixture("hello = echo hi\n");
    let bad_sha = "00".repeat(32);
    let mut child = spawn_console(&fx, &bad_sha);
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(stdin, r#"{{"op": "exec", "cmd": "trusted hello"}}"#).unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 2);
    assert!(resp["stderr"].as_str().unwrap().contains("checksum"));

    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[test]
fn e2e_trusted_denied_when_not_configured() {
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

    writeln!(stdin, r#"{{"op": "exec", "cmd": "trusted build"}}"#).unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 2);
    assert!(resp["stderr"].as_str().unwrap().contains("not configured"));

    drop(stdin);
    assert!(child.wait().unwrap().success());
}
