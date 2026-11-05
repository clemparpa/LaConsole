use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};

struct Session {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<std::process::ChildStdout>,
}

impl Session {
    fn spawn(root: &std::path::Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_la-console"))
            .arg("--root")
            .arg(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
        }
    }

    fn send(&mut self, cmd: &str) -> serde_json::Value {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(
            stdin,
            r#"{{"op": "exec", "cmd": {}}}"#,
            serde_json::to_string(cmd).unwrap()
        )
        .unwrap();
        stdin.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.wait();
    }
}

#[test]
fn e2e_cat_reads_file_within_root() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("hello.txt"), "hello\n").unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send("cat hello.txt");
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["code"], 0);
    assert_eq!(resp["stdout"], "hello\n");
    assert_eq!(resp["stderr"], "");
    assert_eq!(resp["truncated"], false);
}

#[test]
fn e2e_cat_denies_path_escape() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send("cat ../../etc/passwd");
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 2);
    assert!(resp["stderr"].as_str().unwrap().starts_with("denied:"));
}

#[test]
fn e2e_cat_missing_file_returns_code_1() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send("cat nope.txt");
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 1);
    assert!(resp["stderr"].as_str().unwrap().contains("nope.txt"));
}

#[test]
fn e2e_unknown_command_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send("rm -rf /");
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 2);
    assert!(resp["stderr"].as_str().unwrap().contains("unknown command"));
}

#[test]
fn e2e_seq_chains_cat_commands() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "A").unwrap();
    std::fs::write(dir.path().join("b.txt"), "B").unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send("cat a.txt && cat b.txt");
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["stdout"], "B");
    let resp = session.send("cat missing.txt && cat b.txt");
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 1);
}

#[test]
fn e2e_redirect_roundtrip_through_file_sink() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("in.txt"), "payload\n").unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send("cat in.txt > out.txt");
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["stdout"], "");
    let resp = session.send("cat out.txt");
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["stdout"], "payload\n");
}

#[test]
fn e2e_ls_lists_root_and_subdir() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("b.txt"), "").unwrap();
    std::fs::write(dir.path().join("a.txt"), "").unwrap();
    std::fs::create_dir(dir.path().join("src")).unwrap();
    std::fs::write(dir.path().join("src/x.rs"), "").unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send("ls");
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["code"], 0);
    assert_eq!(resp["stdout"], "a.txt\nb.txt\nsrc\n");
    let resp = session.send("ls src");
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["stdout"], "x.rs\n");
}

#[test]
fn e2e_ls_all_lists_hidden_and_ignored() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("keep.txt"), "").unwrap();
    std::fs::write(dir.path().join(".hidden"), "").unwrap();
    std::fs::write(dir.path().join("target.log"), "").unwrap();
    std::fs::write(dir.path().join(".gitignore"), "target.log\n").unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send("ls");
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["stdout"], "keep.txt\n");
    let resp = session.send("ls --all");
    assert_eq!(resp["ok"], true);
    let stdout = resp["stdout"].as_str().unwrap();
    assert!(stdout.contains(".hidden"));
    assert!(stdout.contains("target.log"));
    assert!(stdout.contains("keep.txt"));
}

#[test]
fn e2e_ls_denies_escape_and_missing() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send("ls ..");
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 2);
    assert!(resp["stderr"].as_str().unwrap().starts_with("denied:"));
    let resp = session.send("ls /etc");
    assert_eq!(resp["code"], 2);
    let resp = session.send("ls nope");
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 1);
    assert!(resp["stderr"].as_str().unwrap().contains("nope"));
}

#[test]
fn e2e_echo_prints_text() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send("echo hello la-console");
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["code"], 0);
    assert_eq!(resp["stdout"], "hello la-console\n");
    let resp = session.send("echo *.txt");
    assert_eq!(resp["stdout"], "*.txt\n");
}

#[test]
fn e2e_echo_redirect_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send("echo payload > out.txt");
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["stdout"], "");
    let resp = session.send("cat out.txt");
    assert_eq!(resp["stdout"], "payload\n");
    let resp = session.send("echo more >> out.txt");
    assert_eq!(resp["ok"], true);
    let resp = session.send("cat out.txt");
    assert_eq!(resp["stdout"], "payload\nmore\n");
}

#[test]
fn e2e_echo_redirect_escape_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send("echo x > ../evil.txt");
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 2);
    assert!(resp["stderr"].as_str().unwrap().starts_with("denied:"));
    assert!(!dir.path().parent().unwrap().join("evil.txt").exists());
}
