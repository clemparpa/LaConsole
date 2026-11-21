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
        assert_eq!(resp["kind"], "denied");
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

fn trusted_toml_fixture(content: &str) -> TrustedFixture {
    let root = tempfile::tempdir().unwrap();
    let trusted_dir = tempfile::tempdir().unwrap();
    let trusted_file = trusted_dir.path().join("trusted.toml");
    std::fs::write(&trusted_file, content).unwrap();
    let sha256 = la_console::trusted::sha256_hex(content.as_bytes());
    TrustedFixture {
        root,
        _trusted_dir: trusted_dir,
        trusted_file,
        sha256,
    }
}

#[test]
fn e2e_trusted_toml_executes_with_valid_checksum() {
    let fx = trusted_toml_fixture("[commands.hello]\ncommand = \"echo hi-from-toml\"\n");
    let mut child = spawn_console(&fx, &fx.sha256);
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(stdin, r#"{{"op": "exec", "cmd": "trusted hello"}}"#).unwrap();
    writeln!(stdin, r#"{{"op": "exec", "cmd": "help"}}"#).unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["code"], 0);
    assert_eq!(resp["stdout"], "hi-from-toml\n");

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], true);
    assert!(resp["stdout"]
        .as_str()
        .unwrap()
        .contains("hello = echo hi-from-toml"));

    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[test]
fn e2e_trusted_toml_denied_on_checksum_mismatch() {
    let fx = trusted_toml_fixture("[commands.hello]\ncommand = \"echo hi\"\n");
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
fn e2e_trusted_toml_backend_limit_denied_without_backend() {
    let fx =
        trusted_toml_fixture("[commands.build]\ncommand = \"true\"\nmax_write_bytes = 1048576\n");
    let mut child = spawn_console(&fx, &fx.sha256);
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(stdin, r#"{{"op": "exec", "cmd": "trusted build"}}"#).unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 2);
    assert_eq!(resp["kind"], "denied");
    let stderr = resp["stderr"].as_str().unwrap();
    assert!(stderr.contains("max_write_bytes"), "got: {stderr}");
    assert!(stderr.contains("fail-closed"), "got: {stderr}");

    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[test]
fn e2e_trusted_toml_entry_timeout_overrides_global() {
    let fx = trusted_toml_fixture("[commands.slow]\ncommand = \"sleep 30\"\ntimeout_secs = 1\n");
    let mut child = Command::new(env!("CARGO_BIN_EXE_la-console"))
        .arg("--root")
        .arg(fx.root.path())
        .arg("--timeout-secs")
        .arg("30")
        .arg("--trusted-file")
        .arg(&fx.trusted_file)
        .arg("--trusted-sha256")
        .arg(&fx.sha256)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(stdin, r#"{{"op": "exec", "cmd": "trusted slow"}}"#).unwrap();
    stdin.flush().unwrap();

    let start = std::time::Instant::now();
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 3);
    assert_eq!(resp["kind"], "limit");
    assert!(resp["stderr"]
        .as_str()
        .unwrap()
        .contains("timed out after 1s"));
    assert!(start.elapsed() < std::time::Duration::from_secs(10));

    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[test]
fn e2e_trusted_as_pipe_head_pipes_into_whitelist() {
    let fx = trusted_fixture("lines = printf 'alpha\\nbeta\\ngamma\\n'\n");
    let mut child = spawn_console(&fx, &fx.sha256);
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(
        stdin,
        r#"{{"op": "exec", "cmd": "trusted lines | grep beta"}}"#
    )
    .unwrap();
    writeln!(
        stdin,
        r#"{{"op": "exec", "cmd": "trusted lines | grep beta > out.txt"}}"#
    )
    .unwrap();
    writeln!(
        stdin,
        r#"{{"op": "exec", "cmd": "cat a.txt | trusted lines"}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["code"], 0);
    assert_eq!(resp["stdout"], "(stdin):2:beta\n");

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["code"], 0);
    assert_eq!(resp["stdout"], "");

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 2);
    assert_eq!(resp["kind"], "denied");
    assert!(resp["stderr"].as_str().unwrap().contains("pipe"));

    drop(stdin);
    assert!(child.wait().unwrap().success());
    assert_eq!(
        std::fs::read_to_string(fx.root.path().join("out.txt")).unwrap(),
        "(stdin):2:beta\n"
    );
}

#[test]
fn e2e_sed_on_stream_in_pipe() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("app.log"),
        "INFO start\nERROR boom\nINFO end\n",
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_la-console"))
        .arg("--root")
        .arg(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    let cmds = [
        r#"cat app.log | sed "s/ERROR/FATAL/" | grep FATAL"#,
        r#"cat app.log | sed "s/ERROR/FATAL/" > out.txt"#,
        "cat out.txt",
        r#"cat app.log | sed -i "s/ERROR/FATAL/" app.log"#,
        "cat app.log | sub ERROR FATAL app.log",
        r#"sed "s/a/b/""#,
        r#"sed "s/a/b/" | grep x"#,
    ];
    for cmd in cmds {
        writeln!(
            stdin,
            r#"{{"op": "exec", "cmd": {}}}"#,
            serde_json::to_string(cmd).unwrap()
        )
        .unwrap();
    }
    stdin.flush().unwrap();

    let mut next = || {
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        serde_json::from_str::<serde_json::Value>(&line).unwrap()
    };

    let resp = next();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["code"], 0);
    assert_eq!(resp["stdout"], "(stdin):2:FATAL boom\n");

    let resp = next();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["stdout"], "");

    let resp = next();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["stdout"], "INFO start\nFATAL boom\nINFO end\n");

    for _ in 0..4 {
        let resp = next();
        assert_eq!(resp["ok"], false);
        assert_eq!(resp["code"], 2);
        assert_eq!(resp["kind"], "denied");
    }

    drop(stdin);
    assert!(child.wait().unwrap().success());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("app.log")).unwrap(),
        "INFO start\nERROR boom\nINFO end\n"
    );
}

#[test]
fn e2e_tee_copies_stream_to_file_in_pipe() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("app.log"),
        "INFO start\nERROR boom\nINFO end\n",
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_la-console"))
        .arg("--root")
        .arg(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    let cmds = [
        r#"cat app.log | tee copy.txt | grep ERROR"#,
        r#"cat app.log | tee c2.txt > c3.txt"#,
        "cat copy.txt",
        "tee x.txt",
        r#"cat app.log | tee ../evil.txt"#,
        r#"cat app.log | tee -a out.txt"#,
    ];
    for cmd in cmds {
        writeln!(
            stdin,
            r#"{{"op": "exec", "cmd": {}}}"#,
            serde_json::to_string(cmd).unwrap()
        )
        .unwrap();
    }
    stdin.flush().unwrap();

    let mut next = || {
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        serde_json::from_str::<serde_json::Value>(&line).unwrap()
    };

    let resp = next();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["code"], 0);
    assert_eq!(resp["stdout"], "(stdin):2:ERROR boom\n");

    let resp = next();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["stdout"], "");

    let resp = next();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["stdout"], "INFO start\nERROR boom\nINFO end\n");

    // tee alone (no pipe): denied at parse
    let resp = next();
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 2);
    assert_eq!(resp["kind"], "denied");

    // tee to an escaping path: denied, nothing created outside the root
    let resp = next();
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 2);
    assert_eq!(resp["kind"], "denied");

    // tee with an unknown option: fail (code 1)
    let resp = next();
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 1);
    assert_eq!(resp["kind"], "fail");

    drop(stdin);
    assert!(child.wait().unwrap().success());
    let expected = "INFO start\nERROR boom\nINFO end\n";
    assert_eq!(
        std::fs::read_to_string(dir.path().join("copy.txt")).unwrap(),
        expected
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("c2.txt")).unwrap(),
        expected
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("c3.txt")).unwrap(),
        expected
    );
    assert!(!dir.path().join("x.txt").exists());
    assert!(!dir.path().parent().unwrap().join("evil.txt").exists());
    assert!(!dir.path().join("out.txt").exists());
}

#[test]
fn e2e_max_output_bytes_truncates_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_la-console"))
        .arg("--root")
        .arg(dir.path())
        .arg("--max-output-bytes")
        .arg("10")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(
        stdin,
        r#"{{"op": "exec", "cmd": "echo hello world this is long"}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["truncated"], true);
    assert!(resp["stdout"].as_str().unwrap().len() <= 10);

    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[test]
fn e2e_help_lists_append_syntax() {
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

    writeln!(stdin, r#"{{"op": "exec", "cmd": "help echo"}}"#).unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], true);
    let out = resp["stdout"].as_str().unwrap();
    assert!(
        out.contains("echo <text> >> <path>"),
        "help echo missing >> syntax: {out}"
    );

    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[test]
fn e2e_stdin_redirect_feeds_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("in.txt"), "hello from file\n").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_la-console"))
        .arg("--root")
        .arg(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(stdin, r#"{{"op": "exec", "cmd": "cat < in.txt"}}"#).unwrap();
    writeln!(stdin, r#"{{"op": "exec", "cmd": "cat < ../outside.txt"}}"#).unwrap();
    writeln!(stdin, r#"{{"op": "exec", "cmd": "grep from < in.txt"}}"#).unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["stdout"], "hello from file\n");

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 2);
    assert_eq!(resp["kind"], "denied");

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], true);
    assert!(resp["stdout"].as_str().unwrap().contains("hello from file"));

    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn e2e_server_mode_is_refused_off_linux() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_la-console"))
        .arg("--root")
        .arg(dir.path())
        .arg("--mode")
        .arg("server")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires Linux"), "stderr: {stderr}");
}

#[cfg(target_os = "linux")]
fn unshare_works() -> bool {
    Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--root",
            "/",
            "--wd",
            "/",
        ])
        .arg("/bin/true")
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_server_mode_runs_inside_chroot() {
    if !unshare_works() {
        eprintln!("skipping: unprivileged user namespaces unavailable in this environment");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("hello.txt"), "hello-from-cage\n").unwrap();
    std::fs::write(
        dir.path().parent().unwrap().join("outside-secret.txt"),
        "topsecret\n",
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_la-console"))
        .arg("--root")
        .arg(dir.path())
        .arg("--mode")
        .arg("server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(stdin, r#"{{"op": "exec", "cmd": "cat hello.txt"}}"#).unwrap();
    writeln!(
        stdin,
        r#"{{"op": "exec", "cmd": "cat ../outside-secret.txt"}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["stdout"], "hello-from-cage\n");

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 2);
    assert_eq!(resp["kind"], "denied");

    drop(stdin);
    assert!(child.wait().unwrap().success());
}

/// Finds a statically linked busybox on the host (env override
/// `LA_CONSOLE_TEST_BUSYBOX` first), or `None` when unavailable.
#[cfg(target_os = "linux")]
fn find_static_busybox() -> Option<std::path::PathBuf> {
    use std::path::PathBuf;
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = std::env::var_os("LA_CONSOLE_TEST_BUSYBOX") {
        candidates.push(PathBuf::from(p));
    }
    if let Ok(p) = std::env::var("PATH") {
        for dir in p.split(':') {
            candidates.push(PathBuf::from(dir).join("busybox"));
        }
    }
    candidates.extend(
        [
            "/bin/busybox",
            "/usr/bin/busybox",
            "/sbin/busybox",
            "/usr/sbin/busybox",
        ]
        .iter()
        .map(PathBuf::from),
    );
    candidates.into_iter().find(|c| {
        if !c.is_file() {
            return false;
        }
        let Ok(out) = Command::new("ldd").arg(c).output() else {
            return false;
        };
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        text.contains("not a dynamic executable")
    })
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_server_mode_stages_tools_dir_into_cage() {
    if !unshare_works() {
        eprintln!("skipping: unprivileged user namespaces unavailable in this environment");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let tools = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tools.path().join("bin")).unwrap();
    std::fs::write(tools.path().join("bin/mytool"), b"#!/bin/sh\necho tool\n").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_la-console"))
        .arg("--root")
        .arg(dir.path())
        .arg("--mode")
        .arg("server")
        .arg("--sandbox-tools-dir")
        .arg(tools.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(
        stdin,
        r#"{{"op": "exec", "cmd": "ls opt/la-console-tools/bin"}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], true);
    assert!(
        resp["stdout"].as_str().unwrap().contains("mytool"),
        "stdout: {}",
        resp["stdout"]
    );

    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_server_mode_trusted_runs_through_staged_busybox() {
    if !unshare_works() {
        eprintln!("skipping: unprivileged user namespaces unavailable in this environment");
        return;
    }
    let Some(busybox) = find_static_busybox() else {
        eprintln!("skipping: no statically linked busybox found on this host");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let content = "hello = echo hi-from-busybox\n";
    std::fs::write(dir.path().join("trusted.txt"), content).unwrap();
    let sha = la_console::trusted::sha256_hex(content.as_bytes());
    let mut child = Command::new(env!("CARGO_BIN_EXE_la-console"))
        .arg("--root")
        .arg(dir.path())
        .arg("--mode")
        .arg("server")
        .arg("--sandbox-busybox")
        .arg(&busybox)
        .arg("--trusted-file")
        .arg("trusted.txt")
        .arg("--trusted-sha256")
        .arg(&sha)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(stdin, r#"{{"op": "exec", "cmd": "trusted hello"}}"#).unwrap();
    writeln!(
        stdin,
        r#"{{"op": "exec", "cmd": "cat ../outside-secret.txt"}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], true, "resp: {resp}");
    assert_eq!(resp["stdout"], "hi-from-busybox\n");

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 2);
    assert_eq!(resp["kind"], "denied");

    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_server_mode_denies_trusted() {
    if !unshare_works() {
        eprintln!("skipping: unprivileged user namespaces unavailable in this environment");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let content = "hello = echo hi\n";
    std::fs::write(dir.path().join("trusted.txt"), content).unwrap();
    let sha = la_console::trusted::sha256_hex(content.as_bytes());
    let mut child = Command::new(env!("CARGO_BIN_EXE_la-console"))
        .arg("--root")
        .arg(dir.path())
        .arg("--mode")
        .arg("server")
        .arg("--trusted-file")
        .arg("trusted.txt")
        .arg("--trusted-sha256")
        .arg(&sha)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(stdin, r#"{{"op": "exec", "cmd": "trusted hello"}}"#).unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 2);
    assert_eq!(resp["kind"], "denied");
    assert!(resp["stderr"].as_str().unwrap().contains("server mode"));

    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[test]
fn e2e_grep_include_exclude_dir_filters() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::create_dir_all(dir.path().join("target")).unwrap();
    std::fs::write(dir.path().join("src/a.rs"), "alpha\n").unwrap();
    std::fs::write(dir.path().join("notes.txt"), "alpha\n").unwrap();
    std::fs::write(dir.path().join("target/gen.rs"), "alpha\n").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_la-console"))
        .arg("--root")
        .arg(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(
        stdin,
        r#"{{"op": "exec", "cmd": "grep --include=*.rs --exclude-dir=target alpha ."}}"#
    )
    .unwrap();
    writeln!(
        stdin,
        r#"{{"op": "exec", "cmd": "grep --include='[bad' alpha ."}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["stdout"], "src/a.rs:1:alpha\n");

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["kind"], "fail");
    assert!(resp["stderr"]
        .as_str()
        .unwrap()
        .contains("invalid --include glob"));

    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[test]
fn e2e_json_extractor_on_pipe_and_files() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("data.json"),
        r#"{"body":{"items":[{"name":"first"},{"name":"second"}],"n":3},"ok":true}"#,
    )
    .unwrap();
    std::fs::write(dir.path().join("bad.json"), "{not json").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_la-console"))
        .arg("--root")
        .arg(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    let cmds = [
        r#"cat data.json | json body.items[0].name"#,
        r#"cat data.json | json body | json items[1] | json name"#,
        "json body.n data.json",
        "json body.nope data.json",
        "json . data.json > whole.json",
        "cat bad.json | json a",
        "json -r body data.json",
        "json a ../escape.json",
    ];
    for cmd in cmds {
        writeln!(
            stdin,
            r#"{{"op": "exec", "cmd": {}}}"#,
            serde_json::to_string(cmd).unwrap()
        )
        .unwrap();
    }
    stdin.flush().unwrap();

    let mut next = || {
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        serde_json::from_str::<serde_json::Value>(&line).unwrap()
    };

    let resp = next();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["stdout"], "\"first\"\n");

    let resp = next();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["stdout"], "\"second\"\n");

    let resp = next();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["stdout"], "3\n");

    let resp = next();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["stdout"], "null\n");

    let resp = next();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["stdout"], "");
    let whole = std::fs::read_to_string(dir.path().join("whole.json")).unwrap();
    assert!(serde_json::from_str::<serde_json::Value>(whole.trim()).is_ok());

    let resp = next();
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["kind"], "fail");
    assert!(resp["stderr"].as_str().unwrap().contains("invalid JSON"));

    let resp = next();
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["kind"], "fail");
    assert!(resp["stderr"]
        .as_str()
        .unwrap()
        .contains("unsupported option"));

    let resp = next();
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["kind"], "denied");

    drop(stdin);
    assert!(child.wait().unwrap().success());
}
