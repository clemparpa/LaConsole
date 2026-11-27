//! e2e for the OS confinement backend by spawn (`spec/sandbox-backend.md`):
//! the hidden `__sandbox_helper` arg0, the strict JSON profile, and the
//! sandboxed `trusted` execution (FS confinement, exec confinement, network
//! `none`/`loopback`, v3 fields denied fail-closed).

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_la-console")
}

fn write_profile(dir: &Path, root: &Path, network: &str) -> PathBuf {
    let p = dir.join("profile.json");
    let json = serde_json::json!({"version": 1, "root": root, "network": network});
    std::fs::write(&p, serde_json::to_vec(&json).unwrap()).unwrap();
    p
}

/// Runs `la-console __sandbox_helper <profile> -- <cmd...>` and returns
/// (exit code, stdout, stderr).
fn run_helper(profile: &Path, cmd: &[&str]) -> (Option<i32>, String, String) {
    let mut args: Vec<std::ffi::OsString> =
        vec!["__sandbox_helper".into(), profile.into(), "--".into()];
    args.extend(cmd.iter().map(std::ffi::OsString::from));
    let out = Command::new(bin()).args(&args).output().unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// --- helper arg0 / profile strictness (fail-closed exit code 125) ---

#[test]
fn helper_refuses_bad_usage_with_dedicated_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    let profile = write_profile(dir.path(), dir.path(), "none");
    for args in [
        vec!["__sandbox_helper"],
        vec!["__sandbox_helper", profile.to_str().unwrap()],
        vec!["__sandbox_helper", profile.to_str().unwrap(), "--"],
        vec!["__sandbox_helper", "/nonexistent.json", "--", "/bin/true"],
    ] {
        let out = Command::new(bin()).args(&args).output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(la_console::sandbox_backend::HELPER_FAILURE_EXIT_CODE as i32),
            "args {args:?}"
        );
    }
}

#[test]
fn helper_refuses_invalid_profiles_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let cases: Vec<(&str, String)> = vec![
        (
            "unknown field",
            r#"{"version":1,"root":"/tmp","network":"none","secret":"x"}"#.into(),
        ),
        (
            "wrong version",
            r#"{"version":2,"root":"/tmp","network":"none"}"#.into(),
        ),
        (
            "relative root",
            r#"{"version":1,"root":"rel","network":"none"}"#.into(),
        ),
        ("not json", "nope".into()),
        (
            "oversized",
            format!(
                "{{\"version\":1,\"root\":\"/tmp\",\"pad\":\"{}\"}}",
                "x".repeat(70 * 1024)
            ),
        ),
    ];
    for (name, content) in cases {
        let p = dir.path().join("p.json");
        std::fs::write(&p, content).unwrap();
        let (code, _out, err) = run_helper(&p, &["/bin/true"]);
        assert_eq!(
            code,
            Some(la_console::sandbox_backend::HELPER_FAILURE_EXIT_CODE as i32),
            "case {name}: {err}"
        );
    }
}

// --- sandboxed execution through the helper (macOS/Linux only) ---

/// Spawns the helper with a valid profile on `root` and runs `sh -c script`.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run_sandboxed(root: &Path, script: &str) -> (Option<i32>, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let profile = write_profile(dir.path(), root, "none");
    run_helper(&profile, &["/bin/sh", "-c", script])
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn helper_runs_usual_commands_sandboxed() {
    let root = tempfile::tempdir().unwrap();
    let script = format!("echo hello-sandbox; ls {}", root.path().display());
    let (code, out, err) = run_sandboxed(root.path(), &script);
    assert_eq!(code, Some(0), "err: {err}");
    assert!(out.starts_with("hello-sandbox\n"), "got: {out}");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn helper_confines_writes_to_the_root() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("pwned.txt");
    let script = format!("echo pwned > {}", target.display());
    let (code, _out, err) = run_sandboxed(root.path(), &script);
    assert_ne!(code, Some(0), "write outside root must fail: {err}");
    assert!(!target.exists(), "file written outside the root!");
    // Writes inside the root work.
    let script = format!(
        "echo ok > {}/inside.txt && cat {}/inside.txt",
        root.path().display(),
        root.path().display()
    );
    let (code, out, err) = run_sandboxed(root.path(), &script);
    assert_eq!(code, Some(0), "err: {err}");
    assert_eq!(out, "ok\n");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn helper_confines_reads_outside_root_and_system_dirs() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("secret.txt");
    std::fs::write(&secret, "top-secret").unwrap();
    let script = format!("cat {}", secret.display());
    let (code, out, _err) = run_sandboxed(root.path(), &script);
    assert_ne!(code, Some(0));
    assert!(
        !out.contains("top-secret"),
        "read outside root leaked: {out}"
    );
}

// Linux only: the exec allowlist is a second Landlock layer. On macOS nono
// 0.79 emits a blanket `(allow process-exec*)` (documented in the spec), so
// exec confinement is not enforceable there.
#[cfg(target_os = "linux")]
#[test]
fn helper_confines_exec_to_shell_and_path() {
    let root = tempfile::tempdir().unwrap();
    // A binary copied outside the allowed exec anchors must not be exec'able.
    let outside = tempfile::tempdir().unwrap();
    let evil = outside.path().join("evil-sh");
    std::fs::copy("/bin/sh", &evil).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let profile = write_profile(dir.path(), root.path(), "none");
    let (code, out, err) = run_helper(
        &profile,
        &[evil.to_str().unwrap(), "-c", "echo SHOULD-NOT-RUN"],
    );
    assert_eq!(
        code,
        Some(la_console::sandbox_backend::HELPER_FAILURE_EXIT_CODE as i32),
        "exec outside the allowed paths must be refused: {err}"
    );
    assert!(!out.contains("SHOULD-NOT-RUN"));
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn bash_available() -> bool {
    if Path::new("/bin/bash").exists() {
        true
    } else {
        eprintln!("skipping test: /bin/bash not available");
        false
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn helper_network_none_blocks_even_loopback() {
    if !bash_available() {
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let root = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let profile = write_profile(dir.path(), root.path(), "none");
    let script = format!("exec 3<>/dev/tcp/127.0.0.1/{port} && echo CONNECTED");
    let (code, out, _err) = run_helper(&profile, &["/bin/bash", "-c", &script]);
    assert_ne!(code, Some(0), "network none must block loopback TCP");
    assert!(!out.contains("CONNECTED"));
    assert!(
        listener.accept().is_err(),
        "no connection must reach the listener"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn helper_network_loopback_allows_localhost_only() {
    if !bash_available() {
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let root = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let profile = write_profile(dir.path(), root.path(), "loopback");
    let script = format!("exec 3<>/dev/tcp/127.0.0.1/{port} && echo CONNECTED");
    let (code, out, err) = run_helper(&profile, &["/bin/bash", "-c", &script]);
    assert_eq!(code, Some(0), "loopback must work on macOS: {err}");
    assert!(out.contains("CONNECTED"));
    // External connect must still be refused.
    let (code, _out, _err) = run_helper(
        &profile,
        &["/bin/bash", "-c", "exec 3<>/dev/tcp/192.0.2.1/80"],
    );
    assert_ne!(
        code,
        Some(0),
        "external connect must be refused in loopback mode"
    );
}

// --- trusted execution goes through the sandbox ---

struct TrustedFixture {
    root: tempfile::TempDir,
    _trusted_dir: tempfile::TempDir,
    trusted_file: PathBuf,
    sha256: String,
}

fn trusted_fixture(content: &str) -> TrustedFixture {
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

struct Console {
    child: Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
}

fn spawn_console(fx: &TrustedFixture) -> Console {
    let mut child = Command::new(bin())
        .arg("--root")
        .arg(fx.root.path())
        .arg("--trusted-file")
        .arg(&fx.trusted_file)
        .arg("--trusted-sha256")
        .arg(&fx.sha256)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    Console {
        stdin: child.stdin.take().unwrap(),
        stdout: BufReader::new(child.stdout.take().unwrap()),
        child,
    }
}

impl Console {
    fn exec(&mut self, cmd: &str) -> serde_json::Value {
        writeln!(
            self.stdin,
            r#"{{"op": "exec", "cmd": {}}}"#,
            serde_json::to_string(cmd).unwrap()
        )
        .unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    fn finish(mut self) {
        drop(self.stdin);
        assert!(self.child.wait().unwrap().success());
    }
}

// Spawns a real sandboxed shell: macOS/Linux-only (denied fail-closed on Windows).
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn e2e_trusted_runs_through_the_os_sandbox() {
    let fx = trusted_fixture("[commands.hello]\ncommand = \"echo hi-sandboxed; pwd\"\n");
    let mut console = spawn_console(&fx);
    let resp = console.exec("trusted hello");
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["code"], 0);
    let stdout = resp["stdout"].as_str().unwrap();
    assert!(stdout.contains("hi-sandboxed\n"), "got: {stdout}");
    assert!(
        stdout.contains(
            &la_console::platform::canonicalize(fx.root.path())
                .unwrap()
                .to_string_lossy()
                .into_owned()
        ),
        "cwd must be the root: {stdout}"
    );
    console.finish();
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn e2e_trusted_cannot_write_outside_root() {
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("pwned.txt");
    let content = format!(
        "[commands.pwn]\ncommand = \"echo pwned > {}\"\n",
        target.display()
    );
    let fx = trusted_fixture(&content);
    let mut console = spawn_console(&fx);
    let resp = console.exec("trusted pwn");
    assert_eq!(resp["ok"], false);
    assert_ne!(resp["code"], 0);
    assert!(!target.exists(), "sandbox let a write escape the root");
    console.finish();
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn e2e_trusted_network_none_blocks_loopback_tcp() {
    if !bash_available() {
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let content = format!(
        "[commands.net]\ncommand = \"/bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}'\"\nnetwork = \"none\"\n"
    );
    let fx = trusted_fixture(&content);
    let mut console = spawn_console(&fx);
    let resp = console.exec("trusted net");
    assert_eq!(resp["ok"], false);
    assert_ne!(resp["code"], 0, "network = none must block loopback TCP");
    assert!(listener.accept().is_err());
    console.finish();
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_trusted_network_loopback_is_denied_fail_closed_on_linux() {
    // Landlock net rules are port-only (no IP filtering): loopback-only is not
    // enforceable on Linux, so the helper refuses (exit 125) -> denied.
    let content = "[commands.net]\ncommand = \"true\"\nnetwork = \"loopback\"\n";
    let fx = trusted_fixture(content);
    let mut console = spawn_console(&fx);
    let resp = console.exec("trusted net");
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 2);
    assert_eq!(resp["kind"], "denied");
    let stderr = resp["stderr"].as_str().unwrap();
    assert!(stderr.contains("loopback"), "got: {stderr}");
    console.finish();
}

#[test]
fn e2e_trusted_v3_fields_are_denied_fail_closed() {
    for (field, value) in [
        ("network", "\"proxy\""),
        ("max_write_bytes", "1048576"),
        ("mem_bytes", "1073741824"),
        ("cpus", "2"),
    ] {
        let content = format!("[commands.x]\ncommand = \"true\"\n{field} = {value}\n");
        let fx = trusted_fixture(&content);
        let mut console = spawn_console(&fx);
        let resp = console.exec("trusted x");
        assert_eq!(resp["ok"], false, "field {field}");
        assert_eq!(resp["code"], 2, "field {field}");
        assert_eq!(resp["kind"], "denied", "field {field}");
        let stderr = resp["stderr"].as_str().unwrap();
        assert!(stderr.contains("fail-closed"), "field {field}: {stderr}");
        assert!(stderr.contains(field), "field {field}: {stderr}");
        console.finish();
    }
}
