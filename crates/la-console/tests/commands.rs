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

#[test]
fn e2e_grep_finds_matches_and_denies_escape() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "foo one\nbar\nfoo two\n").unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send("grep foo a.txt");
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["stdout"], "a.txt:1:foo one\na.txt:3:foo two\n");
    let resp = session.send("grep zzz a.txt");
    assert_eq!(resp["code"], 1);
    let resp = session.send("grep foo ../outside.txt");
    assert_eq!(resp["code"], 2);
    assert!(resp["stderr"].as_str().unwrap().starts_with("denied:"));
}

#[test]
fn e2e_sub_rewrites_then_cat_reads_back() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "hello world\n").unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send(r#"sub "h.llo" "bye" a.txt"#);
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["code"], 0);
    let resp = session.send("cat a.txt");
    assert_eq!(resp["stdout"], "bye world\n");
    let resp = session.send("sub a b ../evil.txt");
    assert_eq!(resp["code"], 2);
}

#[test]
fn e2e_http_localhost_only() {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nping")
                .unwrap();
            stream.flush().unwrap();
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send(&format!("http GET http://127.0.0.1:{port}/"));
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["code"], 0);
    assert_eq!(resp["stdout"], "ping");
    let resp = session.send("http GET http://169.254.169.254/latest/meta-data");
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 2);
    assert!(resp["stderr"].as_str().unwrap().starts_with("denied:"));
    let resp = session.send("http GET http://example.com/");
    assert_eq!(resp["code"], 2);
}

#[test]
fn e2e_success_response_has_no_kind_field() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("hello.txt"), "hello\n").unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send("cat hello.txt");
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["code"], 0);
    assert!(resp.get("kind").is_none());
}

#[test]
fn e2e_error_kind_denied_for_security_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send("cat ../../etc/passwd");
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 2);
    assert_eq!(resp["kind"], "denied");
    let resp = session.send("rm -rf /");
    assert_eq!(resp["code"], 2);
    assert_eq!(resp["kind"], "denied");
}

#[test]
fn e2e_error_kind_limit_for_read_bound() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("big.bin"), vec![0u8; 1024 * 1024 + 1]).unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send("cat big.bin");
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 3);
    assert_eq!(resp["kind"], "limit");
}

#[test]
fn e2e_error_kind_fail_for_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send("cat nope.txt");
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 1);
    assert_eq!(resp["kind"], "fail");
}

#[test]
fn e2e_help_lists_every_command_with_all_its_syntaxes() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send("help");
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["code"], 0);
    let stdout = resp["stdout"].as_str().unwrap();
    for expected in [
        "cat <path...>",
        "echo <text>",
        "echo <text> > <path>",
        "ls [path...]",
        "ls [path...] --all",
        "grep <pattern> <path...>",
        "grep <pattern> <path...> --all",
        "sed s/<pat>/<repl>/[g] <path...>",
        "sed -i s/<pat>/<repl>/[g] <path...>",
        "sub <pattern> <replacement> <path...>",
        "http <METHOD> <url>",
        "head [-n N] [path...]",
        "tail [-n N] [path...]",
        "wc [-l|-w|-c] [path...]",
        "sort [-r] [path...]",
        "uniq [-c] [path...]",
        "cut -d <sep> -f <n[,m...]> [path...]",
        "tr <from> <to> [path...]",
        "trusted <name>",
        "help",
    ] {
        assert!(
            stdout.contains(expected),
            "help output missing {expected:?}:\n{stdout}"
        );
    }
}

#[test]
fn e2e_help_specific_command_shows_only_its_syntaxes() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send("help echo");
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["code"], 0);
    let stdout = resp["stdout"].as_str().unwrap();
    assert!(stdout.contains("echo <text>"));
    assert!(stdout.contains("echo <text> > <path>"));
    assert!(!stdout.contains("cat <path...>"));
}

#[test]
fn e2e_help_unknown_command_is_a_fail() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send("help nope");
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 1);
    assert_eq!(resp["kind"], "fail");
}

#[test]
fn e2e_sed_print_mode_previews_without_touching_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "foo bar foo\n").unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send(r#"sed "s/foo/baz/g" a.txt"#);
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["code"], 0);
    assert!(resp.get("kind").is_none());
    assert_eq!(resp["stdout"], "baz bar baz\n");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
        "foo bar foo\n"
    );
}

#[test]
fn e2e_sed_in_place_rewrites_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "foo\n").unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send(r#"sed -i "s/foo/baz/g" a.txt"#);
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["code"], 0);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
        "baz\n"
    );
}

#[test]
fn e2e_sed_unsupported_forms_are_precise_fail_errors() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "x\n").unwrap();
    let mut session = Session::spawn(dir.path());
    let cases = [
        (r#"sed "s/a/b/i" a.txt"#, "unsupported flag 'i'"),
        (r#"sed "2d" a.txt"#, "unsupported command '2'"),
        (r#"sed "s/a/b/;s/c/d/" a.txt"#, "multi-command"),
        (r#"sed -n "s/a/b/" a.txt"#, "unsupported option '-n'"),
    ];
    for (cmd, expected) in cases {
        let resp = session.send(cmd);
        assert_eq!(resp["ok"], false, "{cmd}");
        assert_eq!(resp["code"], 1, "{cmd}");
        assert_eq!(resp["kind"], "fail", "{cmd}");
        assert!(
            resp["stderr"].as_str().unwrap().contains(expected),
            "{cmd}: stderr {:?} missing {expected:?}",
            resp["stderr"]
        );
    }
    // Path-less sed outside a stream position is now rejected at parse time.
    for cmd in ["sed", r#"sed "s/a/b/""#, r#"sed "s/a/b/" | grep x"#] {
        let resp = session.send(cmd);
        assert_eq!(resp["ok"], false, "{cmd}");
        assert_eq!(resp["code"], 2, "{cmd}");
        assert_eq!(resp["kind"], "denied", "{cmd}");
        assert!(
            resp["stderr"].as_str().unwrap().contains("usage"),
            "{cmd}: stderr {:?}",
            resp["stderr"]
        );
    }
    assert_eq!(
        std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
        "x\n"
    );
}

#[test]
fn e2e_grep_flags_search_log() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("app.log"),
        "INFO start\nERROR disk full\nerror retry\nINFO ok\n",
    )
    .unwrap();
    let mut session = Session::spawn(dir.path());

    let resp = session.send("grep -i error app.log");
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["code"], 0);
    assert_eq!(
        resp["stdout"].as_str().unwrap(),
        "app.log:2:ERROR disk full\napp.log:3:error retry\n"
    );

    let resp = session.send("grep -v INFO app.log");
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["code"], 0);
    assert_eq!(
        resp["stdout"].as_str().unwrap(),
        "app.log:2:ERROR disk full\napp.log:3:error retry\n"
    );

    let resp = session.send("grep -c -i error app.log");
    assert_eq!(resp["stdout"].as_str().unwrap(), "app.log:2\n");

    let resp = session.send("grep -q -i error app.log");
    assert_eq!(resp["code"], 0);
    assert_eq!(resp["stdout"].as_str().unwrap(), "");

    let resp = session.send("grep -q nomatch app.log");
    assert_eq!(resp["code"], 1);
    assert_eq!(resp["stdout"].as_str().unwrap(), "");

    let resp = session.send("grep -C 1 ERROR app.log");
    assert_eq!(
        resp["stdout"].as_str().unwrap(),
        "app.log-1-INFO start\napp.log:2:ERROR disk full\napp.log-3-error retry\n"
    );
}

#[test]
fn e2e_grep_pipe_with_flags_and_o() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("in.txt"), "foo bar foo\nplain\n").unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send("cat in.txt | grep -o foo");
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["code"], 0);
    assert_eq!(
        resp["stdout"].as_str().unwrap(),
        "(stdin):1:foo\n(stdin):1:foo\n"
    );
    let resp = session.send("cat in.txt | grep -v plain");
    assert_eq!(resp["stdout"].as_str().unwrap(), "(stdin):1:foo bar foo\n");
    let resp = session.send("grep -l foo in.txt nope.txt");
    assert_eq!(resp["stdout"].as_str().unwrap(), "in.txt\n");
    assert_eq!(resp["code"], 0);
}

#[test]
fn e2e_grep_refused_flags_are_fail_not_denied() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "x\n").unwrap();
    let mut session = Session::spawn(dir.path());
    for cmd in ["grep -P x a.txt", "grep --text x a.txt", "grep -z x a.txt"] {
        let resp = session.send(cmd);
        assert_eq!(resp["ok"], false, "{cmd}");
        assert_eq!(resp["code"], 1, "{cmd}");
        assert_eq!(resp["kind"], "fail", "{cmd}");
        assert!(
            resp["stderr"].as_str().unwrap().contains("not supported"),
            "{cmd}: {:?}",
            resp["stderr"]
        );
    }
    // path escape is still denied (kind=denied, code 2) even with flags
    let resp = session.send("grep -v x ../../etc/passwd");
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 2);
    assert_eq!(resp["kind"], "denied");
}

#[test]
fn e2e_grep_file_patterns_and_exclude_from() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("src")).unwrap();
    std::fs::write(dir.path().join("src/a.rs"), "alpha\nbeta\n").unwrap();
    std::fs::write(dir.path().join("src/b.txt"), "alpha\n").unwrap();
    std::fs::write(dir.path().join("pats.txt"), "alpha\n\nbeta\n").unwrap();
    std::fs::write(dir.path().join("ex.txt"), "*.txt\n").unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send("grep -f pats.txt src");
    assert_eq!(resp["ok"], true);
    assert_eq!(
        resp["stdout"],
        "src/a.rs:1:alpha\nsrc/a.rs:2:beta\nsrc/b.txt:1:alpha\n"
    );
    let resp = session.send("grep -f pats.txt --exclude-from=ex.txt src");
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["stdout"], "src/a.rs:1:alpha\nsrc/a.rs:2:beta\n");
    // -f hors du root = denied
    let resp = session.send("grep -f ../pats.txt alpha src");
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["code"], 2);
    assert_eq!(resp["kind"], "denied");
}

#[test]
fn e2e_help_grep_lists_flags() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::spawn(dir.path());
    let resp = session.send("help grep");
    assert_eq!(resp["ok"], true);
    let stdout = resp["stdout"].as_str().unwrap();
    assert!(stdout.contains("grep [flags] <pattern> [path...]"));
    assert!(stdout.contains("-i -v -w -x -F -c -o -l -L -q -m N -B/-A/-C N"));
    assert!(stdout.contains("--all"));
}

#[test]
fn e2e_stream_filters_full_pipeline() {
    let dir = tempfile::tempdir().unwrap();
    let content: String = (1..=20).map(|i| format!("row{i:02}:val{i}\n")).collect();
    std::fs::write(dir.path().join("data.csv"), content).unwrap();
    std::fs::write(dir.path().join("log.txt"), "ERR\nOK\nERR\nERR\nOK\n").unwrap();
    let mut session = Session::spawn(dir.path());

    let resp = session.send("cat data.csv | head -n 2");
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["stdout"], "row01:val1\nrow02:val2\n");

    let resp = session.send("cat data.csv | tail -n 2");
    assert_eq!(resp["stdout"], "row19:val19\nrow20:val20\n");

    let resp = session.send("cat data.csv | wc -l");
    assert_eq!(resp["stdout"], "20\n");

    let resp = session.send("cat data.csv | sort -r | head -n 1");
    assert_eq!(resp["stdout"], "row20:val20\n");

    let resp = session.send("cat log.txt | sort | uniq -c");
    assert_eq!(resp["stdout"], "3 ERR\n2 OK\n");

    let resp = session.send("cat data.csv | cut -d: -f 1 | head -n 1");
    assert_eq!(resp["stdout"], "row01\n");

    let resp = session.send("cat data.csv | tr a-z A-Z | head -n 1");
    assert_eq!(resp["stdout"], "ROW01:VAL1\n");

    let resp = session.send("head -n 1 < data.csv");
    assert_eq!(resp["stdout"], "row01:val1\n");

    let resp = session.send("cat log.txt | tail -n 1 > last.txt");
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["code"], 0);
    let resp = session.send("cat last.txt");
    assert_eq!(resp["stdout"], "OK\n");
}

#[test]
fn e2e_stream_filters_unknown_option_is_fail() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "x\n").unwrap();
    let mut session = Session::spawn(dir.path());
    for cmd in [
        "sort -q a.txt",
        "head -q a.txt",
        "wc -z a.txt",
        "uniq -d a.txt",
        "cut -s -d: -f1 a.txt",
        "tr -d a b a.txt",
        "tail --nope a.txt",
    ] {
        let resp = session.send(cmd);
        assert_eq!(resp["ok"], false, "cmd {cmd}");
        assert_eq!(resp["code"], 1, "cmd {cmd}");
        assert_eq!(resp["kind"], "fail", "cmd {cmd}");
    }
}

#[test]
fn e2e_stream_filters_deny_escape() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::spawn(dir.path());
    for cmd in [
        "head ../secret.txt",
        "tail -n 1 /etc/passwd",
        "sort ../x",
        "wc -l ../../etc/passwd",
        "uniq ../x",
        "cut -d: -f1 ../x",
        "tr a b ../x",
    ] {
        let resp = session.send(cmd);
        assert_eq!(resp["ok"], false, "cmd {cmd}");
        assert_eq!(resp["code"], 2, "cmd {cmd}");
        assert_eq!(resp["kind"], "denied", "cmd {cmd}");
    }
}

#[test]
fn e2e_stream_filters_invalid_utf8_is_fail() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("bin.dat"), vec![0xff, 0xfe, b'\n']).unwrap();
    let mut session = Session::spawn(dir.path());
    for cmd in [
        "sort bin.dat",
        "head bin.dat",
        "wc bin.dat",
        "tr a b bin.dat",
    ] {
        let resp = session.send(cmd);
        assert_eq!(resp["ok"], false, "cmd {cmd}");
        assert_eq!(resp["code"], 1, "cmd {cmd}");
        assert_eq!(resp["kind"], "fail", "cmd {cmd}");
        assert!(
            resp["stderr"].as_str().unwrap().contains("UTF-8"),
            "cmd {cmd}"
        );
    }
}
