//! OS confinement backend by spawn — [spec/sandbox-backend.md](../../spec/sandbox-backend.md).
//!
//! This is the **only** module that references the `nono` crate (pinned to an
//! exact version in `Cargo.toml`): `apply(profile)` + `support_info()`. A
//! breaking change of the pre-1.0 `nono` therefore touches only this file.
//!
//! Every trusted subprocess is spawned by re-exec'ing our own binary with the
//! hidden arg0 `__sandbox_helper <profile.json> -- <cmd...>`
//! (`std::env::current_exe()`): the child reads the strict JSON profile,
//! applies the sandbox **just before exec** (`Sandbox::apply_auto`), then
//! execs. The sandbox is never applied in the harness process, and no CLI
//! flag can disable it. Fail-closed: any failure in the child exits with the
//! dedicated [`HELPER_FAILURE_EXIT_CODE`], which the parent maps to `denied` —
//! a command is never exec'd unsandboxed.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Hidden arg0 recognized by `main` before the clap CLI is parsed.
pub const HELPER_ARG0: &str = "__sandbox_helper";

/// Dedicated exit code used by the helper when it refuses to exec (bad usage,
/// profile parse error, unsupported backend, apply failure, exec failure).
/// The parent maps it to `denied`. A trusted command that itself exits with
/// this exact code is also reported as `denied` — fail-closed by design.
pub const HELPER_FAILURE_EXIT_CODE: u8 = 125;

const PROFILE_VERSION: u32 = 1;

/// The profile is a few hundred bytes; anything bigger is refused.
const MAX_PROFILE_BYTES: u64 = 64 * 1024;

/// Network mode carried by the profile (spec §3): `none` (default) or
/// `loopback`. `proxy` is not representable here — it stays `denied` at the
/// `trusted.toml` level until v3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileNetwork {
    #[default]
    None,
    Loopback,
}

/// Strict JSON sandbox profile (spec §3): `deny_unknown_fields`, bounded read.
/// It contains paths and the network mode only — never a secret, never env.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxProfile {
    pub version: u32,
    pub root: PathBuf,
    #[serde(default)]
    pub network: ProfileNetwork,
}

impl SandboxProfile {
    pub fn new(root: PathBuf, network: ProfileNetwork) -> Self {
        Self {
            version: PROFILE_VERSION,
            root,
            network,
        }
    }

    pub fn to_json(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|err| format!("profile serialize: {err}"))
    }

    /// Bounded, strict parse: unknown fields and a wrong version are refused.
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() as u64 > MAX_PROFILE_BYTES {
            return Err(format!(
                "profile too large ({} bytes > {MAX_PROFILE_BYTES})",
                bytes.len()
            ));
        }
        let profile: SandboxProfile = serde_json::from_slice(bytes)
            .map_err(|err| format!("invalid sandbox profile: {err}"))?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != PROFILE_VERSION {
            return Err(format!(
                "unsupported profile version {} (expected {PROFILE_VERSION})",
                self.version
            ));
        }
        if !self.root.is_absolute() {
            return Err("profile root must be an absolute canonical path".to_string());
        }
        Ok(())
    }
}

/// Platform support of the OS sandbox backend.
#[derive(Debug, Clone)]
pub struct SupportInfo {
    pub is_supported: bool,
    pub platform: String,
    pub details: String,
}

pub fn support_info() -> SupportInfo {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let info = nono::Sandbox::support_info();
        SupportInfo {
            is_supported: info.is_supported,
            platform: info.platform.to_string(),
            details: info.details,
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        SupportInfo {
            is_supported: false,
            platform: std::env::consts::OS.to_string(),
            details: format!(
                "no OS sandbox backend on platform '{}' (fail-closed)",
                std::env::consts::OS
            ),
        }
    }
}

/// True when an OS sandbox backend is available on this machine. Callers must
/// refuse (fail-closed) when false — never run unsandboxed.
pub fn supported() -> bool {
    support_info().is_supported
}

/// Read-only system paths needed by the shell and the toolchain, centralized
/// here (spec §3) and exercised by the CI matrix. A missing path is skipped
/// (fail-closed: no grant, never an error).
#[cfg(target_os = "linux")]
fn system_read_dirs() -> &'static [&'static str] {
    &["/usr", "/bin", "/lib", "/lib64", "/etc"]
}

/// macOS: `/bin` and `/sbin` are symlinks into `/usr`; `/private/*` holds the
/// real files (dyld cache, tmp, etc.).
#[cfg(target_os = "macos")]
fn system_read_dirs() -> &'static [&'static str] {
    &[
        "/usr",
        "/System",
        "/Library",
        "/private/etc",
        "/private/var",
        "/private/tmp",
        "/bin",
        "/sbin",
    ]
}

/// Map a validated profile to a `CapabilitySet`. This mapping lives ONLY in
/// this module (spec §2) and runs **before** the irreversible apply, so any
/// error here leaves the process unsandboxed (and is reported as `denied`).
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn capabilities(profile: &SandboxProfile) -> Result<nono::CapabilitySet, String> {
    use nono::{AccessMode, CapabilitySet};

    let mut caps = CapabilitySet::new();
    caps = caps
        .allow_path(&profile.root, AccessMode::ReadWrite)
        .map_err(|err| format!("cannot grant root {}: {err}", profile.root.display()))?;
    for dir in system_read_dirs() {
        if Path::new(dir).exists() {
            caps = caps
                .allow_path(dir, AccessMode::Read)
                .map_err(|err| format!("cannot grant system path {dir}: {err}"))?;
        }
    }
    if Path::new("/dev/null").exists() {
        caps = caps
            .allow_file("/dev/null", AccessMode::ReadWrite)
            .map_err(|err| format!("cannot grant /dev/null: {err}"))?;
    }
    match profile.network {
        ProfileNetwork::None => {
            caps = caps.block_network();
        }
        ProfileNetwork::Loopback => {
            // Linux: Landlock network rules are port-only (no IP filtering),
            // so "loopback only" cannot be enforced — denied fail-closed.
            // (macOS Seatbelt can scope outbound TCP to localhost:*.)
            #[cfg(target_os = "linux")]
            return Err(
                "network = \"loopback\" is not enforceable on Linux (Landlock net rules are \
                 port-only, no IP filtering) — denied fail-closed; use network = \"none\""
                    .to_string(),
            );
            #[cfg(target_os = "macos")]
            {
                // Port 0 = the Seatbelt `localhost:*` wildcard.
                caps = caps.block_network().allow_localhost_port(0);
            }
        }
    }
    Ok(caps)
}

/// Apply the sandbox to the **current process** (irreversible). Called only by
/// the `__sandbox_helper` child, right before exec. On error the caller must
/// exit with [`HELPER_FAILURE_EXIT_CODE`] and never exec.
pub fn apply(profile: &SandboxProfile) -> Result<(), String> {
    profile.validate()?;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        // Pre-checks BEFORE the irreversible apply (fail-closed).
        #[cfg(target_os = "linux")]
        {
            let abi = nono::Sandbox::detect_abi()
                .map_err(|err| format!("Landlock unavailable: {err}"))?;
            if !abi.has_execute() {
                return Err(format!(
                    "Landlock ABI {} lacks the Execute restriction (< V3) — denied fail-closed",
                    abi.version_string()
                ));
            }
        }
        let caps = capabilities(profile)?;
        nono::Sandbox::apply_auto(&caps).map_err(|err| format!("sandbox apply failed: {err}"))?;
        // Confine exec to the shell + the reduced PATH + the read-only system
        // dirs (which contain the PATH on standard layouts). On Linux this is
        // a second Landlock layer (`restrict_execute`, ABI V3+): exec is
        // denied everywhere else, in particular under the root and /tmp.
        // On macOS nono 0.79 emits a blanket `(allow process-exec*)`, so
        // there the FS read-only grants are the confinement (see spec §3).
        #[cfg(target_os = "linux")]
        {
            let path_dirs = crate::platform::default_path_entries();
            let mut exec_paths: Vec<&Path> = Vec::new();
            if let Some(sh) = crate::platform::shell() {
                exec_paths.push(Path::new(sh));
            }
            let mut dirs: Vec<&Path> = path_dirs.iter().map(|d| d.as_path()).collect();
            dirs.extend(system_read_dirs().iter().map(Path::new));
            for dir in dirs {
                if dir.exists() {
                    exec_paths.push(dir);
                }
            }
            nono::Sandbox::restrict_execute(&exec_paths)
                .map_err(|err| format!("cannot restrict exec: {err}"))?;
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(format!(
            "no OS sandbox backend on platform '{}' (fail-closed)",
            std::env::consts::OS
        ))
    }
}

/// Hidden arg0 entry point: `la-console __sandbox_helper <profile.json> -- <cmd...>`.
/// On success the process is replaced by `cmd` (exec) — this never returns.
/// On any failure it exits with [`HELPER_FAILURE_EXIT_CODE`].
pub fn run_helper(args: Vec<OsString>) -> ! {
    match helper_exec(args) {
        Ok(()) => unreachable!("exec replaces the process on success"),
        Err(msg) => {
            eprintln!("sandbox helper: {msg}");
            std::process::exit(i32::from(HELPER_FAILURE_EXIT_CODE));
        }
    }
}

/// Parse `<profile.json> -- <cmd...>`, load the profile (bounded read), apply
/// the sandbox, then exec `cmd`. Split from [`run_helper`] for unit tests.
fn helper_exec(args: Vec<OsString>) -> Result<(), String> {
    let (profile_path, cmd) = parse_helper_args(&args)?;
    let profile = load_profile(&profile_path)?;
    apply(&profile)?;
    exec_cmd(&cmd)
}

fn parse_helper_args(args: &[OsString]) -> Result<(PathBuf, Vec<OsString>), String> {
    if args.len() < 3 || args[1] != OsStr::new("--") {
        return Err(format!("usage: {HELPER_ARG0} <profile.json> -- <cmd...>"));
    }
    let cmd = args[2..].to_vec();
    Ok((PathBuf::from(&args[0]), cmd))
}

fn load_profile(path: &Path) -> Result<SandboxProfile, String> {
    use std::io::Read;
    let file = std::fs::File::open(path)
        .map_err(|err| format!("cannot open profile {}: {err}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_PROFILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| format!("cannot read profile {}: {err}", path.display()))?;
    SandboxProfile::from_json(&bytes)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn exec_cmd(cmd: &[OsString]) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    let mut command = std::process::Command::new(&cmd[0]);
    command.args(&cmd[1..]);
    let err = command.exec();
    Err(format!("exec {} failed: {err}", cmd[0].to_string_lossy()))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn exec_cmd(_cmd: &[OsString]) -> Result<(), String> {
    Err(format!(
        "cannot exec on platform '{}' (fail-closed)",
        std::env::consts::OS
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn profile_json(extra: &str) -> Vec<u8> {
        format!("{{\"version\":1,\"root\":\"/tmp/x\",\"network\":\"none\"{extra}}}").into_bytes()
    }

    #[test]
    fn profile_round_trips_through_strict_json() {
        let p = SandboxProfile::new(PathBuf::from("/abs/root"), ProfileNetwork::Loopback);
        let bytes = p.to_json().unwrap();
        assert_eq!(SandboxProfile::from_json(&bytes).unwrap(), p);
    }

    #[test]
    fn profile_network_defaults_to_none() {
        let p = SandboxProfile::from_json(br#"{"version":1,"root":"/abs"}"#).unwrap();
        assert_eq!(p.network, ProfileNetwork::None);
    }

    #[test]
    fn profile_rejects_unknown_fields() {
        let err = SandboxProfile::from_json(&profile_json(",\"secret\":\"tok\"")).unwrap_err();
        assert!(err.contains("invalid sandbox profile"), "got: {err}");
    }

    #[test]
    fn profile_rejects_wrong_version_and_relative_root() {
        let err = SandboxProfile::from_json(br#"{"version":2,"root":"/abs"}"#).unwrap_err();
        assert!(err.contains("version"), "got: {err}");
        let err = SandboxProfile::from_json(br#"{"version":1,"root":"rel/path"}"#).unwrap_err();
        assert!(err.contains("absolute"), "got: {err}");
    }

    #[test]
    fn profile_rejects_oversized_input() {
        let mut bytes = profile_json("");
        bytes.resize(MAX_PROFILE_BYTES as usize + 1, b' ');
        let err = SandboxProfile::from_json(&bytes).unwrap_err();
        assert!(err.contains("too large"), "got: {err}");
    }

    #[test]
    fn helper_args_require_double_dash_and_command() {
        let a = |v: &[&str]| v.iter().map(OsString::from).collect::<Vec<_>>();
        assert!(parse_helper_args(&a(&["p.json", "--", "/bin/true"])).is_ok());
        assert!(parse_helper_args(&a(&["p.json", "/bin/true"])).is_err());
        assert!(parse_helper_args(&a(&["p.json", "--"])).is_err());
        assert!(parse_helper_args(&a(&[])).is_err());
    }

    #[test]
    fn load_profile_fails_closed_on_missing_file() {
        let err = load_profile(Path::new("/nonexistent/profile.json")).unwrap_err();
        assert!(err.contains("cannot open profile"), "got: {err}");
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn capabilities_none_blocks_network() {
        let p = SandboxProfile::new(PathBuf::from("/"), ProfileNetwork::None);
        let caps = capabilities(&p).unwrap();
        assert!(caps.is_network_blocked());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn capabilities_loopback_is_denied_on_linux_port_only_rules() {
        // Landlock net rules are port-only (no IP filtering): loopback-only
        // cannot be enforced, so the mapping refuses before any apply.
        let p = SandboxProfile::new(PathBuf::from("/"), ProfileNetwork::Loopback);
        let err = capabilities(&p).unwrap_err();
        assert!(err.contains("port-only"), "got: {err}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn capabilities_loopback_is_allowed_on_macos() {
        let p = SandboxProfile::new(PathBuf::from("/"), ProfileNetwork::Loopback);
        let caps = capabilities(&p).unwrap();
        assert!(caps.is_network_blocked());
        assert!(caps.localhost_ports().contains(&0));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn support_info_reports_the_backend() {
        let info = support_info();
        assert!(
            info.is_supported,
            "backend must be supported here: {info:?}"
        );
        assert!(supported());
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn support_info_is_fail_closed_off_unix() {
        assert!(!supported());
    }

    proptest! {
        /// The generated profile never contains an unknown field nor a secret:
        /// it round-trips through the strict parser and its JSON keys are
        /// exactly {version, root, network} (spec §6).
        #[test]
        fn profile_never_has_unknown_fields_nor_secrets(
            root_tail in "[ -~]{0,40}",
            network in prop_oneof![Just(ProfileNetwork::None), Just(ProfileNetwork::Loopback)],
        ) {
            let root = PathBuf::from(format!("/tmp/{root_tail}"));
            let p = SandboxProfile::new(root, network);
            let bytes = p.to_json().unwrap();
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let keys: Vec<&str> = value.as_object().unwrap().keys().map(String::as_str).collect();
            let mut keys = keys;
            keys.sort_unstable();
            prop_assert_eq!(keys, vec!["network", "root", "version"]);
            prop_assert!(!bytes.windows(6).any(|w| w == b"secret"));
            prop_assert_eq!(SandboxProfile::from_json(&bytes).unwrap(), p);
        }
    }
}
