//! OS abstraction layer — the only module that knows which OS it runs on
//! (phase 1 of [spec/platform.md](../../spec/platform.md): primitives only,
//! no confinement backend).
//!
//! Everything OS-specific goes through this module; the rest of the code is
//! portable. Fail-closed by default: any uncertain primitive returns
//! `None`/`Err`, which callers translate into `denied`.
//!
//! - macOS (targeted platform, decision 2026-11-24) + Linux (same code, kept
//!   in the CI matrix): `cfg(any(target_os = "macos", target_os = "linux"))`
//!   — behavior unchanged from v1.
//! - Windows native (`cfg(windows)`): compiles and runs fail-closed — the
//!   whitelist commands and `resolve()` work, `trusted` is `denied` (no
//!   shell) and backend limits stay `denied` (via `backend_limit()`).

use std::ffi::OsString;

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod macos;
#[cfg(windows)]
mod windows;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use macos as imp;
#[cfg(windows)]
use windows as imp;

pub use imp::{
    canonicalize, default_path_entries, exit_code, file_id, file_id_of_path, hardlink_escape,
    kill_process_tree, set_new_process_group, shell,
};

/// Stable cross-OS file identity: macOS/Linux `dev`/`ino`, Windows volume serial
/// number + file index (via `same-file`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileId {
    pub dev: u64,
    pub ino: u64,
}

/// Pure check on synthetic file ids: a different device than the root's means
/// the file lives outside the root's device (hardlink escape).
pub fn hardlink_escape_ids(root: &FileId, target: &FileId) -> bool {
    root.dev != target.dev
}

/// True when `input` looks like an *absolute* Windows path or an NTFS stream
/// and must be refused fail-closed:
///
/// - UNC / verbatim prefix `\\server\share`, `\\?\C:\...` (every OS) ;
/// - on Windows: any `:` (drive letter `C:\...` or ADS `file:stream`) — a
///   relative `src\a.rs` keeps its native backslashes and stays valid ;
/// - on macOS/Linux: any backslash (`\` is never a separator there) or a drive
///   letter `C:...` in the first segment.
pub fn looks_like_windows_path(input: &str) -> bool {
    if input.starts_with("\\\\") {
        return true;
    }
    if cfg!(windows) {
        input.contains(':')
    } else {
        input.contains('\\')
            || input
                .split('/')
                .next()
                .is_some_and(|first| first.contains(':'))
    }
}

/// Renders a path with `/` separators on every OS (via `path-slash`): stable
/// output contract for the JSON protocol, and safe to re-feed to `resolve()`,
/// which accepts `/` everywhere. On macOS/Linux a literal backslash inside a
/// component is preserved (`\` is not a separator there). Non-UTF-8 paths
/// fall back to a lossy rendering.
pub fn path_to_slash(path: &std::path::Path) -> String {
    use path_slash::PathExt;
    match path.to_slash() {
        Some(s) => s.into_owned(),
        None => path.to_string_lossy().into_owned(),
    }
}

/// Shell script killing a whole process group: `kill -KILL -<pgid>`.
pub fn shell_group_kill_script(pgid: u32) -> String {
    format!("kill -KILL -{pgid} 2>/dev/null || true")
}

/// Arguments of the Windows tree kill: `taskkill /T /F /PID <pid>`.
pub fn taskkill_args(pid: u32) -> Vec<String> {
    vec![
        "/T".to_string(),
        "/F".to_string(),
        "/PID".to_string(),
        pid.to_string(),
    ]
}

/// `PATH` given to trusted shells, built from `default_path_entries()` with
/// the OS path separator (`env::join_paths` handles `:` vs `;`).
pub fn trusted_path_env() -> OsString {
    std::env::join_paths(default_path_entries()).unwrap_or_default()
}

#[doc(hidden)]
pub mod testutil {
    pub use super::imp::testutil::{set_exec_mode, symlink};

    /// Test helper: creates `link -> original`. On macOS/Linux a failure panics
    /// (tests are never silently skipped there); on Windows it returns
    /// `false` so the test can skip (the symlink privilege may be missing
    /// without Developer Mode).
    pub fn symlink_or_skip(original: &std::path::Path, link: &std::path::Path) -> bool {
        match symlink(original, link) {
            Ok(()) => true,
            Err(err) => {
                #[cfg(windows)]
                {
                    eprintln!("skipping test: cannot create symlink: {err}");
                    false
                }
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                {
                    panic!("cannot create symlink {}: {err}", link.display())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_path_detection_is_fail_closed() {
        // Refused on every OS: drive letters, UNC and verbatim prefixes.
        for bad in [
            "C:\\foo",
            "C:/foo",
            "c:foo",
            "\\\\server\\share",
            "\\\\?\\C:\\x",
            "C:",
            "a:b",
        ] {
            assert!(looks_like_windows_path(bad), "{bad:?}");
        }
        // On macOS/Linux a backslash is never a separator: refused fail-closed.
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        for bad in ["a\\b", "src\\a.rs"] {
            assert!(looks_like_windows_path(bad), "{bad:?}");
        }
        // On Windows a relative path keeps its native backslashes.
        #[cfg(windows)]
        for ok in ["a\\b", "src\\a.rs"] {
            assert!(!looks_like_windows_path(ok), "{ok:?}");
        }
        for ok in [
            "foo",
            "foo/bar",
            "/etc/passwd",
            "",
            "sub/ok.txt",
            "....",
            "héllo-🌍.txt",
        ] {
            assert!(!looks_like_windows_path(ok), "{ok:?}");
        }
    }

    #[test]
    fn path_to_slash_normalizes_separators() {
        assert_eq!(path_to_slash(std::path::Path::new("a/b/c")), "a/b/c");
        #[cfg(windows)]
        assert_eq!(path_to_slash(std::path::Path::new(r"a\b\c")), "a/b/c");
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        assert_eq!(path_to_slash(std::path::Path::new("a\\b")), "a\\b");
    }

    #[test]
    fn hardlink_escape_ids_compares_devices() {
        let a = FileId { dev: 1, ino: 2 };
        let b = FileId { dev: 1, ino: 3 };
        let c = FileId { dev: 2, ino: 2 };
        assert!(!hardlink_escape_ids(&a, &b));
        assert!(hardlink_escape_ids(&a, &c));
    }

    #[test]
    fn kill_argument_builders_are_stable() {
        assert_eq!(
            shell_group_kill_script(1234),
            "kill -KILL -1234 2>/dev/null || true"
        );
        assert_eq!(taskkill_args(1234), ["/T", "/F", "/PID", "1234"]);
    }

    #[test]
    fn trusted_path_env_is_built_with_the_os_separator() {
        let path = trusted_path_env();
        assert!(!path.is_empty());
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        assert!(path.to_string_lossy().contains("/usr/bin"));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn macos_shell_and_default_path_entries() {
        use std::path::PathBuf;
        assert_eq!(shell(), Some("/bin/sh"));
        assert!(default_path_entries().contains(&PathBuf::from("/usr/bin")));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn macos_file_id_comes_from_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let meta = std::fs::metadata(dir.path()).unwrap();
        assert_eq!(file_id(&meta), file_id_of_path(dir.path()));
        assert!(file_id(&meta).is_some());
    }

    #[cfg(windows)]
    #[test]
    fn windows_has_no_shell_fail_closed() {
        assert_eq!(shell(), None);
    }

    #[cfg(windows)]
    #[test]
    fn windows_file_id_and_verbatim_free_canonicalize() {
        let dir = tempfile::tempdir().unwrap();
        let id = file_id_of_path(dir.path()).expect("file information");
        assert_eq!(id, file_id_of_path(dir.path()).unwrap());
        let canon = canonicalize(dir.path()).unwrap();
        assert!(!canon.to_string_lossy().starts_with(r"\\?\"));
    }
}
