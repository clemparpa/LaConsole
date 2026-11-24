//! Windows-native implementations — phase 1 of spec/platform.md runs
//! fail-closed here: no shell (`trusted` denied), no POSIX process groups
//! (`taskkill /T` instead), no seatbelt/WSL2 backend yet.
//!
//! Note on file identity: `std::os::windows::fs::MetadataExt::
//! {volume_serial_number, file_index}` is nightly-only and `same-file` 1.x
//! only exposes `dev()`/`ino()` on unix, so the id is read from the path via
//! `winapi-util` (`GetFileInformationByHandle`: volume serial + file index +
//! link count); `file_id(&Metadata)` returns `None` on Windows.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};

use super::{hardlink_escape_ids, taskkill_args, FileId};

/// `dunce::canonicalize`: like `fs::canonicalize` but without the verbatim
/// `\\?\` prefix, so path comparisons stay byte-comparable with user input.
pub fn canonicalize(path: &Path) -> io::Result<PathBuf> {
    dunce::canonicalize(path)
}

pub fn file_id(_meta: &fs::Metadata) -> Option<FileId> {
    None
}

/// `(FileId, link count)` read from the path via `GetFileInformationByHandle`.
fn file_info(path: &Path) -> Option<(FileId, u64)> {
    let handle = winapi_util::Handle::from_path_any(path).ok()?;
    let info = winapi_util::file::information(&handle).ok()?;
    Some((
        FileId {
            dev: info.volume_serial_number(),
            ino: info.file_index(),
        },
        info.number_of_links(),
    ))
}

pub fn file_id_of_path(path: &Path) -> Option<FileId> {
    file_info(path).map(|(id, _)| id)
}

/// Refuses when the target lives on another volume than the root, or when
/// its link count is above 1 (hardlink, visible on Windows too via
/// `nNumberOfLinks`). Any uncertainty (handle unavailable) is fail-closed:
/// escape. Residual: on ReFS the 64-bit file index is not guaranteed unique
/// (same caveat as same-file), documented in spec/security.md.
pub fn hardlink_escape(root: &Path, target: &Path) -> bool {
    match (file_info(root), file_info(target)) {
        (Some((root_id, _)), Some((target_id, nlink))) => {
            hardlink_escape_ids(&root_id, &target_id) || nlink > 1
        }
        _ => true,
    }
}

/// No shell on Windows native in phase 1: `trusted` is denied fail-closed.
pub fn shell() -> Option<&'static str> {
    None
}

pub fn default_path_entries() -> Vec<PathBuf> {
    vec![
        PathBuf::from(r"C:\Windows\System32"),
        PathBuf::from(r"C:\Windows"),
    ]
}

/// No POSIX process groups on Windows: no-op (the tree kill uses
/// `taskkill /T /F`).
pub fn set_new_process_group(_cmd: &mut Command) {}

/// Kills the child (always), then the whole tree best-effort via
/// `taskkill /T /F /PID <pid>`.
pub fn kill_process_tree(child: &mut Child) {
    let _ = child.kill();
    let _ = Command::new("taskkill")
        .args(taskkill_args(child.id()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// No signals on Windows: the native exit code, truncated to `u16`.
pub fn exit_code(status: &ExitStatus) -> u16 {
    status.code().unwrap_or(1) as u16
}

#[doc(hidden)]
pub mod testutil {
    use std::path::Path;

    pub fn symlink(original: &Path, link: &Path) -> std::io::Result<()> {
        if std::fs::metadata(original)
            .map(|meta| meta.is_dir())
            .unwrap_or(false)
        {
            std::os::windows::fs::symlink_dir(original, link)
        } else {
            std::os::windows::fs::symlink_file(original, link)
        }
    }

    /// No unix exec bit on Windows: no-op.
    pub fn set_exec_mode(_path: &Path) -> std::io::Result<()> {
        Ok(())
    }
}
