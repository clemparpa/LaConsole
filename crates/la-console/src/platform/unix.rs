//! Unix (Linux + macOS) implementations of the platform primitives.
//! Behavior is identical to the v1 unix-only code.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};

use super::{group_kill_args, hardlink_escape_ids, shell_group_kill_script, FileId};

pub fn canonicalize(path: &Path) -> io::Result<PathBuf> {
    fs::canonicalize(path)
}

pub fn file_id(meta: &fs::Metadata) -> Option<FileId> {
    use std::os::unix::fs::MetadataExt;
    Some(FileId {
        dev: meta.dev(),
        ino: meta.ino(),
    })
}

pub fn file_id_of_path(path: &Path) -> Option<FileId> {
    fs::metadata(path).ok().and_then(|meta| file_id(&meta))
}

/// A hardlink escapes the root when the target lives on another device, or
/// when it is a file with a link count above 1 (visible on unix). Any
/// uncertainty (unreadable metadata, no file id) is fail-closed: escape.
pub fn hardlink_escape(root: &Path, target: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let (Ok(root_meta), Ok(target_meta)) = (fs::metadata(root), fs::symlink_metadata(target))
    else {
        return true;
    };
    match (file_id(&root_meta), file_id(&target_meta)) {
        (Some(root_id), Some(target_id)) => {
            hardlink_escape_ids(&root_id, &target_id)
                || (target_meta.is_file() && target_meta.nlink() > 1)
        }
        _ => true,
    }
}

pub fn shell() -> Option<&'static str> {
    Some("/bin/sh")
}

pub fn default_path_entries() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/usr/local/bin"),
        PathBuf::from("/usr/bin"),
        PathBuf::from("/bin"),
    ]
}

pub fn set_new_process_group(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    cmd.process_group(0);
}

/// Kills the child (always) and then its whole process group (best-effort
/// via the same shell used to spawn it, since the child was spawned with
/// `process_group(0)` so pgid == child pid).
pub fn kill_process_tree(child: &mut Child, cage_shell: Option<&str>) {
    let _ = child.kill();
    let pgid = child.id();
    let result = match cage_shell {
        Some(busybox) => Command::new(busybox)
            .args(group_kill_args(pgid))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
        None => match shell() {
            Some(sh) => Command::new(sh)
                .arg("-c")
                .arg(shell_group_kill_script(pgid))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status(),
            None => return,
        },
    };
    let _ = result;
}

pub fn exit_code(status: &ExitStatus) -> u16 {
    use std::os::unix::process::ExitStatusExt;
    status
        .signal()
        .map(|s| 128 + s)
        .or_else(|| status.code())
        .unwrap_or(1) as u16
}

#[doc(hidden)]
pub mod testutil {
    use std::path::Path;

    pub fn symlink(original: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(original, link)
    }

    pub fn set_exec_mode(path: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
    }
}
