use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum Denied {
    #[error("absolute path not under root")]
    AbsoluteOutsideRoot,
    #[error("path escapes root via parent directory")]
    ParentDirEscape,
    #[error("path contains NUL byte")]
    NulByte,
    #[error("symlink resolves outside root")]
    SymlinkEscape,
    #[error("hardlink or foreign device outside root")]
    HardlinkEscape,
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

pub fn resolve(root: &Path, input: &str) -> Result<PathBuf, Denied> {
    if input.contains('\0') {
        return Err(Denied::NulByte);
    }

    let root = fs::canonicalize(root)?;
    let candidate = Path::new(input);

    let relative: PathBuf = if candidate.is_absolute() {
        match candidate.strip_prefix(&root) {
            Ok(rel) => rel.to_path_buf(),
            Err(_) => return Err(Denied::AbsoluteOutsideRoot),
        }
    } else {
        candidate.to_path_buf()
    };

    let mut normalized = PathBuf::new();
    for component in relative.components() {
        match component {
            Component::ParentDir => return Err(Denied::ParentDirEscape),
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
            Component::Normal(seg) => normalized.push(seg),
        }
    }

    let joined = root.join(&normalized);

    let mut probe = joined.clone();
    while !probe.exists() {
        match probe.parent() {
            Some(parent) if parent != probe => probe = parent.to_path_buf(),
            _ => break,
        }
    }

    let canonical_probe = fs::canonicalize(&probe)?;
    let remainder = joined
        .strip_prefix(&probe)
        .unwrap_or_else(|_| Path::new(""));
    let canonical_target = if remainder.as_os_str().is_empty() {
        canonical_probe
    } else {
        canonical_probe.join(remainder)
    };

    if !canonical_target.starts_with(&root) {
        return Err(Denied::SymlinkEscape);
    }

    if let Ok(meta) = fs::symlink_metadata(&canonical_target) {
        let root_meta = fs::metadata(&root)?;
        if meta.dev() != root_meta.dev() {
            return Err(Denied::HardlinkEscape);
        }
        if meta.is_file() && meta.nlink() > 1 {
            return Err(Denied::HardlinkEscape);
        }
    }

    Ok(canonical_target)
}
