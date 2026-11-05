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

pub struct Resolver {
    root: PathBuf,
}

impl Resolver {
    pub fn new(root: &Path) -> Result<Self, Denied> {
        Ok(Self {
            root: fs::canonicalize(root)?,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn resolve(&self, input: &str) -> Result<PathBuf, Denied> {
        let relative = normalize_relative(&self.root, input)?;
        let target = canonical_within(&self.root, &relative)?;
        check_hardlink(&self.root, &target)?;
        Ok(target)
    }
}

pub fn resolve(root: &Path, input: &str) -> Result<PathBuf, Denied> {
    Resolver::new(root)?.resolve(input)
}

fn normalize_relative(root: &Path, input: &str) -> Result<PathBuf, Denied> {
    if input.contains('\0') {
        return Err(Denied::NulByte);
    }
    let candidate = Path::new(input);
    let relative: PathBuf = if candidate.is_absolute() {
        match candidate.strip_prefix(root) {
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
    Ok(normalized)
}

fn canonical_within(root: &Path, relative: &Path) -> Result<PathBuf, Denied> {
    let joined = root.join(relative);
    let mut probe = joined.clone();
    while fs::symlink_metadata(&probe).is_err() {
        match probe.parent() {
            Some(parent) if parent != probe => probe = parent.to_path_buf(),
            _ => break,
        }
    }
    let canonical_probe = fs::canonicalize(&probe)?;
    let remainder = joined
        .strip_prefix(&probe)
        .unwrap_or_else(|_| Path::new(""));
    let target = if remainder.as_os_str().is_empty() {
        canonical_probe
    } else {
        canonical_probe.join(remainder)
    };
    if !target.starts_with(root) {
        return Err(Denied::SymlinkEscape);
    }
    Ok(target)
}

fn check_hardlink(root: &Path, target: &Path) -> Result<(), Denied> {
    if let Ok(meta) = fs::symlink_metadata(target) {
        let root_meta = fs::metadata(root)?;
        if meta.dev() != root_meta.dev() {
            return Err(Denied::HardlinkEscape);
        }
        if meta.is_file() && meta.nlink() > 1 {
            return Err(Denied::HardlinkEscape);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_rejects_nul() {
        let root = Path::new("/tmp");
        assert!(matches!(
            normalize_relative(root, "a\0b"),
            Err(Denied::NulByte)
        ));
    }

    #[test]
    fn normalize_rejects_parent_dir() {
        let root = Path::new("/tmp");
        assert!(matches!(
            normalize_relative(root, "../x"),
            Err(Denied::ParentDirEscape)
        ));
    }

    #[test]
    fn normalize_rejects_absolute_outside_root() {
        let root = Path::new("/tmp/root");
        assert!(matches!(
            normalize_relative(root, "/etc/passwd"),
            Err(Denied::AbsoluteOutsideRoot)
        ));
    }

    #[test]
    fn normalize_strips_absolute_inside_root() {
        let root = Path::new("/tmp/root");
        let rel = normalize_relative(root, "/tmp/root/a/b.txt").unwrap();
        assert_eq!(rel, Path::new("a/b.txt"));
    }

    #[test]
    fn normalize_collapses_curdir_and_double_slash() {
        let root = Path::new("/tmp/root");
        let rel = normalize_relative(root, "./a//b/").unwrap();
        assert_eq!(rel, Path::new("a/b"));
    }

    #[test]
    fn resolver_reuses_canonical_root() {
        let dir = tempfile::tempdir().unwrap();
        let resolver = Resolver::new(dir.path()).unwrap();
        assert!(resolver.root().is_absolute());
        let resolved = resolver.resolve("x.txt").unwrap();
        assert!(resolved.starts_with(resolver.root()));
    }
}
