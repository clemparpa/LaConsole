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

#[derive(Clone)]
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
        let raw = normalize(input)?;
        let target = canonical_within(&self.root, &raw)?;
        check_hardlink(&self.root, &target)?;
        Ok(target)
    }
}

pub fn resolve(root: &Path, input: &str) -> Result<PathBuf, Denied> {
    Resolver::new(root)?.resolve(input)
}

fn normalize(input: &str) -> Result<PathBuf, Denied> {
    if input.contains('\0') {
        return Err(Denied::NulByte);
    }
    let mut normalized = PathBuf::new();
    for component in Path::new(input).components() {
        match component {
            Component::ParentDir => return Err(Denied::ParentDirEscape),
            Component::CurDir | Component::Prefix(_) => {}
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::Normal(seg) => normalized.push(seg),
        }
    }
    Ok(normalized)
}

fn canonical_within(root: &Path, raw: &Path) -> Result<PathBuf, Denied> {
    let joined = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        root.join(raw)
    };
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
        return Err(if raw.is_absolute() {
            Denied::AbsoluteOutsideRoot
        } else {
            Denied::SymlinkEscape
        });
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
        assert!(matches!(normalize("a\0b"), Err(Denied::NulByte)));
    }

    #[test]
    fn normalize_rejects_parent_dir() {
        assert!(matches!(normalize("../x"), Err(Denied::ParentDirEscape)));
        assert!(matches!(
            normalize("/etc/../x"),
            Err(Denied::ParentDirEscape)
        ));
    }

    #[test]
    fn normalize_keeps_absolute_verbatim() {
        assert_eq!(normalize("/etc/passwd").unwrap(), Path::new("/etc/passwd"));
    }

    #[test]
    fn normalize_collapses_curdir_and_double_slash() {
        assert_eq!(normalize("./a//b/").unwrap(), Path::new("a/b"));
    }

    #[test]
    fn canonical_within_rejects_absolute_outside_root() {
        let dir = tempfile::tempdir().unwrap();
        let resolver_root = fs::canonicalize(dir.path()).unwrap();
        assert!(matches!(
            canonical_within(&resolver_root, Path::new("/etc/passwd")),
            Err(Denied::AbsoluteOutsideRoot)
        ));
    }

    #[test]
    fn canonical_within_accepts_absolute_via_symlinked_root() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("ok.txt"), b"ok").unwrap();
        let link_parent = tempfile::tempdir().unwrap();
        let link = link_parent.path().join("rootlink");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();
        let resolver = Resolver::new(&link).unwrap();
        let resolved = resolver
            .resolve(link.join("ok.txt").to_str().unwrap())
            .unwrap();
        assert!(resolved.starts_with(resolver.root()));
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
