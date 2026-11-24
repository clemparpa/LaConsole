use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::platform;

#[derive(Debug, thiserror::Error)]
pub enum Denied {
    #[error("absolute path not under root")]
    AbsoluteOutsideRoot,
    #[error("path escapes root via parent directory")]
    ParentDirEscape,
    #[error("path contains NUL byte")]
    NulByte,
    #[error("windows-style path refused (drive letter, backslash or UNC prefix)")]
    WindowsPath,
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
            root: platform::canonicalize(root)?,
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
    // Fail-closed on every OS: a Windows-style path (drive letter, backslash,
    // UNC/verbatim prefix) is never a valid input for the confinement.
    if platform::looks_like_windows_path(input) {
        return Err(Denied::WindowsPath);
    }
    let mut normalized = PathBuf::new();
    for component in Path::new(input).components() {
        match component {
            Component::ParentDir => return Err(Denied::ParentDirEscape),
            Component::CurDir => {}
            Component::Prefix(_) => return Err(Denied::WindowsPath),
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
    let canonical_probe = platform::canonicalize(&probe)?;
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
    if fs::symlink_metadata(target).is_ok() && platform::hardlink_escape(root, target) {
        return Err(Denied::HardlinkEscape);
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
    fn normalize_rejects_windows_style_paths_fail_closed() {
        for bad in [
            "C:\\foo",
            "C:/foo",
            "c:foo",
            "\\\\server\\share",
            "\\\\?\\C:\\x",
            "a:b",
        ] {
            assert!(matches!(normalize(bad), Err(Denied::WindowsPath)), "{bad}");
        }
        // On macOS/Linux a backslash is never a separator: refused fail-closed too.
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        for bad in ["a\\b", "src\\a.rs"] {
            assert!(matches!(normalize(bad), Err(Denied::WindowsPath)), "{bad}");
        }
    }

    #[test]
    fn canonical_within_rejects_absolute_outside_root() {
        let dir = tempfile::tempdir().unwrap();
        let resolver_root = platform::canonicalize(dir.path()).unwrap();
        // Absolute path outside the root, built from the tempdir's parent so
        // it is absolute on every OS (on Windows a `C:\...` input never gets
        // here: `normalize()` refuses it with `WindowsPath` first).
        let outside = dir.path().parent().unwrap().join("la-console-outside.txt");
        assert!(outside.is_absolute());
        assert!(matches!(
            canonical_within(&resolver_root, &outside),
            Err(Denied::AbsoluteOutsideRoot)
        ));
    }

    #[test]
    fn canonical_within_accepts_absolute_via_symlinked_root() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("ok.txt"), b"ok").unwrap();
        let link_parent = tempfile::tempdir().unwrap();
        let link = link_parent.path().join("rootlink");
        assert!(platform::testutil::symlink_or_skip(dir.path(), &link));
        let resolver = Resolver::new(&link).unwrap();
        // `canonical_within` takes an already-normalized path: an absolute
        // path through the symlinked root must land inside the canonical root.
        let abs = link.join("ok.txt");
        let resolved = canonical_within(resolver.root(), &abs).unwrap();
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
