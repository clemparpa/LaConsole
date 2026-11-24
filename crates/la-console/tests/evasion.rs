use la_console::platform;
use la_console::platform::testutil::symlink_or_skip;
use la_console::resolve::{resolve, Denied};
use std::fs;

fn root() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("sub")).unwrap();
    fs::write(dir.path().join("sub/ok.txt"), b"ok").unwrap();
    dir
}

fn canonical_root(dir: &tempfile::TempDir) -> std::path::PathBuf {
    platform::canonicalize(dir.path()).unwrap()
}

/// A root whose absolute path contains a backslash (as on Windows, `C:\...`)
/// must not break resolution: only user input goes through the fail-closed
/// windows-path check, never the canonical root itself.
#[test]
fn root_with_backslash_in_its_path_still_works() {
    let base = tempfile::tempdir().unwrap();
    let root_path = base.path().join("weird\\root");
    fs::create_dir_all(root_path.join("src")).unwrap();
    fs::write(root_path.join("src/a.rs"), b"ok").unwrap();
    let resolved = resolve(&root_path, "src/a.rs").unwrap();
    let canon_root = platform::canonicalize(&root_path).unwrap();
    assert!(resolved.starts_with(&canon_root));
    assert!(resolved.ends_with("src/a.rs") || resolved.ends_with("src\\a.rs"));
}

#[test]
fn allows_simple_relative_path() {
    let dir = root();
    let resolved = resolve(dir.path(), "sub/ok.txt").unwrap();
    assert!(resolved.starts_with(canonical_root(&dir)));
    assert!(resolved.ends_with("sub/ok.txt"));
}

#[test]
fn denies_parent_dir() {
    let dir = root();
    assert!(matches!(
        resolve(dir.path(), "../escape"),
        Err(Denied::ParentDirEscape)
    ));
    assert!(matches!(
        resolve(dir.path(), "sub/../../escape"),
        Err(Denied::ParentDirEscape)
    ));
}

// Absolute unix paths are refused; on Windows an absolute input carries a
// drive letter and is refused as `WindowsPath` (see denies_windows_style_paths).
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn denies_absolute_outside_root() {
    let dir = root();
    assert!(matches!(
        resolve(dir.path(), "/etc/passwd"),
        Err(Denied::AbsoluteOutsideRoot)
    ));
}

/// Windows-style absolute paths (drive letter, UNC/verbatim prefix) are
/// refused fail-closed on every OS, not only on Windows.
#[test]
fn denies_windows_style_paths() {
    let dir = root();
    for bad in [
        "C:\\foo",
        "C:/foo",
        "c:foo",
        "\\\\server\\share",
        "\\\\?\\C:\\x",
        "a:b",
    ] {
        assert!(
            matches!(resolve(dir.path(), bad), Err(Denied::WindowsPath)),
            "{bad}"
        );
    }
}

/// On macOS/Linux a backslash is never a path separator: refused fail-closed (on
/// Windows a relative `a\b` keeps its native backslashes and stays valid).
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn denies_backslash_paths_on_macos_linux() {
    let dir = root();
    for bad in ["a\\b", "src\\a.rs"] {
        assert!(
            matches!(resolve(dir.path(), bad), Err(Denied::WindowsPath)),
            "{bad}"
        );
    }
}

// On Windows every absolute input carries a drive letter and is refused as
// `WindowsPath` (fail-closed): only relative inputs are accepted there.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn allows_absolute_inside_root() {
    let dir = root();
    let abs = dir.path().join("sub/ok.txt");
    let resolved = resolve(dir.path(), abs.to_str().unwrap()).unwrap();
    assert!(resolved.starts_with(canonical_root(&dir)));
}

#[test]
fn allows_root_passed_via_symlink() {
    let dir = root();
    let link_parent = tempfile::tempdir().unwrap();
    let link = link_parent.path().join("rootlink");
    if !symlink_or_skip(dir.path(), &link) {
        return;
    }
    let resolved = resolve(&link, "sub/ok.txt").unwrap();
    assert!(resolved.starts_with(canonical_root(&dir)));
    // Absolute input through the symlinked root: macOS/Linux-only (on Windows it is
    // a drive-letter path, refused as `WindowsPath`).
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let abs = link.join("sub/ok.txt");
        let resolved = resolve(&link, abs.to_str().unwrap()).unwrap();
        assert!(resolved.starts_with(canonical_root(&dir)));
    }
}

#[test]
fn denies_symlink_escape() {
    let dir = root();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret.txt"), b"secret").unwrap();
    if !symlink_or_skip(
        &outside.path().join("secret.txt"),
        &dir.path().join("link.txt"),
    ) {
        return;
    }
    assert!(matches!(
        resolve(dir.path(), "link.txt"),
        Err(Denied::SymlinkEscape)
    ));
}

#[test]
fn denies_symlink_dir_escape() {
    let dir = root();
    let outside = tempfile::tempdir().unwrap();
    if !symlink_or_skip(outside.path(), &dir.path().join("linkdir")) {
        return;
    }
    assert!(matches!(
        resolve(dir.path(), "linkdir/anything"),
        Err(Denied::SymlinkEscape)
    ));
}

// Hardlink detection via the link count (`nlink`) is macOS/Linux-only; on Windows
// a same-volume hardlink is undetectable (documented in spec/security.md).
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn denies_hardlink_escape() {
    let dir = root();
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("target.txt");
    fs::write(&target, b"x").unwrap();
    fs::hard_link(&target, dir.path().join("hard.txt")).unwrap();
    assert!(matches!(
        resolve(dir.path(), "hard.txt"),
        Err(Denied::HardlinkEscape)
    ));
}

#[test]
fn denies_nul_byte() {
    let dir = root();
    assert!(matches!(resolve(dir.path(), "a\0b"), Err(Denied::NulByte)));
}

#[test]
fn allows_double_slash_and_trailing_slash() {
    let dir = root();
    let resolved = resolve(dir.path(), "sub//ok.txt").unwrap();
    assert!(resolved.ends_with("sub/ok.txt"));
    let resolved = resolve(dir.path(), "sub/").unwrap();
    assert!(resolved.ends_with("sub"));
}

#[test]
fn allows_unicode_path() {
    let dir = root();
    fs::write(dir.path().join("héllo-🌍.txt"), b"ok").unwrap();
    let resolved = resolve(dir.path(), "héllo-🌍.txt").unwrap();
    assert!(resolved.ends_with("héllo-🌍.txt"));
}

#[test]
fn dotdot_like_names_are_literal() {
    let dir = root();
    let resolved = resolve(dir.path(), "..x//").unwrap();
    assert!(resolved.ends_with("..x"));
}

/// Win32 tronque les points/espaces de fin de nom ("...." devient ""), donc ce
/// cas n'existe pas tel quel sur Windows : macOS/Linux-only.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn trailing_dots_name_is_literal_on_macos_linux() {
    let dir = root();
    let resolved = resolve(dir.path(), "....//").unwrap();
    assert!(resolved.ends_with("...."));
}

mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn never_escapes_root(input in any::<String>()) {
            let dir = root();
            if let Ok(resolved) = resolve(dir.path(), &input) {
                let canonical_root = platform::canonicalize(dir.path()).unwrap();
                prop_assert!(resolved.starts_with(&canonical_root));
            }
        }
    }
}
