use la_console::resolve::{resolve, Denied};
use std::fs;
use std::os::unix::fs::symlink;

fn root() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("sub")).unwrap();
    fs::write(dir.path().join("sub/ok.txt"), b"ok").unwrap();
    dir
}

fn canonical_root(dir: &tempfile::TempDir) -> std::path::PathBuf {
    fs::canonicalize(dir.path()).unwrap()
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

#[test]
fn denies_absolute_outside_root() {
    let dir = root();
    assert!(matches!(
        resolve(dir.path(), "/etc/passwd"),
        Err(Denied::AbsoluteOutsideRoot)
    ));
}

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
    symlink(dir.path(), &link).unwrap();
    let resolved = resolve(&link, "sub/ok.txt").unwrap();
    assert!(resolved.starts_with(canonical_root(&dir)));
    let abs = link.join("sub/ok.txt");
    let resolved = resolve(&link, abs.to_str().unwrap()).unwrap();
    assert!(resolved.starts_with(canonical_root(&dir)));
}

#[test]
fn denies_symlink_escape() {
    let dir = root();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret.txt"), b"secret").unwrap();
    symlink(
        outside.path().join("secret.txt"),
        dir.path().join("link.txt"),
    )
    .unwrap();
    assert!(matches!(
        resolve(dir.path(), "link.txt"),
        Err(Denied::SymlinkEscape)
    ));
}

#[test]
fn denies_symlink_dir_escape() {
    let dir = root();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), dir.path().join("linkdir")).unwrap();
    assert!(matches!(
        resolve(dir.path(), "linkdir/anything"),
        Err(Denied::SymlinkEscape)
    ));
}

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
                let canonical_root = fs::canonicalize(dir.path()).unwrap();
                prop_assert!(resolved.starts_with(&canonical_root));
            }
        }
    }
}
