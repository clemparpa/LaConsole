use clap::ValueEnum;
use std::ffi::OsString;
use std::path::Path;

/// Deployment mode of the console.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// Local use on a user machine (macOS or Linux): pure-Rust confinement
    /// only (`resolve()` + bounds). This is the default and works everywhere.
    User,
    /// Server deployment, Linux only: the process re-execs itself inside an
    /// unprivileged user namespace + chroot, so the kernel blocks any escape
    /// even if the Rust confinement had a bug (defense in depth).
    Server,
}

/// Environment marker set on the sandboxed child, as a second guard against
/// re-exec loops (the `--inside-sandbox` flag is the primary one).
pub const ENV_MARKER: &str = "LA_CONSOLE_SANDBOXED";

/// Name of the staged binary copy placed at the top of the chroot so the
/// re-exec can find itself inside the cage. Removed again at startup.
#[cfg(target_os = "linux")]
const STAGED_BIN: &str = ".la-console-sandbox-bin";

/// Directory (inside the chroot) holding the shared libraries the staged
/// dynamic binary needs, exposed via `LD_LIBRARY_PATH`.
#[cfg(target_os = "linux")]
const STAGED_LIBS_DIR: &str = ".la-console-sandbox-libs";

/// Startup gate. Returns `Ok(())` when the process should run normally;
/// on Linux with `Mode::Server` and no sandbox marker present, it re-execs
/// the current binary inside `unshare` and this function only returns on
/// failure. On other platforms `Mode::Server` is refused fail-closed.
pub fn gate(
    mode: Mode,
    inside_sandbox: bool,
    root: &Path,
    forward: &[OsString],
) -> Result<(), String> {
    if mode == Mode::User || inside_sandbox || std::env::var_os(ENV_MARKER).is_some() {
        return Ok(());
    }
    reexec_sandboxed(root, forward)
}

/// Removes the staged binary copy and staged libraries from the top of the
/// chroot. Called once at startup when running with `--inside-sandbox`;
/// best-effort.
pub fn cleanup_staged_bin() {
    #[cfg(target_os = "linux")]
    {
        let _ = std::fs::remove_file(format!("/{STAGED_BIN}"));
        let _ = std::fs::remove_dir_all(format!("/{STAGED_LIBS_DIR}"));
    }
}

#[cfg(target_os = "linux")]
fn reexec_sandboxed(root: &Path, forward: &[OsString]) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe().map_err(|err| format!("cannot locate self: {err}"))?;
    let in_cage_exe = stage_binary(&exe, root)?;
    let mut cmd = build_unshare_command(&in_cage_exe, root, forward);
    cmd.env(ENV_MARKER, "1");
    let err = cmd.exec();
    Err(format!(
        "cannot enter sandbox (unshare --user --map-root-user --mount --root): {err}"
    ))
}

/// The re-exec happens after the chroot, so the binary must be reachable by a
/// path inside the cage. If it already lives under `root`, use its in-cage
/// path; otherwise stage a private copy at the top of the root, along with
/// the dynamic loader and shared libraries it needs (a statically linked
/// binary needs none of that).
#[cfg(target_os = "linux")]
fn stage_binary(exe: &Path, root: &Path) -> Result<OsString, String> {
    use std::os::unix::fs::PermissionsExt;
    let in_cage_exe = match exe.strip_prefix(root) {
        Ok(rel) => OsString::from(format!("/{}", rel.display())),
        Err(_) => {
            let staged = root.join(STAGED_BIN);
            std::fs::copy(exe, &staged)
                .map_err(|err| format!("cannot stage binary into {}: {err}", staged.display()))?;
            std::fs::set_permissions(&staged, PermissionsExt::from_mode(0o700))
                .map_err(|err| format!("cannot chmod staged binary: {err}"))?;
            OsString::from(format!("/{STAGED_BIN}"))
        }
    };
    stage_dynamic_deps(exe, root)?;
    Ok(in_cage_exe)
}

/// Parses `ldd` output of our own binary and copies the ELF interpreter (to
/// its absolute path inside the cage, which is hardcoded in the binary) and
/// every shared library (into the staged libs dir) under `root`.
#[cfg(target_os = "linux")]
fn stage_dynamic_deps(exe: &Path, root: &Path) -> Result<(), String> {
    let output = std::process::Command::new("ldd")
        .arg(exe)
        .output()
        .map_err(|err| format!("cannot run ldd on {}: {err}", exe.display()))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut interpreter: Option<String> = None;
    let mut libs: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some((_, rhs)) = line.split_once("=>") {
            if let Some(path) = rhs.split_whitespace().next() {
                if path.starts_with('/') {
                    libs.push(path.to_string());
                }
            }
        } else if line.starts_with('/') {
            if let Some(path) = line.split_whitespace().next() {
                interpreter = Some(path.to_string());
            }
        }
    }
    if let Some(interp) = interpreter {
        copy_into_cage(Path::new(&interp), root)?;
    }
    if !libs.is_empty() {
        let libs_dir = root.join(STAGED_LIBS_DIR);
        std::fs::create_dir_all(&libs_dir)
            .map_err(|err| format!("cannot create {}: {err}", libs_dir.display()))?;
        for lib in libs {
            let src = Path::new(&lib);
            let Some(name) = src.file_name() else {
                continue;
            };
            std::fs::copy(src, libs_dir.join(name))
                .map_err(|err| format!("cannot stage {lib}: {err}"))?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn copy_into_cage(abs: &Path, root: &Path) -> Result<(), String> {
    let rel = abs
        .strip_prefix("/")
        .map_err(|_| format!("not an absolute path: {}", abs.display()))?;
    let dst = root.join(rel);
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("cannot create {}: {err}", parent.display()))?;
    }
    std::fs::copy(abs, &dst).map_err(|err| format!("cannot stage {}: {err}", abs.display()))?;
    Ok(())
}

/// Builds `unshare --user --map-root-user --mount --root <root> --wd /
/// <in-cage-exe> --root / --inside-sandbox <forward...>`. Inside the chroot
/// the workspace is the whole filesystem, so the console relaunches with
/// `--root /`.
#[cfg(target_os = "linux")]
fn build_unshare_command(
    in_cage_exe: &OsString,
    root: &Path,
    forward: &[OsString],
) -> std::process::Command {
    let mut cmd = std::process::Command::new("unshare");
    cmd.arg("--user")
        .arg("--map-root-user")
        .arg("--mount")
        .arg("--root")
        .arg(root)
        .arg("--wd")
        .arg("/")
        .arg(in_cage_exe)
        .arg("--root")
        .arg("/")
        .arg("--inside-sandbox")
        .args(forward)
        .env("LD_LIBRARY_PATH", format!("/{STAGED_LIBS_DIR}"));
    cmd
}

#[cfg(not(target_os = "linux"))]
fn reexec_sandboxed(_root: &Path, _forward: &[OsString]) -> Result<(), String> {
    Err("--mode server requires Linux (unprivileged user namespaces + chroot); use --mode user on this platform".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_mode_never_reexecs() {
        assert!(gate(Mode::User, false, Path::new("/tmp"), &[]).is_ok());
    }

    #[test]
    fn inside_sandbox_flag_short_circuits_even_in_server_mode() {
        assert!(gate(Mode::Server, true, Path::new("/tmp"), &[]).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unshare_command_shape() {
        let in_cage_exe = OsString::from("/.la-console-sandbox-bin");
        let root = Path::new("/srv/workspace");
        let forward: Vec<OsString> = vec![
            OsString::from("--timeout-secs"),
            OsString::from("30"),
            OsString::from("--trusted-file"),
            OsString::from("trusted.txt"),
        ];
        let cmd = build_unshare_command(&in_cage_exe, root, &forward);
        assert_eq!(cmd.get_program(), "unshare");
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            vec![
                "--user",
                "--map-root-user",
                "--mount",
                "--root",
                "/srv/workspace",
                "--wd",
                "/",
                "/.la-console-sandbox-bin",
                "--root",
                "/",
                "--inside-sandbox",
                "--timeout-secs",
                "30",
                "--trusted-file",
                "trusted.txt",
            ]
        );
        let envs: Vec<(String, String)> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.unwrap().to_string_lossy().into_owned(),
                )
            })
            .collect();
        assert!(envs.contains(&("LD_LIBRARY_PATH".to_string(), format!("/{STAGED_LIBS_DIR}"))));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stage_binary_reuses_exe_already_under_root() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("bin/la-console");
        let staged = stage_binary(&exe, dir.path()).unwrap();
        assert_eq!(staged, OsString::from("/bin/la-console"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stage_binary_copies_exe_from_outside_root() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let exe = outside.path().join("la-console");
        std::fs::write(&exe, b"ELF").unwrap();
        let staged = stage_binary(&exe, dir.path()).unwrap();
        assert_eq!(staged, OsString::from(format!("/{STAGED_BIN}")));
        assert_eq!(std::fs::read(dir.path().join(STAGED_BIN)).unwrap(), b"ELF");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn server_mode_is_refused_off_linux() {
        let err = gate(Mode::Server, false, Path::new("/tmp"), &[]).unwrap_err();
        assert!(err.contains("requires Linux"), "got: {err}");
    }
}
