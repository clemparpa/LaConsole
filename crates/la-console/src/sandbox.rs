use clap::ValueEnum;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

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

/// In-cage path of the staged static busybox (when `--sandbox-busybox` is
/// given): it provides the shell (`busybox sh`) and the core applets used by
/// `trusted` commands in server mode.
pub const CAGE_BUSYBOX: &str = "/bin/busybox";

/// In-cage directory receiving the operator-provided toolchain
/// (`--sandbox-tools-dir`, e.g. git + go) copied wholesale into the cage.
pub const CAGE_TOOLS_DIR: &str = "/opt/la-console-tools";

/// In-cage directory holding staged shared libraries (console binary + tool
/// ELF deps), exposed to trusted children via `LD_LIBRARY_PATH`.
pub const CAGE_LIBS_DIR: &str = "/.la-console-sandbox-libs";

/// PATH given to trusted commands running inside the cage: busybox applets
/// (symlinked in /bin) plus the staged toolchain.
pub const CAGE_TRUSTED_PATH: &str = "/bin:/opt/la-console-tools/bin:/opt/la-console-tools/go/bin";

/// Operator-provided content staged into the chroot before the re-exec, so the
/// cage is not empty in server mode. All fields are optional; without a
/// busybox, `trusted` commands stay denied in server mode (fail-closed).
#[derive(Clone, Debug, Default)]
pub struct SandboxImage {
    /// Host path to a **static** busybox binary (verified via `ldd`).
    pub busybox: Option<PathBuf>,
    /// Optional sha256 pin of the busybox binary (hex, lowercase).
    pub busybox_sha256: Option<String>,
    /// Optional host directory (git, go toolchain, ...) copied into the cage
    /// at `CAGE_TOOLS_DIR`; every ELF file found in it gets its dynamic
    /// dependencies (loader + libs) staged too.
    pub tools_dir: Option<PathBuf>,
}

/// Startup gate. Returns `Ok(())` when the process should run normally;
/// on Linux with `Mode::Server` and no sandbox marker present, it stages the
/// cage image and re-execs the current binary inside `unshare`; this function
/// only returns on failure. On other platforms `Mode::Server` is refused
/// fail-closed.
pub fn gate(
    mode: Mode,
    inside_sandbox: bool,
    root: &Path,
    forward: &[OsString],
    image: &SandboxImage,
) -> Result<(), String> {
    if mode == Mode::User || inside_sandbox || std::env::var_os(ENV_MARKER).is_some() {
        return Ok(());
    }
    reexec_sandboxed(root, forward, image)
}

/// In-cage shell used for `trusted` commands in server mode: the staged
/// busybox, when present. `None` inside the cage without `--sandbox-busybox`.
pub fn cage_shell() -> Option<&'static str> {
    #[cfg(target_os = "linux")]
    {
        if Path::new(CAGE_BUSYBOX).is_file() {
            return Some(CAGE_BUSYBOX);
        }
    }
    None
}

/// Removes the staged binary copy from the top of the chroot. Called once at
/// startup when running with `--inside-sandbox`; best-effort. The staged
/// libs dir is kept when a tools dir was staged (tool ELF deps live there and
/// are needed by trusted children at exec time).
pub fn cleanup_staged_bin() {
    #[cfg(target_os = "linux")]
    {
        let _ = std::fs::remove_file(format!("/{STAGED_BIN}"));
        if !Path::new(CAGE_TOOLS_DIR).exists() {
            let _ = std::fs::remove_dir_all(format!("/{STAGED_LIBS_DIR}"));
        }
    }
}

/// Defense in depth, fail-closed: remount the staged cage image read-only
/// (bind + remount,ro) via the staged busybox `mount` applet. The process is
/// root inside its own user namespace, so it holds CAP_SYS_ADMIN over the
/// unshared mount namespace and the remount cannot leak to the host. Without
/// this, the agent could overwrite `/bin/busybox` or a staged tool through
/// ordinary whitelist writes (everything under the chroot root is writable)
/// and have that tampered binary run inside later `trusted` commands. Any
/// failure is returned as an error and the caller must abort (exit 2): the
/// chroot + userns still confine escapes, but a writable cage image is not an
/// acceptable deployment. No-op outside Linux or without a staged busybox
/// (in that case `trusted` stays denied, so there is nothing executable to
/// protect).
pub fn protect_cage_tools() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let busybox = Path::new(CAGE_BUSYBOX);
        if !busybox.is_file() {
            return Ok(());
        }
        let mut targets = vec!["/bin".to_string()];
        for path in [CAGE_TOOLS_DIR, CAGE_LIBS_DIR] {
            if Path::new(path).exists() {
                targets.push(path.to_string());
            }
        }
        for target in &targets {
            remount_read_only(busybox, target)?;
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(())
    }
}

/// Bind-mounts `target` onto itself then remounts it read-only via the staged
/// busybox `mount` applet; any failure is an error.
#[cfg(target_os = "linux")]
fn remount_read_only(busybox: &Path, target: &str) -> Result<(), String> {
    let bind = std::process::Command::new(busybox)
        .arg("mount")
        .arg("-o")
        .arg("bind")
        .arg(target)
        .arg(target)
        .status();
    let remount = std::process::Command::new(busybox)
        .arg("mount")
        .arg("-o")
        .arg("remount,ro")
        .arg(target)
        .status();
    if !matches!(bind, Ok(s) if s.success()) || !matches!(remount, Ok(s) if s.success()) {
        return Err(format!(
            "could not remount {target} read-only in the cage (refusing to run with a writable cage image)"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn reexec_sandboxed(root: &Path, forward: &[OsString], image: &SandboxImage) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe().map_err(|err| format!("cannot locate self: {err}"))?;
    let in_cage_exe = stage_binary(&exe, root)?;
    stage_image(root, image)?;
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
    let (interpreter, libs) = ldd_deps(exe)?;
    stage_deps(&interpreter, &libs, root)
}

/// Runs `ldd` on `exe` and returns the ELF interpreter (absolute path) and the
/// shared libraries it needs.
#[cfg(target_os = "linux")]
fn ldd_deps(exe: &Path) -> Result<(Option<String>, Vec<String>), String> {
    let output = std::process::Command::new("ldd")
        .arg(exe)
        .output()
        .map_err(|err| format!("cannot run ldd on {}: {err}", exe.display()))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
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
    Ok((interpreter, libs))
}

/// Copies the ELF interpreter (to its absolute in-cage path) and every shared
/// library (into the staged libs dir) under `root`.
#[cfg(target_os = "linux")]
fn stage_deps(interpreter: &Option<String>, libs: &[String], root: &Path) -> Result<(), String> {
    if let Some(interp) = interpreter {
        copy_into_cage(Path::new(interp), root)?;
    }
    if !libs.is_empty() {
        let libs_dir = root.join(STAGED_LIBS_DIR);
        std::fs::create_dir_all(&libs_dir)
            .map_err(|err| format!("cannot create {}: {err}", libs_dir.display()))?;
        for lib in libs {
            let src = Path::new(lib);
            let Some(name) = src.file_name() else {
                continue;
            };
            std::fs::copy(src, libs_dir.join(name))
                .map_err(|err| format!("cannot stage {lib}: {err}"))?;
        }
    }
    Ok(())
}

/// Stages the operator-provided cage image (busybox + tools dir) under `root`.
#[cfg(target_os = "linux")]
fn stage_image(root: &Path, image: &SandboxImage) -> Result<(), String> {
    if let Some(busybox) = &image.busybox {
        stage_busybox(busybox, image.busybox_sha256.as_deref(), root)?;
    }
    if let Some(tools_dir) = &image.tools_dir {
        stage_tools_dir(tools_dir, root)?;
    }
    Ok(())
}

/// Verifies the busybox binary (ELF magic, optional sha256 pin, statically
/// linked), copies it to `<root>/bin/busybox` (mode 0555) and symlinks every
/// applet into `<root>/bin` so `trusted` commands resolve `sh`, `ls`, ... by
/// name through the cage PATH.
#[cfg(target_os = "linux")]
fn stage_busybox(busybox: &Path, expected_sha256: Option<&str>, root: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(busybox)
        .map_err(|err| format!("cannot stat busybox {}: {err}", busybox.display()))?;
    if !meta.is_file() {
        return Err(format!(
            "busybox {} is not a regular file",
            busybox.display()
        ));
    }
    if !is_elf(busybox) {
        return Err(format!(
            "busybox {} is not an ELF binary (refusing to stage it)",
            busybox.display()
        ));
    }
    if let Some(expected) = expected_sha256 {
        let actual = sha256_file(busybox)?;
        if actual != expected.to_ascii_lowercase() {
            return Err(format!(
                "busybox sha256 mismatch: expected {expected}, got {actual}"
            ));
        }
    }
    let (interpreter, libs) = ldd_deps(busybox)?;
    if interpreter.is_some() || !libs.is_empty() {
        return Err(format!(
            "busybox {} must be statically linked (ldd reports dynamic deps); refusing to stage it",
            busybox.display()
        ));
    }
    let bin_dir = root.join("bin");
    std::fs::create_dir_all(&bin_dir)
        .map_err(|err| format!("cannot create {}: {err}", bin_dir.display()))?;
    let staged = bin_dir.join("busybox");
    std::fs::copy(busybox, &staged)
        .map_err(|err| format!("cannot stage busybox into {}: {err}", staged.display()))?;
    std::fs::set_permissions(&staged, PermissionsExt::from_mode(0o555))
        .map_err(|err| format!("cannot chmod staged busybox: {err}"))?;
    let output = std::process::Command::new(&staged)
        .arg("--list")
        .output()
        .map_err(|err| format!("cannot list busybox applets: {err}"))?;
    let list = String::from_utf8_lossy(&output.stdout);
    let applets: Vec<String> = list
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    install_applets(&bin_dir, &applets)?;
    Ok(())
}

/// Creates one symlink per applet name in `bin_dir`, pointing at the in-cage
/// busybox path (resolved inside the chroot).
#[cfg(target_os = "linux")]
fn install_applets(bin_dir: &Path, applets: &[String]) -> Result<(), String> {
    for applet in applets {
        if applet.contains('/') {
            return Err(format!("invalid applet name: {applet}"));
        }
        let link = bin_dir.join(applet);
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(CAGE_BUSYBOX, &link)
            .map_err(|err| format!("cannot symlink {}: {err}", link.display()))?;
    }
    Ok(())
}

/// Copies the operator-provided tools dir (git, go, ...) into the cage at
/// `CAGE_TOOLS_DIR`, then stages the dynamic deps of every ELF file found in
/// the copy (loader at its absolute in-cage path, libs in the staged libs
/// dir). Symlinks are followed by `fs::copy`; a symlink loop fails closed.
#[cfg(target_os = "linux")]
fn stage_tools_dir(tools_dir: &Path, root: &Path) -> Result<(), String> {
    const MAX_TOOL_FILES: usize = 20_000;
    let meta = std::fs::metadata(tools_dir)
        .map_err(|err| format!("cannot stat tools dir {}: {err}", tools_dir.display()))?;
    if !meta.is_dir() {
        return Err(format!(
            "tools dir {} is not a directory",
            tools_dir.display()
        ));
    }
    let dst = root.join(CAGE_TOOLS_DIR.strip_prefix('/').unwrap());
    let copied = copy_dir_recursive(tools_dir, &dst, MAX_TOOL_FILES)?;
    let mut scanned = 0usize;
    for path in walk_files(&dst) {
        if is_elf(&path) {
            scanned += 1;
            let (interpreter, libs) = ldd_deps(&path)?;
            stage_deps(&interpreter, &libs, root)?;
        }
    }
    eprintln!(
        "staged cage tools: {copied} files copied to {CAGE_TOOLS_DIR}, {scanned} ELF binaries scanned"
    );
    Ok(())
}

/// Recursive copy preserving permissions; returns the number of files copied.
#[cfg(target_os = "linux")]
fn copy_dir_recursive(src: &Path, dst: &Path, max_files: usize) -> Result<usize, String> {
    let mut count = 0usize;
    std::fs::create_dir_all(dst)
        .map_err(|err| format!("cannot create {}: {err}", dst.display()))?;
    for entry in
        std::fs::read_dir(src).map_err(|err| format!("cannot read {}: {err}", src.display()))?
    {
        let entry =
            entry.map_err(|err| format!("cannot read entry in {}: {err}", src.display()))?;
        let path = entry.path();
        let target = dst.join(entry.file_name());
        let meta = entry
            .metadata()
            .map_err(|err| format!("cannot stat {}: {err}", path.display()))?;
        if meta.is_dir() {
            count += copy_dir_recursive(&path, &target, max_files - count)?;
        } else {
            count += 1;
            if count > max_files {
                return Err(format!("tools dir exceeds {max_files} files"));
            }
            std::fs::copy(&path, &target)
                .map_err(|err| format!("cannot copy {}: {err}", path.display()))?;
        }
    }
    Ok(count)
}

/// All regular files under `dir`, depth-first.
#[cfg(target_os = "linux")]
fn walk_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                out.push(path);
            }
        }
    }
    out
}

/// True when the file starts with the ELF magic.
#[cfg(target_os = "linux")]
fn is_elf(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).is_ok() && magic == [0x7f, b'E', b'L', b'F']
}

#[cfg(target_os = "linux")]
fn sha256_file(path: &Path) -> Result<String, String> {
    use sha2::Digest;
    let bytes =
        std::fs::read(path).map_err(|err| format!("cannot read {}: {err}", path.display()))?;
    let digest = sha2::Sha256::digest(&bytes);
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
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
fn reexec_sandboxed(
    _root: &Path,
    _forward: &[OsString],
    _image: &SandboxImage,
) -> Result<(), String> {
    Err("--mode server requires Linux (unprivileged user namespaces + chroot); use --mode user on this platform".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_mode_never_reexecs() {
        assert!(gate(
            Mode::User,
            false,
            Path::new("/tmp"),
            &[],
            &SandboxImage::default()
        )
        .is_ok());
    }

    #[test]
    fn inside_sandbox_flag_short_circuits_even_in_server_mode() {
        assert!(gate(
            Mode::Server,
            true,
            Path::new("/tmp"),
            &[],
            &SandboxImage::default()
        )
        .is_ok());
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
        let err = gate(
            Mode::Server,
            false,
            Path::new("/tmp"),
            &[],
            &SandboxImage::default(),
        )
        .unwrap_err();
        assert!(err.contains("requires Linux"), "got: {err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stage_busybox_rejects_non_elf_file() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("busybox");
        std::fs::write(&fake, b"#!/bin/sh\necho hi\n").unwrap();
        let err = stage_busybox(&fake, None, dir.path()).unwrap_err();
        assert!(err.contains("not an ELF"), "got: {err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stage_busybox_rejects_dynamic_binary() {
        // The test binary itself is dynamically linked on Linux.
        let exe = std::env::current_exe().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let err = stage_busybox(&exe, None, dir.path()).unwrap_err();
        assert!(err.contains("statically linked"), "got: {err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stage_busybox_rejects_sha256_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("busybox");
        std::fs::write(&fake, b"\x7fELF-fake").unwrap();
        let err = stage_busybox(&fake, Some(&"00".repeat(32)), dir.path()).unwrap_err();
        assert!(err.contains("sha256 mismatch"), "got: {err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn install_applets_creates_symlinks_to_cage_busybox() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        install_applets(&bin, &["sh".to_string(), "ls".to_string()]).unwrap();
        for applet in ["sh", "ls"] {
            let link = bin.join(applet);
            assert_eq!(
                std::fs::read_link(&link).unwrap().to_str().unwrap(),
                CAGE_BUSYBOX
            );
        }
        assert!(install_applets(&bin, &["../evil".to_string()]).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stage_tools_dir_copies_tree_and_stages_elf_deps() {
        let tools = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tools.path().join("bin")).unwrap();
        std::fs::write(tools.path().join("bin/README"), b"tools").unwrap();
        // A real dynamic ELF binary: its loader + libs must be staged.
        std::fs::copy("/bin/true", tools.path().join("bin/true")).unwrap();
        let root = tempfile::tempdir().unwrap();
        stage_tools_dir(tools.path(), root.path()).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.path().join("opt/la-console-tools/bin/README")).unwrap(),
            "tools"
        );
        assert!(root.path().join("opt/la-console-tools/bin/true").is_file());
        let libs_dir = root.path().join(STAGED_LIBS_DIR);
        assert!(libs_dir.is_dir());
        assert!(
            std::fs::read_dir(&libs_dir).unwrap().count() > 0,
            "expected staged shared libraries"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stage_tools_dir_rejects_non_directory() {
        let file = tempfile::tempdir().unwrap();
        let f = file.path().join("not-a-dir");
        std::fs::write(&f, b"x").unwrap();
        let root = tempfile::tempdir().unwrap();
        assert!(stage_tools_dir(&f, root.path()).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cage_shell_is_none_without_staged_busybox() {
        // Outside a cage there is no /bin/busybox in the host fs view of the
        // test process... unless the host has one; only assert the negative
        // when the file is absent.
        if !Path::new(CAGE_BUSYBOX).exists() {
            assert!(cage_shell().is_none());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn protect_cage_tools_is_a_noop_without_busybox() {
        if !Path::new(CAGE_BUSYBOX).exists() {
            assert!(protect_cage_tools().is_ok());
        }
    }

    /// A fake busybox whose `mount` applet always fails (exit 1) or always
    /// succeeds (exit 0), to exercise the fail-closed path of the remount.
    #[cfg(target_os = "linux")]
    fn fake_mount_busybox(dir: &tempfile::TempDir, exit_code: i32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let fake = dir.path().join("busybox");
        std::fs::write(&fake, format!("#!/bin/sh\nexit {exit_code}\n")).unwrap();
        std::fs::set_permissions(&fake, PermissionsExt::from_mode(0o755)).unwrap();
        fake
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn remount_read_only_succeeds_when_mount_applet_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let busybox = fake_mount_busybox(&dir, 0);
        assert!(remount_read_only(&busybox, "/bin").is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn remount_read_only_is_fatal_when_mount_applet_fails() {
        let dir = tempfile::tempdir().unwrap();
        let busybox = fake_mount_busybox(&dir, 1);
        let err = remount_read_only(&busybox, "/bin").unwrap_err();
        assert!(err.contains("/bin"), "got: {err}");
        assert!(err.contains("read-only"), "got: {err}");
    }
}
