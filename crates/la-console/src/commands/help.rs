use std::sync::Arc;

use super::{CommandSpec, Ctx, ExecError, RawOutput, COMMANDS};
use crate::parse::SimpleCommand;
use crate::sink::DiskQuota;

pub(crate) fn run(
    cmd: &SimpleCommand,
    _input: &[u8],
    ctx: &Ctx,
    _quota: &Arc<DiskQuota>,
) -> Result<RawOutput, ExecError> {
    match cmd.argv.get(1) {
        None => Ok(RawOutput {
            code: 0,
            stdout: render_all(ctx).into_bytes(),
            stderr: Vec::new(),
        }),
        Some(arg) => {
            if arg.glob {
                return Err(ExecError::Fail("help: glob is not allowed".to_string()));
            }
            match COMMANDS.iter().find(|spec| spec.name == arg.text) {
                Some(spec) => Ok(RawOutput {
                    code: 0,
                    stdout: render_one(spec).into_bytes(),
                    stderr: Vec::new(),
                }),
                None => Err(ExecError::Fail(format!(
                    "help: unknown command '{}'",
                    arg.text
                ))),
            }
        }
    }
}

pub(crate) fn render_all(ctx: &Ctx) -> String {
    let mut out = String::from("available commands:\n");
    for spec in COMMANDS {
        out.push_str(&format!("  {} - {}\n", spec.name, spec.summary));
        for syntax in spec.syntaxes {
            out.push_str(&format!("    {syntax}\n"));
        }
    }
    out.push_str("trusted commands: ");
    match &ctx.trusted {
        Some(registry) => {
            let entries = registry.entries_sorted();
            if entries.is_empty() {
                out.push_str("none declared\n");
            } else {
                out.push_str("declared in the trusted file\n");
                for entry in entries {
                    out.push_str(&format!(
                        "  {} = {}{}\n",
                        entry.name,
                        entry.command,
                        entry_options(entry)
                    ));
                    if let Some(desc) = &entry.description {
                        out.push_str(&format!("    description: {desc}\n"));
                    }
                    for (flag, spec) in &entry.flags {
                        match &spec.description {
                            Some(d) => out.push_str(&format!("    flag {flag}: {d}\n")),
                            None => out.push_str(&format!("    flag {flag}\n")),
                        }
                    }
                }
            }
        }
        None => out.push_str("not configured (--trusted-file)\n"),
    }
    out
}

fn entry_options(entry: &crate::trusted::TrustedEntry) -> String {
    let mut parts: Vec<String> = Vec::new();
    if entry.no_path_check {
        parts.push("no_path_check".to_string());
    }
    if let Some(t) = entry.timeout_secs {
        parts.push(format!("timeout_secs={t}"));
    }
    if let Some(b) = entry.max_write_bytes {
        parts.push(format!("max_write_bytes={b}"));
    }
    if let Some(b) = entry.mem_bytes {
        parts.push(format!("mem_bytes={b}"));
    }
    if let Some(c) = entry.cpus {
        parts.push(format!("cpus={c}"));
    }
    if let Some(n) = entry.network {
        parts.push(format!("network={n}"));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" [{}]", parts.join(", "))
    }
}

fn render_one(spec: &CommandSpec) -> String {
    let mut out = format!("{} - {}\n", spec.name, spec.summary);
    for syntax in spec.syntaxes {
        out.push_str(&format!("  {syntax}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::Limits;
    use crate::parse::parse_input;
    use crate::resolve::Resolver;
    use std::collections::HashMap;

    fn ctx_with(dir: &tempfile::TempDir, trusted: Option<crate::trusted::TrustedRegistry>) -> Ctx {
        Ctx {
            resolver: Resolver::new(dir.path()).unwrap(),
            sensibles: vec![],
            secrets: vec![],
            limits: Limits::default(),
            trusted,
            sandboxed: false,
            sandbox_shell: None,
        }
    }

    fn run_cmd(dir: &tempfile::TempDir, cmd: &str) -> Result<RawOutput, ExecError> {
        let ctx = ctx_with(dir, None);
        let node = parse_input(cmd, &HashMap::new()).unwrap();
        let crate::parse::Node::Simple(simple) = node else {
            panic!("expected simple command");
        };
        run(&simple, &[], &ctx, &Arc::new(DiskQuota::new(1024)))
    }

    #[test]
    fn registry_entries_are_unique_and_documented() {
        let mut names: Vec<_> = COMMANDS.iter().map(|s| s.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), COMMANDS.len(), "duplicate command names");
        for spec in COMMANDS {
            assert!(!spec.name.is_empty());
            assert!(!spec.syntaxes.is_empty(), "{} has no syntax", spec.name);
            assert!(!spec.summary.is_empty(), "{} has no summary", spec.name);
            for syntax in spec.syntaxes {
                assert!(
                    syntax.starts_with(spec.name),
                    "syntax {syntax} of {}",
                    spec.name
                );
            }
        }
    }

    #[test]
    fn help_lists_every_registered_command_with_all_syntaxes() {
        let dir = tempfile::tempdir().unwrap();
        let out = run_cmd(&dir, "help").unwrap();
        assert_eq!(out.code, 0);
        let text = String::from_utf8(out.stdout).unwrap();
        for spec in COMMANDS {
            assert!(text.contains(spec.name), "missing {}", spec.name);
            assert!(text.contains(spec.summary));
            for syntax in spec.syntaxes {
                assert!(text.contains(syntax), "missing syntax {syntax}");
            }
        }
        assert!(text.contains("not configured"));
    }

    #[test]
    fn help_one_command_shows_only_its_syntaxes() {
        let dir = tempfile::tempdir().unwrap();
        let out = run_cmd(&dir, "help echo").unwrap();
        assert_eq!(out.code, 0);
        let text = String::from_utf8(out.stdout).unwrap();
        assert!(text.contains("echo <text>"));
        assert!(text.contains("echo <text> > <path>"));
        assert!(!text.contains("cat <path...>"));
    }

    #[test]
    fn help_unknown_command_is_a_fail() {
        let dir = tempfile::tempdir().unwrap();
        let err = run_cmd(&dir, "help nope").unwrap_err();
        assert!(matches!(err, ExecError::Fail(m) if m.contains("unknown command")));
    }

    #[test]
    fn help_lists_trusted_entries_when_configured() {
        let dir = tempfile::tempdir().unwrap();
        let trusted_dir = tempfile::tempdir().unwrap();
        let trusted_file = trusted_dir.path().join("trusted.toml");
        std::fs::write(
            &trusted_file,
            "[commands.build]\ncommand = \"cargo build --locked\"\n\n\
             [commands.run-tests]\ncommand = \"cargo test\"\nno_path_check = true\n",
        )
        .unwrap();
        let sha = crate::trusted::sha256_hex(std::fs::read(&trusted_file).unwrap().as_slice());
        let registry =
            crate::trusted::TrustedRegistry::load(&trusted_file, Some(sha), dir.path(), false)
                .unwrap();
        let ctx = ctx_with(&dir, Some(registry));
        let text = render_all(&ctx);
        assert!(text.contains("build = cargo build --locked"));
        assert!(text.contains("run-tests = cargo test [no_path_check]"));
    }

    #[test]
    fn help_lists_toml_entry_limits_description_and_flags() {
        let dir = tempfile::tempdir().unwrap();
        let trusted_dir = tempfile::tempdir().unwrap();
        let trusted_file = trusted_dir.path().join("trusted.toml");
        std::fs::write(
            &trusted_file,
            "[commands.build]\ncommand = \"cargo build\"\ndescription = \"Compile le projet\"\ntimeout_secs = 600\nnetwork = \"none\"\n\n\
             [commands.build.flags]\n\"--release\" = { description = \"Build optimise\" }\n\"-j\" = {}\n",
        )
        .unwrap();
        let sha = crate::trusted::sha256_hex(std::fs::read(&trusted_file).unwrap().as_slice());
        let registry =
            crate::trusted::TrustedRegistry::load(&trusted_file, Some(sha), dir.path(), false)
                .unwrap();
        let ctx = ctx_with(&dir, Some(registry));
        let text = render_all(&ctx);
        assert!(text.contains("build = cargo build [timeout_secs=600, network=none]"));
        assert!(text.contains("description: Compile le projet"));
        assert!(text.contains("flag --release: Build optimise"));
        assert!(text.contains("flag -j\n"));
    }
}
