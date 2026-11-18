use std::fs;

use super::{
    check_read_bound, collect_paths, read_bounded, resolve_read_target, Ctx, ExecError, RawOutput,
};
use crate::parse::{Arg, SimpleCommand};
use grep::matcher::Matcher;

pub const DEFAULT_MAX_GREP_MATCHES: usize = 10_000;
/// Hard bound on -B/-A/-C context lines (memory bound for the searcher buffers).
pub const MAX_CONTEXT_LINES: usize = 100;
/// Hard bound on the --group-separator length, in bytes.
pub const MAX_GROUP_SEPARATOR_BYTES: usize = 64;
/// Default bound on the total number of --include/--exclude/--exclude-dir globs.
pub const DEFAULT_MAX_GREP_GLOBS: usize = 64;
/// Hard bound on a single glob filter (--include/--exclude/--exclude-dir), in bytes.
pub const MAX_GREP_GLOB_BYTES: usize = 256;
/// Default bound on the total number of patterns (-e flags plus -f/--file lines).
pub const DEFAULT_MAX_GREP_PATTERNS: usize = 10_000;
/// Hard bound on a single pattern line read from a -f/--file, in bytes.
pub const MAX_GREP_PATTERN_BYTES: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum OutMode {
    Lines,
    Count,
    FilesWith,
    FilesWithout,
    Quiet,
}

#[derive(Clone, Debug)]
struct Opts {
    all: bool,
    case_insensitive: bool,
    invert: bool,
    word: bool,
    whole_line: bool,
    fixed: bool,
    count: bool,
    only_matching: bool,
    files_with: bool,
    files_without: bool,
    quiet: bool,
    max_count: Option<u64>,
    before: usize,
    after: usize,
    group_separator: String,
    patterns: Vec<String>,
    pattern_files: Vec<String>,
    exclude_from: Vec<String>,
    includes: Vec<String>,
    excludes: Vec<String>,
    exclude_dirs: Vec<String>,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            all: false,
            case_insensitive: false,
            invert: false,
            word: false,
            whole_line: false,
            fixed: false,
            count: false,
            only_matching: false,
            files_with: false,
            files_without: false,
            quiet: false,
            max_count: None,
            before: 0,
            after: 0,
            group_separator: "--".to_string(),
            patterns: Vec::new(),
            pattern_files: Vec::new(),
            exclude_from: Vec::new(),
            includes: Vec::new(),
            excludes: Vec::new(),
            exclude_dirs: Vec::new(),
        }
    }
}

/// Output-mode priority, same as GNU grep: -q > -l > -L > -c > -o > plain lines.
fn resolve_mode(o: &Opts) -> OutMode {
    if o.quiet {
        OutMode::Quiet
    } else if o.files_with {
        OutMode::FilesWith
    } else if o.files_without {
        OutMode::FilesWithout
    } else if o.count {
        OutMode::Count
    } else {
        OutMode::Lines
    }
}

fn no_value(flag: &str, inline: Option<String>) -> Result<(), ExecError> {
    if inline.is_some() {
        return Err(ExecError::Fail(format!(
            "grep: option {flag} doesn't take a value"
        )));
    }
    Ok(())
}

fn opt_value(
    flag: &str,
    inline: Option<String>,
    args: &[Arg],
    i: &mut usize,
) -> Result<String, ExecError> {
    if let Some(v) = inline {
        return Ok(v);
    }
    *i += 1;
    if *i >= args.len() {
        return Err(ExecError::Fail(format!(
            "grep: option {flag} requires an argument"
        )));
    }
    Ok(args[*i].text.clone())
}

fn parse_num(flag: &str, v: &str) -> Result<u64, ExecError> {
    v.parse::<u64>()
        .map_err(|_| ExecError::Fail(format!("grep: invalid number '{v}' for {flag}")))
}

fn parse_ctx(flag: &str, v: &str) -> Result<usize, ExecError> {
    let n = v
        .parse::<usize>()
        .map_err(|_| ExecError::Fail(format!("grep: invalid number '{v}' for {flag}")))?;
    if n > MAX_CONTEXT_LINES {
        return Err(ExecError::Fail(format!(
            "grep: {flag} too large (max {MAX_CONTEXT_LINES})"
        )));
    }
    Ok(n)
}

fn check_glob(flag: &str, v: &str) -> Result<String, ExecError> {
    if v.is_empty() || v.contains('\0') {
        return Err(ExecError::Fail(format!("grep: empty glob for {flag}")));
    }
    if v.len() > MAX_GREP_GLOB_BYTES {
        return Err(ExecError::Fail(format!(
            "grep: {flag} glob too long (max {MAX_GREP_GLOB_BYTES} bytes)"
        )));
    }
    Ok(v.to_string())
}

/// Reads patterns from a `-f`/`--file` file through the secured read pipeline:
/// `read_bounded` = resolve() (no escape) + sensitive-file denial + regular
/// file only + max_read_bytes. Strict UTF-8, empty lines ignored, per-line and
/// total bounds enforced. The patterns themselves are compiled later with the
/// same linear-time regex engine as `-e` patterns.
fn read_pattern_file(ctx: &Ctx, rel: &str) -> Result<Vec<String>, ExecError> {
    let bytes = read_bounded(ctx, rel)?;
    let text = String::from_utf8(bytes)
        .map_err(|_| ExecError::Fail(format!("grep: {rel}: pattern file is not valid UTF-8")))?;
    let mut pats = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_GREP_PATTERN_BYTES {
            return Err(ExecError::Fail(format!(
                "grep: {rel}: pattern line too long (max {MAX_GREP_PATTERN_BYTES} bytes)"
            )));
        }
        pats.push(line.to_string());
    }
    if pats.len() > ctx.limits.max_grep_patterns {
        return Err(ExecError::Limit(format!(
            "grep: {rel}: too many patterns (max {})",
            ctx.limits.max_grep_patterns
        )));
    }
    Ok(pats)
}

/// Reads exclude globs from an `--exclude-from` file, same secured read
/// pipeline and bounds as `read_pattern_file`. Each non-empty line becomes an
/// `--exclude` glob; the total glob count (command line + file) is bounded in
/// `build_walk_filters`.
fn read_glob_file(ctx: &Ctx, rel: &str) -> Result<Vec<String>, ExecError> {
    let bytes = read_bounded(ctx, rel)?;
    let text = String::from_utf8(bytes)
        .map_err(|_| ExecError::Fail(format!("grep: {rel}: exclude file is not valid UTF-8")))?;
    let mut globs = Vec::new();
    let mut probe = ignore::overrides::OverrideBuilder::new(ctx.resolver.root());
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let g = check_glob("--exclude-from", line)?;
        probe.add(&format!("!{g}")).map_err(|err| {
            ExecError::Fail(format!(
                "grep: {rel}: invalid --exclude-from glob '{line}': {err}"
            ))
        })?;
        globs.push(g);
    }
    Ok(globs)
}

fn short_refused(c: char, raw: &str) -> ExecError {
    let why = match c {
        'P' => "PCRE is a ReDoS risk; the dialect is ERE (-E)",
        'G' => "the dialect is ERE (-E)",
        'z' => "NUL-separated lines are not supported",
        'b' => "byte offsets are not supported; line numbers are always shown (-n)",
        'h' => "the file name is always shown",
        'R' => "following symlinks is refused (escape vector)",
        'd' | 'D' => {
            "reading directories/devices directly is refused; directories are always searched recursively"
        }
        'I' => "already the default: binary files are skipped",
        _ => "not supported",
    };
    ExecError::Fail(format!(
        "grep: option '-{c}' in '{raw}' not supported: {why}"
    ))
}

fn long_refused(name: &str) -> ExecError {
    let why = match name {
        "perl-regexp" => "PCRE is a ReDoS risk; the dialect is ERE (-E)",
        "basic-regexp" => "the dialect is ERE (-E)",
        "null-data" => "NUL-separated lines are not supported",
        "dereference-recursive" => "following symlinks is refused (escape vector)",
        "directories" | "devices" | "binary-files" => {
            "not supported; directories are always searched recursively and binary files always skipped"
        }
        "text" => {
            "reading binaries as text is not supported; '-a'/'--all' here means search hidden + gitignored files (ripgrep semantics)"
        }
        _ => "not supported",
    };
    ExecError::Fail(format!("grep: option --{name} not supported: {why}"))
}

fn parse_opts(args: &[Arg]) -> Result<(Opts, Vec<&Arg>), ExecError> {
    let mut o = Opts::default();
    let mut positional: Vec<&Arg> = Vec::new();
    let mut i = 0usize;
    let mut opts_done = false;
    while i < args.len() {
        let arg = &args[i];
        let text = arg.text.as_str();
        if !opts_done && text == "--" {
            opts_done = true;
        } else if !opts_done && text.starts_with("--") && text.len() > 2 {
            let body = &text[2..];
            let (name, inline) = match body.find('=') {
                Some(p) => (&body[..p], Some(body[p + 1..].to_string())),
                None => (body, None),
            };
            match name {
                "all" => {
                    no_value("--all", inline)?;
                    o.all = true;
                }
                "ignore-case" => {
                    no_value("--ignore-case", inline)?;
                    o.case_insensitive = true;
                }
                "no-ignore-case" => {
                    no_value("--no-ignore-case", inline)?;
                }
                "invert-match" => {
                    no_value("--invert-match", inline)?;
                    o.invert = true;
                }
                "word-regexp" => {
                    no_value("--word-regexp", inline)?;
                    o.word = true;
                }
                "line-regexp" => {
                    no_value("--line-regexp", inline)?;
                    o.whole_line = true;
                }
                "line-number" => {
                    no_value("--line-number", inline)?;
                }
                "count" => {
                    no_value("--count", inline)?;
                    o.count = true;
                }
                "only-matching" => {
                    no_value("--only-matching", inline)?;
                    o.only_matching = true;
                }
                "files-with-matches" => {
                    no_value("--files-with-matches", inline)?;
                    o.files_with = true;
                }
                "files-without-match" => {
                    no_value("--files-without-match", inline)?;
                    o.files_without = true;
                }
                "quiet" | "silent" => {
                    no_value("--quiet", inline)?;
                    o.quiet = true;
                }
                "extended-regexp" => {
                    no_value("--extended-regexp", inline)?;
                }
                "fixed-strings" => {
                    no_value("--fixed-strings", inline)?;
                    o.fixed = true;
                }
                "recursive" => {
                    no_value("--recursive", inline)?;
                }
                "regexp" => {
                    let v = opt_value("--regexp", inline, args, &mut i)?;
                    o.patterns.push(v);
                }
                "max-count" => {
                    let v = opt_value("--max-count", inline, args, &mut i)?;
                    o.max_count = Some(parse_num("--max-count", &v)?);
                }
                "before-context" => {
                    let v = opt_value("--before-context", inline, args, &mut i)?;
                    o.before = parse_ctx("--before-context", &v)?;
                }
                "after-context" => {
                    let v = opt_value("--after-context", inline, args, &mut i)?;
                    o.after = parse_ctx("--after-context", &v)?;
                }
                "context" => {
                    let v = opt_value("--context", inline, args, &mut i)?;
                    let n = parse_ctx("--context", &v)?;
                    o.before = n;
                    o.after = n;
                }
                "group-separator" => {
                    let v = opt_value("--group-separator", inline, args, &mut i)?;
                    if v.len() > MAX_GROUP_SEPARATOR_BYTES {
                        return Err(ExecError::Fail(format!(
                            "grep: --group-separator too long (max {MAX_GROUP_SEPARATOR_BYTES} bytes)"
                        )));
                    }
                    o.group_separator = v;
                }
                "file" => {
                    let v = opt_value("--file", inline, args, &mut i)?;
                    o.pattern_files.push(v);
                }
                "exclude-from" => {
                    let v = opt_value("--exclude-from", inline, args, &mut i)?;
                    o.exclude_from.push(v);
                }
                "include" | "exclude" | "exclude-dir" => {
                    let v = opt_value(&format!("--{name}"), inline, args, &mut i)?;
                    let v = check_glob(&format!("--{name}"), &v)?;
                    match name {
                        "include" => o.includes.push(v),
                        "exclude" => o.excludes.push(v),
                        _ => o.exclude_dirs.push(v),
                    }
                }
                other => return Err(long_refused(other)),
            }
        } else if !opts_done && text.starts_with('-') && text.len() > 1 {
            let chars: Vec<char> = text[1..].chars().collect();
            let mut j = 0usize;
            while j < chars.len() {
                let c = chars[j];
                match c {
                    'a' => o.all = true,
                    'i' => o.case_insensitive = true,
                    'v' => o.invert = true,
                    'w' => o.word = true,
                    'x' => o.whole_line = true,
                    'n' => {}
                    'c' => o.count = true,
                    'o' => o.only_matching = true,
                    'l' => o.files_with = true,
                    'L' => o.files_without = true,
                    'q' => o.quiet = true,
                    'E' => {}
                    'F' => o.fixed = true,
                    'r' => {}
                    'e' | 'f' | 'm' | 'B' | 'A' | 'C' => {
                        let rest: String = chars[j + 1..].iter().collect();
                        let v = if !rest.is_empty() {
                            rest
                        } else {
                            i += 1;
                            if i >= args.len() {
                                return Err(ExecError::Fail(format!(
                                    "grep: option '-{c}' requires an argument"
                                )));
                            }
                            args[i].text.clone()
                        };
                        match c {
                            'e' => o.patterns.push(v),
                            'f' => o.pattern_files.push(v),
                            'm' => o.max_count = Some(parse_num("-m", &v)?),
                            'B' => o.before = parse_ctx("-B", &v)?,
                            'A' => o.after = parse_ctx("-A", &v)?,
                            'C' => {
                                let n = parse_ctx("-C", &v)?;
                                o.before = n;
                                o.after = n;
                            }
                            _ => unreachable!(),
                        }
                        break;
                    }
                    other => return Err(short_refused(other, text)),
                }
                j += 1;
            }
        } else if !opts_done && text == "-" {
            return Err(ExecError::Fail(
                "grep: '-' (stdin) is implicit: omit the path to read stdin".to_string(),
            ));
        } else {
            positional.push(arg);
        }
        i += 1;
    }
    Ok((o, positional))
}

#[allow(clippy::needless_lifetimes)]
fn split_patterns<'a>(
    opts: &Opts,
    positional: Vec<&'a Arg>,
) -> Result<(Vec<String>, Vec<&'a Arg>), ExecError> {
    if opts.patterns.is_empty() && opts.pattern_files.is_empty() {
        let mut it = positional.into_iter();
        match it.next() {
            Some(first) => Ok((vec![first.text.clone()], it.collect())),
            None => Err(ExecError::Fail("grep: missing pattern".to_string())),
        }
    } else if opts.patterns.is_empty() {
        Err(ExecError::Fail(
            "grep: no patterns found in -f/--file file(s)".to_string(),
        ))
    } else {
        Ok((opts.patterns.clone(), positional))
    }
}

/// Glob filters for recursive searches, built once per command from
/// --include/--exclude/--exclude-dir. Applied via `filter_entry`, i.e. after
/// the walker's own hidden/.gitignore filters, so a glob can never make a
/// hidden or gitignored file visible without --all.
struct WalkFilters {
    files: Option<ignore::overrides::Override>,
    dirs: Option<ignore::overrides::Override>,
}

fn build_walk_filters(ctx: &Ctx, opts: &Opts) -> Result<WalkFilters, ExecError> {
    let total = opts.includes.len() + opts.excludes.len() + opts.exclude_dirs.len();
    if total > ctx.limits.max_grep_globs {
        return Err(ExecError::Limit(format!(
            "grep: too many glob filters (max {})",
            ctx.limits.max_grep_globs
        )));
    }
    let files = if opts.includes.is_empty() && opts.excludes.is_empty() {
        None
    } else {
        let mut b = ignore::overrides::OverrideBuilder::new(ctx.resolver.root());
        for g in &opts.includes {
            b.add(g).map_err(|err| {
                ExecError::Fail(format!("grep: invalid --include glob '{g}': {err}"))
            })?;
        }
        for g in &opts.excludes {
            b.add(&format!("!{g}")).map_err(|err| {
                ExecError::Fail(format!("grep: invalid --exclude glob '{g}': {err}"))
            })?;
        }
        Some(
            b.build()
                .map_err(|err| ExecError::Fail(format!("grep: invalid glob filter: {err}")))?,
        )
    };
    let dirs =
        if opts.exclude_dirs.is_empty() {
            None
        } else {
            let mut b = ignore::overrides::OverrideBuilder::new(ctx.resolver.root());
            for g in &opts.exclude_dirs {
                b.add(&format!("!{g}")).map_err(|err| {
                    ExecError::Fail(format!("grep: invalid --exclude-dir glob '{g}': {err}"))
                })?;
            }
            Some(b.build().map_err(|err| {
                ExecError::Fail(format!("grep: invalid --exclude-dir glob: {err}"))
            })?)
        };
    Ok(WalkFilters { files, dirs })
}

pub(crate) fn run(
    cmd: &SimpleCommand,
    input: &[u8],
    ctx: &Ctx,
    _quota: &std::sync::Arc<crate::sink::DiskQuota>,
) -> Result<RawOutput, ExecError> {
    let (mut opts, positional) = parse_opts(&cmd.argv[1..])?;
    let pattern_files = opts.pattern_files.clone();
    for pf in &pattern_files {
        let pats = read_pattern_file(ctx, pf)?;
        opts.patterns.extend(pats);
    }
    let exclude_from = opts.exclude_from.clone();
    for ef in &exclude_from {
        let globs = read_glob_file(ctx, ef)?;
        opts.excludes.extend(globs);
    }
    let (patterns, path_args) = split_patterns(&opts, positional)?;
    let mode = resolve_mode(&opts);

    let mut mb = grep::regex::RegexMatcherBuilder::new();
    mb.case_insensitive(opts.case_insensitive)
        .word(opts.word)
        .whole_line(opts.whole_line)
        .fixed_strings(opts.fixed);
    let matcher = mb
        .build_many(&patterns)
        .map_err(|err| ExecError::Fail(format!("grep: invalid pattern: {err}")))?;

    let mut sb = grep::searcher::SearcherBuilder::new();
    sb.line_number(true)
        .invert_match(opts.invert)
        .before_context(opts.before)
        .after_context(opts.after)
        .binary_detection(grep::searcher::BinaryDetection::quit(b'\0'));
    if let Some(max) = opts.max_count {
        sb.max_matches(Some(max));
    }
    let mut searcher = sb.build();

    let targets = collect_paths(ctx, path_args.iter().copied())?;
    let filters = build_walk_filters(ctx, &opts)?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut found_any = false;
    let mut global = 0usize;
    let limit = ctx.limits.max_grep_matches;
    let sep = opts.group_separator.clone();

    if targets.is_empty() {
        let st = search_slice(
            &mut searcher,
            &matcher,
            mode,
            opts.only_matching,
            &sep,
            "(stdin)",
            input,
            &mut stdout,
            &mut global,
            limit,
        )?;
        if st.overflow {
            return Err(ExecError::Limit(format!(
                "grep: too many matches (max {limit})"
            )));
        }
        found_any |= st.found;
    }
    for rel in &targets {
        match search_target(
            ctx,
            &filters,
            &mut searcher,
            &matcher,
            rel,
            opts.all,
            mode,
            opts.only_matching,
            &sep,
            &mut stdout,
            &mut global,
            limit,
        ) {
            Ok(st) => {
                if st.overflow {
                    return Err(ExecError::Limit(format!(
                        "grep: too many matches (max {limit})"
                    )));
                }
                found_any |= st.found;
            }
            Err(ExecError::Denied(msg)) => return Err(ExecError::Denied(msg)),
            Err(ExecError::Limit(msg)) => return Err(ExecError::Limit(msg)),
            Err(ExecError::Fail(msg)) => {
                stderr.extend_from_slice(format!("grep: {msg}\n").as_bytes());
            }
        }
    }
    let code = if found_any { 0 } else { 1 };
    Ok(RawOutput {
        code,
        stdout,
        stderr,
    })
}

#[derive(Default)]
struct FileStats {
    found: bool,
    count: u64,
    overflow: bool,
}

#[allow(clippy::too_many_arguments)]
fn search_target(
    ctx: &Ctx,
    filters: &WalkFilters,
    searcher: &mut grep::searcher::Searcher,
    matcher: &grep::regex::RegexMatcher,
    rel: &str,
    all: bool,
    mode: OutMode,
    only_matching: bool,
    sep: &str,
    out: &mut Vec<u8>,
    global: &mut usize,
    limit: usize,
) -> Result<FileStats, ExecError> {
    let (target, meta) = resolve_read_target(ctx, rel)?;
    if meta.is_dir() {
        let mut walker = ignore::WalkBuilder::new(&target);
        walker
            .follow_links(false)
            .parents(false)
            .require_git(false)
            .hidden(!all)
            .ignore(!all)
            .git_ignore(!all)
            .git_global(!all)
            .git_exclude(!all);
        let files_filter = filters.files.clone();
        let dirs_filter = filters.dirs.clone();
        walker.filter_entry(move |entry| {
            if entry.depth() == 0 {
                return true;
            }
            if entry.file_type().is_some_and(|ft| ft.is_dir()) {
                if let Some(dirs) = &dirs_filter {
                    return !dirs.matched(entry.path(), true).is_ignore();
                }
                return true;
            }
            if let Some(files) = &files_filter {
                return !files.matched(entry.path(), false).is_ignore();
            }
            true
        });
        let mut files: Vec<(String, std::path::PathBuf)> = Vec::new();
        for entry in walker.build() {
            let entry = entry.map_err(|err| ExecError::Fail(format!("{rel}: {err}")))?;
            if entry.depth() == 0 || !entry.file_type().is_some_and(|ft| ft.is_file()) {
                continue;
            }
            if files.len() > ctx.limits.max_grep_files {
                return Err(ExecError::Limit(format!(
                    "grep: too many files (max {})",
                    ctx.limits.max_grep_files
                )));
            }
            let Some(entry_rel) = entry
                .path()
                .strip_prefix(ctx.resolver.root())
                .ok()
                .and_then(|p| p.to_str())
                .map(str::to_string)
            else {
                continue;
            };
            if ctx.resolver.resolve(&entry_rel).is_err() {
                continue;
            }
            files.push((entry_rel, entry.path().to_path_buf()));
        }
        files.sort();
        let mut agg = FileStats::default();
        for (entry_rel, entry_path) in files {
            let fmeta = fs::metadata(&entry_path)
                .map_err(|err| ExecError::Fail(format!("{entry_rel}: {err}")))?;
            check_read_bound(ctx, &entry_rel, &fmeta)?;
            let st = search_file(
                searcher,
                matcher,
                mode,
                only_matching,
                sep,
                &entry_rel,
                &entry_path,
                out,
                global,
                limit,
            )?;
            agg.found |= st.found;
            agg.count += st.count;
            if st.overflow {
                agg.overflow = true;
                return Ok(agg);
            }
        }
        Ok(agg)
    } else if meta.is_file() {
        check_read_bound(ctx, rel, &meta)?;
        search_file(
            searcher,
            matcher,
            mode,
            only_matching,
            sep,
            rel,
            &target,
            out,
            global,
            limit,
        )
    } else {
        Err(ExecError::Fail(format!("{rel}: not a regular file")))
    }
}

#[allow(clippy::too_many_arguments)]
fn search_slice(
    searcher: &mut grep::searcher::Searcher,
    matcher: &grep::regex::RegexMatcher,
    mode: OutMode,
    only_matching: bool,
    sep: &str,
    label: &str,
    data: &[u8],
    out: &mut Vec<u8>,
    global: &mut usize,
    limit: usize,
) -> Result<FileStats, ExecError> {
    let mut sink = CollectSink {
        rel: label.to_string(),
        mode,
        only_matching,
        sep,
        out,
        matcher,
        stats: FileStats::default(),
        global,
        limit,
    };
    searcher
        .search_slice(matcher, data, &mut sink)
        .map_err(|err| ExecError::Fail(format!("{label}: {err}")))?;
    Ok(sink.stats)
}

#[allow(clippy::too_many_arguments)]
fn search_file(
    searcher: &mut grep::searcher::Searcher,
    matcher: &grep::regex::RegexMatcher,
    mode: OutMode,
    only_matching: bool,
    sep: &str,
    rel: &str,
    path: &std::path::Path,
    out: &mut Vec<u8>,
    global: &mut usize,
    limit: usize,
) -> Result<FileStats, ExecError> {
    let mut sink = CollectSink {
        rel: rel.to_string(),
        mode,
        only_matching,
        sep,
        out,
        matcher,
        stats: FileStats::default(),
        global,
        limit,
    };
    searcher
        .search_path(matcher, path, &mut sink)
        .map_err(|err| ExecError::Fail(format!("{rel}: {err}")))?;
    Ok(sink.stats)
}

struct CollectSink<'a> {
    rel: String,
    mode: OutMode,
    only_matching: bool,
    sep: &'a str,
    out: &'a mut Vec<u8>,
    matcher: &'a grep::regex::RegexMatcher,
    stats: FileStats,
    global: &'a mut usize,
    limit: usize,
}

impl grep::searcher::Sink for CollectSink<'_> {
    type Error = std::io::Error;

    fn matched(
        &mut self,
        _searcher: &grep::searcher::Searcher,
        mat: &grep::searcher::SinkMatch<'_>,
    ) -> Result<bool, Self::Error> {
        self.stats.found = true;
        *self.global += 1;
        if *self.global > self.limit {
            self.stats.overflow = true;
            return Ok(false);
        }
        self.stats.count += 1;
        match self.mode {
            OutMode::Quiet => Ok(false),
            OutMode::Count | OutMode::FilesWith | OutMode::FilesWithout => Ok(true),
            OutMode::Lines => {
                let line_no = mat.line_number().unwrap_or(0);
                let line = String::from_utf8_lossy(mat.bytes());
                let trimmed = line.trim_end();
                if self.only_matching {
                    let bytes = trimmed.as_bytes();
                    let mut at = 0usize;
                    while at <= bytes.len() {
                        match self.matcher.find_at(bytes, at) {
                            Ok(Some(m)) => {
                                let piece = String::from_utf8_lossy(&bytes[m.start()..m.end()]);
                                self.out.extend_from_slice(
                                    format!("{}:{}:{}\n", self.rel, line_no, piece).as_bytes(),
                                );
                                at = if m.end() > m.start() {
                                    m.end()
                                } else {
                                    m.end() + 1
                                };
                            }
                            Ok(None) => break,
                            Err(_) => break,
                        }
                    }
                } else {
                    self.out.extend_from_slice(
                        format!("{}:{}:{}\n", self.rel, line_no, trimmed).as_bytes(),
                    );
                }
                Ok(true)
            }
        }
    }

    fn context(
        &mut self,
        _searcher: &grep::searcher::Searcher,
        ctx: &grep::searcher::SinkContext<'_>,
    ) -> Result<bool, Self::Error> {
        if self.mode == OutMode::Lines {
            let line = String::from_utf8_lossy(ctx.bytes());
            let line_no = ctx.line_number().unwrap_or(0);
            self.out.extend_from_slice(
                format!("{}-{}-{}\n", self.rel, line_no, line.trim_end()).as_bytes(),
            );
        }
        Ok(true)
    }

    fn context_break(&mut self, _searcher: &grep::searcher::Searcher) -> Result<bool, Self::Error> {
        if self.mode == OutMode::Lines {
            self.out
                .extend_from_slice(format!("{}\n", self.sep).as_bytes());
        }
        Ok(true)
    }

    fn finish(
        &mut self,
        _searcher: &grep::searcher::Searcher,
        _fin: &grep::searcher::SinkFinish,
    ) -> Result<(), Self::Error> {
        match self.mode {
            OutMode::Count => {
                self.out
                    .extend_from_slice(format!("{}:{}\n", self.rel, self.stats.count).as_bytes());
            }
            OutMode::FilesWith if self.stats.found => {
                self.out
                    .extend_from_slice(format!("{}\n", self.rel).as_bytes());
            }
            OutMode::FilesWithout if !self.stats.found => {
                self.out
                    .extend_from_slice(format!("{}\n", self.rel).as_bytes());
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{execute, Ctx, ExecError, ExecOutcome, Limits};
    use crate::parse::parse_input;
    use crate::resolve::Resolver;
    use proptest::prelude::*;
    use std::collections::HashMap;
    use std::fs;

    fn run_cmd(dir: &tempfile::TempDir, cmd: &str) -> Result<ExecOutcome, ExecError> {
        let resolver = Resolver::new(dir.path()).unwrap();
        let ctx = Ctx {
            resolver,
            sensibles: vec![],
            secrets: vec![],
            limits: Limits::default(),
            trusted: None,
            sandboxed: false,
            sandbox_shell: None,
        };
        let node = parse_input(cmd, &HashMap::new()).unwrap();
        execute(&node, &ctx)
    }

    fn ctx_with(dir: &tempfile::TempDir, sensibles: Vec<regex::Regex>, max_read: usize) -> Ctx {
        Ctx {
            resolver: Resolver::new(dir.path()).unwrap(),
            sensibles,
            secrets: vec![],
            limits: Limits {
                max_read_bytes: max_read,
                ..Limits::default()
            },
            trusted: None,
            sandboxed: false,
            sandbox_shell: None,
        }
    }

    #[test]
    fn grep_finds_matches_in_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "foo one\nbar\nfoo two\n").unwrap();
        let out = run_cmd(&dir, "grep foo a.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "a.txt:1:foo one\na.txt:3:foo two\n");
    }

    #[test]
    fn grep_no_match_is_code_1() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "nothing\n").unwrap();
        let out = run_cmd(&dir, "grep zzz a.txt").unwrap();
        assert_eq!(out.code, 1);
        assert_eq!(out.stdout, "");
    }

    #[test]
    fn grep_searches_directories_recursively() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/a.rs"), "let x = 1;\n").unwrap();
        fs::write(dir.path().join("b.txt"), "let y = 2;\n").unwrap();
        let out = run_cmd(&dir, "grep let .").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "b.txt:1:let y = 2;\nsrc/a.rs:1:let x = 1;\n");
    }

    #[test]
    fn grep_respects_gitignore_unless_all() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("keep.txt"), "hit\n").unwrap();
        fs::write(dir.path().join("ignored.log"), "hit\n").unwrap();
        fs::write(dir.path().join(".gitignore"), "ignored.log\n").unwrap();
        let out = run_cmd(&dir, "grep hit .").unwrap();
        assert_eq!(out.stdout, "keep.txt:1:hit\n");
        let out = run_cmd(&dir, "grep --all hit .").unwrap();
        assert!(out.stdout.contains("ignored.log:1:hit"));
        assert!(out.stdout.contains("keep.txt:1:hit"));
    }

    #[test]
    fn grep_supports_glob_paths() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "hit\n").unwrap();
        fs::write(dir.path().join("b.rs"), "hit\n").unwrap();
        let out = run_cmd(&dir, "grep hit *.txt").unwrap();
        assert_eq!(out.stdout, "a.txt:1:hit\n");
    }

    #[test]
    fn grep_denies_escape_and_sensitive() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            run_cmd(&dir, "grep x ../secret.txt").unwrap_err(),
            ExecError::Denied(_)
        ));
        fs::write(dir.path().join(".env"), "SECRET=1\n").unwrap();
        let ctx = ctx_with(
            &dir,
            vec![regex::Regex::new(r".*\.env$").unwrap()],
            1024 * 1024,
        );
        let node = parse_input("grep SECRET .env", &HashMap::new()).unwrap();
        assert!(matches!(
            execute(&node, &ctx).unwrap_err(),
            ExecError::Denied(_)
        ));
    }

    #[test]
    fn grep_denies_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("big.txt"), vec![b'a'; 2048]).unwrap();
        let ctx = ctx_with(&dir, vec![], 1024);
        let node = parse_input("grep a big.txt", &HashMap::new()).unwrap();
        assert!(matches!(
            execute(&node, &ctx).unwrap_err(),
            ExecError::Limit(_)
        ));
    }

    #[test]
    fn grep_invalid_pattern_is_fail() {
        let dir = tempfile::tempdir().unwrap();
        let err = run_cmd(&dir, "grep '[' a.txt").unwrap_err();
        assert!(matches!(err, ExecError::Fail(m) if m.contains("invalid pattern")));
    }

    #[test]
    fn grep_missing_operands() {
        let dir = tempfile::tempdir().unwrap();
        let err = run_cmd(&dir, "grep").unwrap_err();
        assert!(matches!(err, ExecError::Fail(m) if m.contains("missing pattern")));
    }

    #[test]
    fn grep_reads_stdin_when_no_file_operand() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("in.txt"), "hello world\nfoo bar\n").unwrap();
        let out = run_cmd(&dir, "grep foo < in.txt").unwrap();
        assert_eq!(out.code, 0);
        assert!(out.stdout.contains("foo bar"));
        assert!(!out.stdout.contains("hello world"));
    }

    #[test]
    fn grep_skips_binary_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("bin.dat"), b"hit\0hit\n").unwrap();
        fs::write(dir.path().join("text.txt"), "hit\n").unwrap();
        let out = run_cmd(&dir, "grep hit .").unwrap();
        assert_eq!(out.stdout, "text.txt:1:hit\n");
    }

    // ---- flags ----

    #[test]
    fn grep_flag_i_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("log.txt"), "ERROR one\nerror two\nok\n").unwrap();
        let out = run_cmd(&dir, "grep -i error log.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "log.txt:1:ERROR one\nlog.txt:2:error two\n");
        let out = run_cmd(&dir, "grep --ignore-case ERROR log.txt").unwrap();
        assert_eq!(out.stdout, "log.txt:1:ERROR one\nlog.txt:2:error two\n");
    }

    #[test]
    fn grep_flag_v_invert() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("log.txt"), "INFO a\nERROR b\nINFO c\n").unwrap();
        let out = run_cmd(&dir, "grep -v INFO log.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "log.txt:2:ERROR b\n");
        let out = run_cmd(&dir, "grep -v 'INFO|ERROR' log.txt").unwrap();
        assert_eq!(out.code, 1);
        assert_eq!(out.stdout, "");
    }

    #[test]
    fn grep_flag_w_word() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "cat\nconcatenate\ncatapult\n").unwrap();
        let out = run_cmd(&dir, "grep -w cat a.txt").unwrap();
        assert_eq!(out.stdout, "a.txt:1:cat\n");
    }

    #[test]
    fn grep_flag_x_whole_line() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "INFO\nINFO extra\n").unwrap();
        let out = run_cmd(&dir, "grep -x INFO a.txt").unwrap();
        assert_eq!(out.stdout, "a.txt:1:INFO\n");
    }

    #[test]
    fn grep_flag_f_fixed_strings() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "a.b\naxb\na*b\n").unwrap();
        let out = run_cmd(&dir, "grep -F 'a.b' a.txt").unwrap();
        assert_eq!(out.stdout, "a.txt:1:a.b\n");
        let out = run_cmd(&dir, "grep -F 'a*b' a.txt").unwrap();
        assert_eq!(out.stdout, "a.txt:3:a*b\n");
        fs::write(dir.path().join("b.txt"), "x [ y\n").unwrap();
        let out = run_cmd(&dir, "grep -F '[' b.txt").unwrap();
        assert_eq!(out.stdout, "b.txt:1:x [ y\n");
        let err = run_cmd(&dir, "grep '[' b.txt").unwrap_err();
        assert!(matches!(err, ExecError::Fail(m) if m.contains("invalid pattern")));
    }

    #[test]
    fn grep_flag_e_explicit_and_multiple_patterns_are_or() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "foo\nbar\nbaz\n").unwrap();
        let out = run_cmd(&dir, "grep -e foo -e bar a.txt").unwrap();
        assert_eq!(out.stdout, "a.txt:1:foo\na.txt:2:bar\n");
        let out = run_cmd(&dir, "grep --regexp=foo --regexp bar a.txt").unwrap();
        assert_eq!(out.stdout, "a.txt:1:foo\na.txt:2:bar\n");
        let out = run_cmd(&dir, "grep -efoo -ebar a.txt").unwrap();
        assert_eq!(out.stdout, "a.txt:1:foo\na.txt:2:bar\n");
        fs::write(dir.path().join("bar"), "foo inside bar\n").unwrap();
        let out = run_cmd(&dir, "grep -e foo a.txt bar").unwrap();
        assert!(out.stdout.contains("a.txt:1:foo"));
        assert!(out.stdout.contains("bar:1:foo inside bar"));
    }

    #[test]
    fn grep_flags_e_and_n_are_noop() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "foo one\nbar\n").unwrap();
        let plain = run_cmd(&dir, "grep foo a.txt").unwrap();
        let out = run_cmd(&dir, "grep -E -n foo a.txt").unwrap();
        assert_eq!(out.stdout, plain.stdout);
        let out = run_cmd(&dir, "grep --extended-regexp --line-number foo a.txt").unwrap();
        assert_eq!(out.stdout, plain.stdout);
    }

    #[test]
    fn grep_flag_c_counts_per_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\nx\ny\n").unwrap();
        fs::write(dir.path().join("b.txt"), "nothing\n").unwrap();
        let out = run_cmd(&dir, "grep -c x a.txt b.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "a.txt:2\nb.txt:0\n");
        let out = run_cmd(&dir, "grep -c zzz a.txt b.txt").unwrap();
        assert_eq!(out.code, 1);
        assert_eq!(out.stdout, "a.txt:0\nb.txt:0\n");
    }

    #[test]
    fn grep_code_zero_if_any_file_matches() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "nothing\n").unwrap();
        fs::write(dir.path().join("b.txt"), "hit\n").unwrap();
        let out = run_cmd(&dir, "grep hit a.txt b.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "b.txt:1:hit\n");
    }

    #[test]
    fn grep_flag_o_only_matching() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "foo bar foo\n").unwrap();
        let out = run_cmd(&dir, "grep -o foo a.txt").unwrap();
        assert_eq!(out.stdout, "a.txt:1:foo\na.txt:1:foo\n");
        let out = run_cmd(&dir, "grep -o 'b.r' a.txt").unwrap();
        assert_eq!(out.stdout, "a.txt:1:bar\n");
    }

    #[test]
    fn grep_flags_l_and_l_list_file_names() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "hit\n").unwrap();
        fs::write(dir.path().join("b.txt"), "nope\n").unwrap();
        let out = run_cmd(&dir, "grep -l hit a.txt b.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "a.txt\n");
        let out = run_cmd(&dir, "grep -L hit a.txt b.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "b.txt\n");
        let out = run_cmd(&dir, "grep -l -L hit a.txt b.txt").unwrap();
        assert_eq!(out.stdout, "a.txt\n");
    }

    #[test]
    fn grep_flag_q_quiet_exit_code_only() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "error here\n").unwrap();
        let out = run_cmd(&dir, "grep -q error a.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "");
        let out = run_cmd(&dir, "grep -q zzz a.txt").unwrap();
        assert_eq!(out.code, 1);
        assert_eq!(out.stdout, "");
        let out = run_cmd(&dir, "grep -q -c error a.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "");
    }

    #[test]
    fn grep_flag_m_max_count_per_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\nx\nx\n").unwrap();
        fs::write(dir.path().join("b.txt"), "x\nx\nx\nx\n").unwrap();
        let out = run_cmd(&dir, "grep -m 2 x a.txt b.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "a.txt:1:x\na.txt:2:x\nb.txt:1:x\nb.txt:2:x\n");
        let out = run_cmd(&dir, "grep -m 0 x a.txt").unwrap();
        assert_eq!(out.code, 1);
        assert_eq!(out.stdout, "");
        let out = run_cmd(&dir, "grep -c -m 1 x a.txt").unwrap();
        assert_eq!(out.stdout, "a.txt:1\n");
    }

    #[test]
    fn grep_context_b_a_c() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("log.txt"),
            "l1\nERR l2\nl3\nl4\nl5\nERR l6\nl7\n",
        )
        .unwrap();
        let out = run_cmd(&dir, "grep -C 1 ERR log.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(
            out.stdout,
            "log.txt-1-l1\nlog.txt:2:ERR l2\nlog.txt-3-l3\n--\nlog.txt-5-l5\nlog.txt:6:ERR l6\nlog.txt-7-l7\n"
        );
        let out = run_cmd(&dir, "grep -B 1 ERR log.txt").unwrap();
        assert_eq!(
            out.stdout,
            "log.txt-1-l1\nlog.txt:2:ERR l2\n--\nlog.txt-5-l5\nlog.txt:6:ERR l6\n"
        );
        let out = run_cmd(&dir, "grep -A 1 ERR log.txt").unwrap();
        assert_eq!(
            out.stdout,
            "log.txt:2:ERR l2\nlog.txt-3-l3\n--\nlog.txt:6:ERR l6\nlog.txt-7-l7\n"
        );
        let out = run_cmd(&dir, "grep --context=1 ERR log.txt").unwrap();
        assert!(out.stdout.contains("log.txt-1-l1"));
        let out = run_cmd(
            &dir,
            "grep --before-context 1 --after-context 1 ERR log.txt",
        )
        .unwrap();
        assert!(out.stdout.contains("log.txt-3-l3"));
    }

    #[test]
    fn grep_context_merges_overlapping_groups_without_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\ny\nx\n").unwrap();
        let out = run_cmd(&dir, "grep -C 2 x a.txt").unwrap();
        assert_eq!(out.stdout, "a.txt:1:x\na.txt-2-y\na.txt:3:x\n");
    }

    #[test]
    fn grep_group_separator_custom_and_bounded() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\na\nmid\nb\nx\n").unwrap();
        let out = run_cmd(&dir, "grep -C 1 --group-separator=@@ x a.txt").unwrap();
        assert_eq!(
            out.stdout,
            "a.txt:1:x\na.txt-2-a\n@@\na.txt-4-b\na.txt:5:x\n"
        );
        let long_sep = "0123456789".repeat(7);
        let err = run_cmd(
            &dir,
            &format!("grep -C 1 --group-separator={long_sep} x a.txt"),
        )
        .unwrap_err();
        assert!(matches!(err, ExecError::Fail(m) if m.contains("group-separator too long")));
    }

    #[test]
    fn grep_short_flags_combine_and_values_attach() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "ERROR one\nerror two\nok\n").unwrap();
        let out = run_cmd(&dir, "grep -vi error a.txt").unwrap();
        assert_eq!(out.stdout, "a.txt:3:ok\n");
        fs::write(dir.path().join("b.txt"), "x\nx\nx\n").unwrap();
        let out = run_cmd(&dir, "grep -m2 x b.txt").unwrap();
        assert_eq!(out.stdout, "b.txt:1:x\nb.txt:2:x\n");
        let out = run_cmd(&dir, "grep -efoo a.txt").unwrap();
        assert_eq!(out.code, 1);
        let out = run_cmd(&dir, "grep -C1 error a.txt").unwrap();
        assert!(out.stdout.contains("a.txt-3-ok"));
        let err = run_cmd(&dir, "grep -c2 error a.txt").unwrap_err();
        assert!(matches!(err, ExecError::Fail(_)));
    }

    #[test]
    fn grep_long_options_with_separate_or_inline_values() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\nx\nx\n").unwrap();
        let out = run_cmd(&dir, "grep --max-count=2 x a.txt").unwrap();
        assert_eq!(out.stdout, "a.txt:1:x\na.txt:2:x\n");
        let out = run_cmd(&dir, "grep --max-count 2 x a.txt").unwrap();
        assert_eq!(out.stdout, "a.txt:1:x\na.txt:2:x\n");
        let out = run_cmd(&dir, "grep --regexp=x a.txt").unwrap();
        assert_eq!(out.code, 0);
        let out = run_cmd(&dir, "grep --count --max-count 1 x a.txt").unwrap();
        assert_eq!(out.stdout, "a.txt:1\n");
    }

    #[test]
    fn grep_double_dash_ends_options() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "-dash\nplain\n").unwrap();
        let out = run_cmd(&dir, "grep -- - a.txt").unwrap();
        assert_eq!(out.stdout, "a.txt:1:-dash\n");
    }

    #[test]
    fn grep_refused_flags_are_fail_with_message() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        for cmd in [
            "grep -P 'x' a.txt",
            "grep -G x a.txt",
            "grep -z x a.txt",
            "grep -b x a.txt",
            "grep -h x a.txt",
            "grep -R x .",
            "grep --text x a.txt",
            "grep --label=STDIN x a.txt",
            "grep --binary-files=text x a.txt",
            "grep --color x a.txt",
            "grep -Q x a.txt",
            "grep --nope x a.txt",
        ] {
            let err = run_cmd(&dir, cmd).unwrap_err();
            assert!(
                matches!(&err, ExecError::Fail(m) if m.contains("not supported") || m.contains("unrecognized")),
                "cmd {cmd:?} -> {err:?}"
            );
        }
        let err = run_cmd(&dir, "grep -P x a.txt").unwrap_err();
        assert!(matches!(err, ExecError::Fail(m) if m.contains("ERE")));
    }

    #[test]
    fn grep_dash_alone_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let err = run_cmd(&dir, "grep x -").unwrap_err();
        assert!(matches!(err, ExecError::Fail(m) if m.contains("stdin")));
    }

    #[test]
    fn grep_context_too_large_is_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        let err = run_cmd(&dir, "grep -C 101 x a.txt").unwrap_err();
        assert!(matches!(err, ExecError::Fail(m) if m.contains("too large")));
        let err = run_cmd(&dir, "grep --context=99999999999999999999 x a.txt").unwrap_err();
        assert!(
            matches!(err, ExecError::Fail(m) if m.contains("invalid number") || m.contains("too large"))
        );
        let err = run_cmd(&dir, "grep -m abc x a.txt").unwrap_err();
        assert!(matches!(err, ExecError::Fail(m) if m.contains("invalid number")));
        let err = run_cmd(&dir, "grep -m").unwrap_err();
        assert!(matches!(err, ExecError::Fail(m) if m.contains("requires an argument")));
    }

    #[test]
    fn grep_mode_priority_l_over_c() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x\nx\n").unwrap();
        let out = run_cmd(&dir, "grep -c -l x a.txt").unwrap();
        assert_eq!(out.stdout, "a.txt\n");
    }

    #[test]
    fn grep_v_with_o_prints_nothing_but_code_zero() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "hello\n").unwrap();
        let out = run_cmd(&dir, "grep -v -o x a.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "");
    }

    #[test]
    fn grep_flags_do_not_weaken_path_security() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            run_cmd(&dir, "grep -v x ../secret.txt").unwrap_err(),
            ExecError::Denied(_)
        ));
        assert!(matches!(
            run_cmd(&dir, "grep -i -l x /etc/passwd").unwrap_err(),
            ExecError::Denied(_)
        ));
        fs::write(dir.path().join(".env"), "SECRET=1\n").unwrap();
        let ctx = ctx_with(
            &dir,
            vec![regex::Regex::new(r".*\.env$").unwrap()],
            1024 * 1024,
        );
        let node = parse_input("grep -i SECRET .env", &HashMap::new()).unwrap();
        assert!(matches!(
            execute(&node, &ctx).unwrap_err(),
            ExecError::Denied(_)
        ));
    }

    #[test]
    fn grep_too_many_matches_is_limit_even_with_flags() {
        let dir = tempfile::tempdir().unwrap();
        let mut content = String::new();
        for _ in 0..50 {
            content.push_str("hit\n");
        }
        fs::write(dir.path().join("a.txt"), content).unwrap();
        let ctx = Ctx {
            resolver: Resolver::new(dir.path()).unwrap(),
            sensibles: vec![],
            secrets: vec![],
            limits: Limits {
                max_grep_matches: 10,
                ..Limits::default()
            },
            trusted: None,
            sandboxed: false,
            sandbox_shell: None,
        };
        for cmd in ["grep hit a.txt", "grep -o hit a.txt", "grep -v zzz a.txt"] {
            let node = parse_input(cmd, &HashMap::new()).unwrap();
            assert!(
                matches!(execute(&node, &ctx).unwrap_err(), ExecError::Limit(_)),
                "cmd {cmd:?} should hit the match limit"
            );
        }
    }

    #[test]
    fn grep_binary_skipped_even_with_invert() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("bin.dat"), b"hit\0hit\n").unwrap();
        let out = run_cmd(&dir, "grep -v zzz bin.dat").unwrap();
        assert_eq!(out.code, 1);
        assert_eq!(out.stdout, "");
    }

    #[test]
    fn grep_flags_work_on_globs_stdin_and_pipes() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "HIT\n").unwrap();
        fs::write(dir.path().join("b.rs"), "HIT\n").unwrap();
        let out = run_cmd(&dir, "grep -i hit *.txt").unwrap();
        assert_eq!(out.stdout, "a.txt:1:HIT\n");
        fs::write(dir.path().join("in.txt"), "Foo Bar\nbaz\n").unwrap();
        let out = run_cmd(&dir, "grep -i foo < in.txt").unwrap();
        assert_eq!(out.stdout, "(stdin):1:Foo Bar\n");
        let out = run_cmd(&dir, "cat in.txt | grep -v baz").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "(stdin):1:Foo Bar\n");
        let out = run_cmd(&dir, "cat in.txt | grep -o -i foo").unwrap();
        assert_eq!(out.stdout, "(stdin):1:Foo\n");
        let out = run_cmd(&dir, "grep -ia hit .").unwrap();
        assert!(out.stdout.contains("a.txt:1:HIT"));
        assert!(out.stdout.contains("b.rs:1:HIT"));
    }

    #[test]
    fn grep_include_filters_recursively_at_any_depth() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src/deep")).unwrap();
        fs::write(dir.path().join("a.rs"), "hit\n").unwrap();
        fs::write(dir.path().join("src/deep/b.rs"), "hit\n").unwrap();
        fs::write(dir.path().join("c.txt"), "hit\n").unwrap();
        let out = run_cmd(&dir, "grep --include=*.rs hit .").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "a.rs:1:hit\nsrc/deep/b.rs:1:hit\n");
    }

    #[test]
    fn grep_include_value_as_separate_arg() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.rs"), "hit\n").unwrap();
        fs::write(dir.path().join("b.txt"), "hit\n").unwrap();
        let out = run_cmd(&dir, "grep --include '*.rs' hit .").unwrap();
        assert_eq!(out.stdout, "a.rs:1:hit\n");
    }

    #[test]
    fn grep_exclude_and_include_combine() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/a.rs"), "hit\n").unwrap();
        fs::write(dir.path().join("src/a_test.rs"), "hit\n").unwrap();
        fs::write(dir.path().join("notes.txt"), "hit\n").unwrap();
        let out = run_cmd(&dir, "grep --include=*.rs --exclude=*_test.rs hit .").unwrap();
        assert_eq!(out.stdout, "src/a.rs:1:hit\n");
    }

    #[test]
    fn grep_exclude_dir_skips_whole_subtree() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("keep")).unwrap();
        fs::create_dir_all(dir.path().join("target/gen")).unwrap();
        fs::write(dir.path().join("keep/hit.txt"), "hit\n").unwrap();
        fs::write(dir.path().join("target/gen/hit.rs"), "hit\n").unwrap();
        let out = run_cmd(&dir, "grep --exclude-dir=target hit .").unwrap();
        assert_eq!(out.stdout, "keep/hit.txt:1:hit\n");
        let out = run_cmd(&dir, "grep --exclude-dir=gen hit .").unwrap();
        assert_eq!(out.stdout, "keep/hit.txt:1:hit\n");
    }

    #[test]
    fn grep_include_does_not_bypass_hidden_or_gitignore() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".hidden.rs"), "hit\n").unwrap();
        fs::write(dir.path().join("visible.rs"), "hit\n").unwrap();
        fs::write(dir.path().join("ignored.log"), "hit\n").unwrap();
        fs::write(dir.path().join("keep.log"), "hit\n").unwrap();
        fs::write(dir.path().join(".gitignore"), "ignored.log\n").unwrap();
        let out = run_cmd(&dir, "grep --include=*.rs hit .").unwrap();
        assert_eq!(out.stdout, "visible.rs:1:hit\n");
        let out = run_cmd(&dir, "grep --include=*.log hit .").unwrap();
        assert_eq!(out.stdout, "keep.log:1:hit\n");
        let out = run_cmd(&dir, "grep -a --include=*.rs hit .").unwrap();
        assert_eq!(out.stdout, ".hidden.rs:1:hit\nvisible.rs:1:hit\n");
    }

    #[test]
    fn grep_glob_filters_do_not_apply_to_explicit_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("c.txt"), "hit\n").unwrap();
        let out = run_cmd(&dir, "grep --include=*.rs hit c.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "c.txt:1:hit\n");
    }

    #[test]
    fn grep_glob_too_long_is_fail() {
        let dir = tempfile::tempdir().unwrap();
        let long = "a".repeat(super::MAX_GREP_GLOB_BYTES + 1);
        let err = run_cmd(&dir, &format!("grep --include={long} hit .")).unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("too long")));
    }

    #[test]
    fn grep_too_many_glob_filters_is_limit() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "hit\n").unwrap();
        let mut cmd = String::from("grep");
        for i in 0..(super::DEFAULT_MAX_GREP_GLOBS + 1) {
            cmd.push_str(&format!(" --include=g{i}.rs"));
        }
        cmd.push_str(" hit .");
        let err = run_cmd(&dir, &cmd).unwrap_err();
        assert!(matches!(err, ExecError::Limit(ref m) if m.contains("too many glob filters")));
    }

    #[test]
    fn grep_invalid_glob_is_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "hit\n").unwrap();
        let err = run_cmd(&dir, "grep --include='[a' hit .").unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("invalid --include glob")));
        let err = run_cmd(&dir, "grep --exclude-dir='[a' hit .").unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("invalid --exclude-dir glob")));
    }

    #[test]
    fn grep_glob_filters_never_read_outside_root() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), "TOPSECRET\n").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret.txt"),
            dir.path().join("link.txt"),
        )
        .unwrap();
        fs::write(dir.path().join("inside.txt"), "hit\n").unwrap();
        let out = run_cmd(&dir, "grep --include=** TOPSECRET .").unwrap();
        assert_eq!(out.code, 1);
        assert_eq!(out.stdout, "");
        let out = run_cmd(&dir, "grep -a --include=** TOPSECRET .").unwrap();
        assert_eq!(out.code, 1);
        assert_eq!(out.stdout, "");
    }

    #[test]
    fn grep_file_flag_reads_patterns_one_per_line() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "alpha\nbeta\ngamma\n").unwrap();
        fs::write(dir.path().join("pats.txt"), "alpha\n\nbeta\n").unwrap();
        let out = run_cmd(&dir, "grep -f pats.txt a.txt").unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "a.txt:1:alpha\na.txt:2:beta\n");
        let out = run_cmd(&dir, "grep --file=pats.txt a.txt").unwrap();
        assert_eq!(out.stdout, "a.txt:1:alpha\na.txt:2:beta\n");
    }

    #[test]
    fn grep_file_and_e_combine_as_union() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "alpha\nbeta\ngamma\n").unwrap();
        fs::write(dir.path().join("pats.txt"), "alpha\n").unwrap();
        let out = run_cmd(&dir, "grep -e beta -f pats.txt a.txt").unwrap();
        assert_eq!(out.stdout, "a.txt:1:alpha\na.txt:2:beta\n");
        let out = run_cmd(&dir, "grep -f pats.txt --file pats.txt a.txt").unwrap();
        assert_eq!(out.stdout, "a.txt:1:alpha\n");
    }

    #[test]
    fn grep_file_empty_without_e_is_fail() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("pats.txt"), "\n\n").unwrap();
        fs::write(dir.path().join("a.txt"), "x\n").unwrap();
        let err = run_cmd(&dir, "grep -f pats.txt a.txt").unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("no patterns")));
    }

    #[test]
    fn grep_file_denies_sensitive_and_escape() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".env"), "alpha\n").unwrap();
        let ctx = ctx_with(
            &dir,
            vec![regex::Regex::new(r".*\.env$").unwrap()],
            1024 * 1024,
        );
        let node = parse_input("grep -f .env x .", &HashMap::new()).unwrap();
        assert!(matches!(
            execute(&node, &ctx).unwrap_err(),
            ExecError::Denied(_)
        ));
        let node = parse_input("grep --exclude-from=.env x .", &HashMap::new()).unwrap();
        assert!(matches!(
            execute(&node, &ctx).unwrap_err(),
            ExecError::Denied(_)
        ));
        assert!(matches!(
            run_cmd(&dir, "grep -f ../pats.txt x .").unwrap_err(),
            ExecError::Denied(_)
        ));
    }

    #[test]
    fn grep_file_denies_oversized_and_rejects_non_utf8() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("big.txt"), vec![b'a'; 2048]).unwrap();
        let ctx = ctx_with(&dir, vec![], 1024);
        let node = parse_input("grep -f big.txt x .", &HashMap::new()).unwrap();
        assert!(matches!(
            execute(&node, &ctx).unwrap_err(),
            ExecError::Limit(_)
        ));
        fs::write(dir.path().join("bad.bin"), vec![0xff, 0xfe, b'\n']).unwrap();
        let err = run_cmd(&dir, "grep -f bad.bin x .").unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("UTF-8")));
    }

    #[test]
    fn grep_file_rejects_invalid_pattern_and_long_line() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "ok\n").unwrap();
        fs::write(dir.path().join("pats.txt"), "ok\n[\n").unwrap();
        let err = run_cmd(&dir, "grep -f pats.txt a.txt").unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("invalid pattern")));
        let long = "a".repeat(super::MAX_GREP_PATTERN_BYTES + 1);
        fs::write(dir.path().join("long.txt"), format!("{long}\n")).unwrap();
        let err = run_cmd(&dir, "grep -f long.txt a.txt").unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("too long")));
    }

    #[test]
    fn grep_too_many_patterns_from_file_is_limit() {
        let dir = tempfile::tempdir().unwrap();
        let mut pats = String::new();
        for i in 0..11 {
            pats.push_str(&format!("p{i}\n"));
        }
        fs::write(dir.path().join("pats.txt"), pats).unwrap();
        fs::write(dir.path().join("a.txt"), "p0\n").unwrap();
        let ctx = Ctx {
            resolver: Resolver::new(dir.path()).unwrap(),
            sensibles: vec![],
            secrets: vec![],
            limits: Limits {
                max_grep_patterns: 10,
                ..Limits::default()
            },
            trusted: None,
            sandboxed: false,
            sandbox_shell: None,
        };
        let node = parse_input("grep -f pats.txt a.txt", &HashMap::new()).unwrap();
        assert!(matches!(
            execute(&node, &ctx).unwrap_err(),
            ExecError::Limit(ref m) if m.contains("too many patterns")
        ));
    }

    #[test]
    fn grep_exclude_from_applies_globs_and_counts_toward_limit() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.rs"), "hit\n").unwrap();
        fs::write(dir.path().join("b.txt"), "hit\n").unwrap();
        fs::write(dir.path().join("ex.txt"), "*.txt\n\n").unwrap();
        let out = run_cmd(&dir, "grep --exclude-from=ex.txt hit .").unwrap();
        assert_eq!(out.stdout, "a.rs:1:hit\n");
        let out = run_cmd(&dir, "grep --exclude=*.md --exclude-from=ex.txt hit .").unwrap();
        assert_eq!(out.stdout, "a.rs:1:hit\n");
        let mut cmd = String::from("grep --exclude-from=ex.txt");
        for i in 0..super::DEFAULT_MAX_GREP_GLOBS {
            cmd.push_str(&format!(" --exclude=g{i}.x"));
        }
        cmd.push_str(" hit .");
        let err = run_cmd(&dir, &cmd).unwrap_err();
        assert!(matches!(err, ExecError::Limit(ref m) if m.contains("too many glob filters")));
        fs::write(dir.path().join("bad_ex.txt"), "[a\n").unwrap();
        let err = run_cmd(&dir, "grep --exclude-from=bad_ex.txt hit .").unwrap_err();
        assert!(matches!(err, ExecError::Fail(ref m) if m.contains("invalid --exclude-from glob")));
    }

    proptest! {
        #[test]
        fn proptest_glob_filters_never_list_symlink_escape(
            globs in proptest::collection::vec("[a-z*?_.]{1,10}", 0..6),
        ) {
            let dir = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            fs::write(outside.path().join("secret.txt"), "LEAKME\n").unwrap();
            std::os::unix::fs::symlink(outside.path().join("secret.txt"), dir.path().join("link"))
                .unwrap();
            fs::write(dir.path().join("inside.txt"), "hit\n").unwrap();
            let mut cmd = String::from("grep");
            for g in &globs {
                cmd.push_str(&format!(" --include={g} --exclude={g}"));
            }
            cmd.push_str(" LEAKME .");
            let node = match parse_input(&cmd, &HashMap::new()) {
                Ok(n) => n,
                Err(_) => return Ok(()),
            };
            let ctx = Ctx {
                resolver: Resolver::new(dir.path()).unwrap(),
                sensibles: vec![],
                secrets: vec![],
                limits: Limits::default(),
                trusted: None,
                sandboxed: false,
                sandbox_shell: None,
            };
            match execute(&node, &ctx) {
                Ok(out) => {
                    let bytes = out.stdout.clone().into_bytes();
                    let stdout = String::from_utf8_lossy(&bytes);
                    prop_assert!(!stdout.contains("link"), "symlink escape listed: {stdout}");
                    prop_assert!(!stdout.contains("LEAKME"), "outside content leaked: {stdout}");
                }
                Err(ExecError::Fail(_)) | Err(ExecError::Denied(_)) => {}
                Err(other) => return Err(proptest::test_runner::TestCaseError::fail(format!("unexpected error: {other:?}"))),
            }
        }
    }

    proptest! {
        #[test]
        fn proptest_random_pattern_and_flag_never_panics(
            pattern in ".*",
            flag in prop::sample::select(vec!["-i", "-v", "-w", "-x", "-F", "-c", "-o", "-l", "-L", "-q", "-n", "-E", "-a", "-vi", "-cF", "--invert-match", "--count"]),
        ) {
            prop_assume!(!pattern.contains('\0'));
            let dir = tempfile::tempdir().unwrap();
            fs::write(dir.path().join("a.txt"), "hello ERROR world\nfoo bar\n").unwrap();
            let quoted = shell_words::quote(&pattern);
            let cmd = format!("grep {flag} -e {quoted} a.txt");
            let node = match parse_input(&cmd, &HashMap::new()) {
                Ok(n) => n,
                Err(_) => return Ok(()),
            };
            let ctx = Ctx {
                resolver: Resolver::new(dir.path()).unwrap(),
                sensibles: vec![],
                secrets: vec![],
                limits: Limits::default(),
                trusted: None,
                sandboxed: false,
                sandbox_shell: None,
            };
            match execute(&node, &ctx) {
                Ok(out) => {
                    prop_assert!(out.code == 0 || out.code == 1, "unexpected code {}", out.code);
                    prop_assert!(String::from_utf8(out.stdout.clone().into_bytes()).is_ok(), "stdout not utf8");
                }
                // fail-closed refusals are fine (usage error or security refusal);
                // anything else (limit) would be a bug for this tiny input
                Err(ExecError::Fail(_)) | Err(ExecError::Denied(_)) => {}
                Err(other) => return Err(proptest::test_runner::TestCaseError::fail(format!("unexpected error: {other:?}"))),
            }
        }
    }
}
