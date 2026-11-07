use std::collections::HashMap;
use std::path::Path;

pub const DEFAULT_MAX_GLOB_MATCHES: usize = 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("missing command")]
    MissingCommand,
    #[error("unterminated quote")]
    UnterminatedQuote,
    #[error("backticks are never allowed (no sub-execution)")]
    Backticks,
    #[error("background '&' is not allowed")]
    BackgroundAmpersand,
    #[error("operator '||' is not allowed")]
    OrOperator,
    #[error("stdin redirection '<' is not supported in v1")]
    RedirectInUnsupported,
    #[error("appending stderr ('2>>' / '&>>') is not supported in v1")]
    AppendStderrUnsupported,
    #[error("parentheses are only allowed as '$(VAR)' variable reference")]
    SubshellParens,
    #[error("'trusted' command is not allowed in a pipe")]
    TrustedInPipe,
    #[error("redirection is only allowed on the last command of a pipe")]
    RedirectInPipe,
    #[error("variable assignment is not allowed")]
    Assignment,
    #[error("special variable '{0}' is not allowed")]
    SpecialVariable(String),
    #[error("invalid variable reference '{0}'")]
    InvalidVariable(String),
    #[error("undeclared variable '{0}'")]
    UndeclaredVariable(String),
    #[error("unexpected operator '{0}'")]
    UnexpectedOperator(String),
    #[error("redirection is missing a target path")]
    MissingRedirectTarget,
    #[error("tokenization error: {0}")]
    Tokenize(String),
    #[error("invalid glob pattern: {0}")]
    InvalidGlob(String),
    #[error("glob i/o error: {0}")]
    GlobIo(String),
    #[error("glob match denied: {0}")]
    GlobDenied(String),
    #[error("glob matched more than {0} files")]
    TooManyGlobMatches(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Seq(Vec<Node>),
    Pipe(Vec<SimpleCommand>),
    Simple(SimpleCommand),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleCommand {
    pub argv: Vec<Arg>,
    pub redirects: Vec<Redirect>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arg {
    pub text: String,
    pub glob: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redirect {
    Out { path: String, append: bool },
    Err { path: String },
    ErrToOut,
    All { path: String, append: bool },
}

pub fn is_trusted(cmd: &SimpleCommand) -> bool {
    cmd.argv.first().is_some_and(|a| a.text == "trusted")
}

pub fn all_commands(node: &Node) -> Vec<&SimpleCommand> {
    let mut out = Vec::new();
    collect_commands(node, &mut out);
    out
}

fn collect_commands<'a>(node: &'a Node, out: &mut Vec<&'a SimpleCommand>) {
    match node {
        Node::Seq(nodes) => {
            for n in nodes {
                collect_commands(n, out);
            }
        }
        Node::Pipe(cmds) => out.extend(cmds.iter()),
        Node::Simple(cmd) => out.push(cmd),
    }
}

pub fn pipe_has_trusted(node: &Node) -> bool {
    match node {
        Node::Seq(nodes) => nodes.iter().any(pipe_has_trusted),
        Node::Pipe(cmds) => cmds.iter().any(is_trusted),
        Node::Simple(_) => false,
    }
}

pub fn parse_input(input: &str, vars: &HashMap<String, String>) -> Result<Node, ParseError> {
    let tokens = lex(input)?;
    let mut parser = TokenParser {
        tokens,
        pos: 0,
        vars,
    };
    let node = parser.parse_seq()?;
    if parser.pos != parser.tokens.len() {
        return Err(ParseError::UnexpectedOperator(format!(
            "{:?}",
            parser.tokens[parser.pos]
        )));
    }
    Ok(node)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    And,
    Semi,
    Pipe,
    Out,
    Append,
    ErrOut,
    ErrToOut,
    AllOut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Word(RawWord),
    Op(Op),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawWord {
    text: String,
    quoted: bool,
}

fn lex(input: &str) -> Result<Vec<Tok>, ParseError> {
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut brace_var = false;
    let mut cmd_subst = 0usize;
    let mut i = 0usize;
    macro_rules! flush {
        () => {
            if !cur.is_empty() || quoted {
                tokens.push(Tok::Word(RawWord {
                    text: std::mem::take(&mut cur),
                    quoted: std::mem::take(&mut quoted),
                }));
            }
        };
    }
    while i < chars.len() {
        let c = chars[i];
        match c {
            _ if c.is_whitespace() => {
                flush!();
                i += 1;
            }
            '\'' => {
                quoted = true;
                cur.push(c);
                i += 1;
                let mut closed = false;
                while i < chars.len() {
                    if chars[i] == '`' {
                        return Err(ParseError::Backticks);
                    }
                    cur.push(chars[i]);
                    if chars[i] == '\'' {
                        closed = true;
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                if !closed {
                    return Err(ParseError::UnterminatedQuote);
                }
            }
            '"' => {
                quoted = true;
                cur.push(c);
                i += 1;
                let mut closed = false;
                while i < chars.len() {
                    if chars[i] == '`' {
                        return Err(ParseError::Backticks);
                    }
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        if chars[i + 1] == '`' {
                            return Err(ParseError::Backticks);
                        }
                        cur.push(chars[i]);
                        cur.push(chars[i + 1]);
                        i += 2;
                        continue;
                    }
                    cur.push(chars[i]);
                    if chars[i] == '"' {
                        closed = true;
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                if !closed {
                    return Err(ParseError::UnterminatedQuote);
                }
            }
            '`' => return Err(ParseError::Backticks),
            '&' => {
                if i + 1 < chars.len() && chars[i + 1] == '&' {
                    flush!();
                    tokens.push(Tok::Op(Op::And));
                    i += 2;
                } else if i + 1 < chars.len() && chars[i + 1] == '>' {
                    flush!();
                    tokens.push(Tok::Op(Op::AllOut));
                    i += 2;
                    if i < chars.len() && chars[i] == '>' {
                        return Err(ParseError::AppendStderrUnsupported);
                    }
                } else {
                    return Err(ParseError::BackgroundAmpersand);
                }
            }
            '|' => {
                if i + 1 < chars.len() && chars[i + 1] == '|' {
                    return Err(ParseError::OrOperator);
                }
                flush!();
                tokens.push(Tok::Op(Op::Pipe));
                i += 1;
            }
            ';' => {
                flush!();
                tokens.push(Tok::Op(Op::Semi));
                i += 1;
            }
            '>' => {
                if cur == "2" && !quoted {
                    cur.clear();
                    if i + 1 < chars.len() && chars[i + 1] == '>' {
                        return Err(ParseError::AppendStderrUnsupported);
                    }
                    if i + 2 < chars.len() && chars[i + 1] == '&' && chars[i + 2] == '1' {
                        tokens.push(Tok::Op(Op::ErrToOut));
                        i += 3;
                    } else {
                        tokens.push(Tok::Op(Op::ErrOut));
                        i += 1;
                    }
                } else {
                    flush!();
                    if i + 1 < chars.len() && chars[i + 1] == '>' {
                        tokens.push(Tok::Op(Op::Append));
                        i += 2;
                    } else {
                        tokens.push(Tok::Op(Op::Out));
                        i += 1;
                    }
                }
            }
            '<' => return Err(ParseError::RedirectInUnsupported),
            '{' => {
                if cur.ends_with('$') && !brace_var {
                    brace_var = true;
                    cur.push(c);
                    i += 1;
                } else {
                    return Err(ParseError::UnexpectedOperator("{".to_string()));
                }
            }
            '}' => {
                if brace_var {
                    brace_var = false;
                    cur.push(c);
                    i += 1;
                } else {
                    return Err(ParseError::UnexpectedOperator("}".to_string()));
                }
            }
            '(' => {
                if cur.ends_with('$') {
                    cmd_subst += 1;
                    cur.push(c);
                    i += 1;
                } else {
                    return Err(ParseError::SubshellParens);
                }
            }
            ')' => {
                if cmd_subst > 0 {
                    cmd_subst -= 1;
                    cur.push(c);
                    i += 1;
                } else {
                    return Err(ParseError::SubshellParens);
                }
            }
            _ => {
                cur.push(c);
                i += 1;
            }
        }
    }
    flush!();
    Ok(tokens)
}

struct TokenParser<'a> {
    tokens: Vec<Tok>,
    pos: usize,
    vars: &'a HashMap<String, String>,
}

impl TokenParser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.pos)
    }

    fn peek_op(&self) -> Option<Op> {
        match self.peek() {
            Some(Tok::Op(op)) => Some(*op),
            _ => None,
        }
    }

    fn parse_seq(&mut self) -> Result<Node, ParseError> {
        let mut nodes = vec![self.parse_pipe()?];
        while matches!(self.peek_op(), Some(Op::And) | Some(Op::Semi)) {
            self.pos += 1;
            nodes.push(self.parse_pipe()?);
        }
        if nodes.len() == 1 {
            Ok(nodes.pop().expect("one node was just pushed"))
        } else {
            Ok(Node::Seq(nodes))
        }
    }

    fn parse_pipe(&mut self) -> Result<Node, ParseError> {
        let mut cmds = vec![self.parse_simple()?];
        while self.peek_op() == Some(Op::Pipe) {
            self.pos += 1;
            cmds.push(self.parse_simple()?);
        }
        for (idx, cmd) in cmds.iter().enumerate() {
            if cmds.len() > 1 && is_trusted(cmd) {
                return Err(ParseError::TrustedInPipe);
            }
            if idx + 1 < cmds.len() && !cmd.redirects.is_empty() {
                return Err(ParseError::RedirectInPipe);
            }
        }
        if cmds.len() == 1 {
            Ok(Node::Simple(
                cmds.pop().expect("one command was just pushed"),
            ))
        } else {
            Ok(Node::Pipe(cmds))
        }
    }

    fn parse_simple(&mut self) -> Result<SimpleCommand, ParseError> {
        let mut argv = Vec::new();
        let mut redirects = Vec::new();
        loop {
            match self.peek_op() {
                Some(op) if is_redirect(op) => {
                    self.pos += 1;
                    match op {
                        Op::ErrToOut => redirects.push(Redirect::ErrToOut),
                        Op::Out | Op::Append | Op::ErrOut | Op::AllOut => {
                            let Some(Tok::Word(raw)) = self.peek() else {
                                return Err(ParseError::MissingRedirectTarget);
                            };
                            let raw = raw.clone();
                            self.pos += 1;
                            let path = expand_vars(&unquote_word(&raw)?, self.vars)?;
                            if has_glob(&path) {
                                return Err(ParseError::InvalidGlob(
                                    "glob in redirection target".to_string(),
                                ));
                            }
                            redirects.push(match op {
                                Op::Out => Redirect::Out {
                                    path,
                                    append: false,
                                },
                                Op::Append => Redirect::Out { path, append: true },
                                Op::ErrOut => Redirect::Err { path },
                                Op::AllOut => Redirect::All {
                                    path,
                                    append: false,
                                },
                                _ => unreachable!("matched redirect ops above"),
                            });
                        }
                        _ => unreachable!("is_redirect filter"),
                    }
                }
                _ => match self.peek() {
                    Some(Tok::Word(raw)) => {
                        let raw = raw.clone();
                        self.pos += 1;
                        let text = unquote_word(&raw)?;
                        reject_assignment(raw.quoted, &text)?;
                        let expanded = expand_vars(&text, self.vars)?;
                        let glob = has_glob(&expanded);
                        argv.push(Arg {
                            text: expanded,
                            glob,
                        });
                    }
                    _ => break,
                },
            }
        }
        if argv.is_empty() {
            return Err(ParseError::MissingCommand);
        }
        Ok(SimpleCommand { argv, redirects })
    }
}

fn is_redirect(op: Op) -> bool {
    matches!(
        op,
        Op::Out | Op::Append | Op::ErrOut | Op::ErrToOut | Op::AllOut
    )
}

fn unquote_word(raw: &RawWord) -> Result<String, ParseError> {
    let parts = shell_words::split(&raw.text).map_err(|e| ParseError::Tokenize(e.to_string()))?;
    Ok(parts.into_iter().next().unwrap_or_default())
}

fn reject_assignment(quoted: bool, text: &str) -> Result<(), ParseError> {
    if quoted {
        return Ok(());
    }
    if let Some(eq) = text.find('=') {
        let name = &text[..eq];
        if !name.is_empty() && is_valid_var_name(name) {
            return Err(ParseError::Assignment);
        }
    }
    Ok(())
}

fn is_valid_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn lookup_var<'a>(
    name: &str,
    raw: &str,
    vars: &'a HashMap<String, String>,
) -> Result<&'a str, ParseError> {
    if !is_valid_var_name(name) {
        return Err(ParseError::InvalidVariable(raw.to_string()));
    }
    vars.get(name)
        .map(String::as_str)
        .ok_or_else(|| ParseError::UndeclaredVariable(name.to_string()))
}

fn expand_vars(text: &str, vars: &HashMap<String, String>) -> Result<String, ParseError> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::new();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] != '$' {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        if i + 1 >= chars.len() {
            return Err(ParseError::InvalidVariable("$".to_string()));
        }
        match chars[i + 1] {
            '{' => {
                let mut j = i + 2;
                while j < chars.len() && chars[j] != '}' {
                    j += 1;
                }
                if j >= chars.len() {
                    let raw: String = chars[i..].iter().collect();
                    return Err(ParseError::InvalidVariable(raw));
                }
                let name: String = chars[i + 2..j].iter().collect();
                let raw: String = chars[i..=j].iter().collect();
                out.push_str(lookup_var(&name, &raw, vars)?);
                i = j + 1;
            }
            '(' => {
                let mut j = i + 2;
                while j < chars.len() && chars[j] != ')' {
                    j += 1;
                }
                if j >= chars.len() {
                    let raw: String = chars[i..].iter().collect();
                    return Err(ParseError::InvalidVariable(raw));
                }
                let name: String = chars[i + 2..j].iter().collect();
                let raw: String = chars[i..=j].iter().collect();
                out.push_str(lookup_var(&name, &raw, vars)?);
                i = j + 1;
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let mut j = i + 1;
                while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
                    j += 1;
                }
                let name: String = chars[i + 1..j].iter().collect();
                let raw: String = chars[i..j].iter().collect();
                out.push_str(lookup_var(&name, &raw, vars)?);
                i = j;
            }
            c => return Err(ParseError::SpecialVariable(format!("${c}"))),
        }
    }
    Ok(out)
}

pub fn has_glob(text: &str) -> bool {
    text.contains('*') || text.contains('?')
}

pub fn expand_globs(
    root: &Path,
    pattern: &str,
    max_matches: usize,
) -> Result<Vec<String>, ParseError> {
    use wax::walk::Entry as _;
    let glob = wax::Glob::new(pattern).map_err(|e| ParseError::InvalidGlob(e.to_string()))?;
    let resolver =
        crate::resolve::Resolver::new(root).map_err(|e| ParseError::GlobDenied(e.to_string()))?;
    let mut matches = Vec::new();
    for entry in glob.walk(resolver.root()) {
        let entry = entry.map_err(|e| ParseError::GlobIo(e.to_string()))?;
        let path = entry.path();
        let Ok(rel) = path.strip_prefix(resolver.root()) else {
            continue;
        };
        let Some(rel_str) = rel.to_str() else {
            continue;
        };
        resolver
            .resolve(rel_str)
            .map_err(|e| ParseError::GlobDenied(e.to_string()))?;
        matches.push(rel_str.to_string());
        if matches.len() > max_matches {
            return Err(ParseError::TooManyGlobMatches(max_matches));
        }
    }
    matches.sort();
    Ok(matches)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_vars() -> HashMap<String, String> {
        HashMap::new()
    }

    fn parse(input: &str) -> Result<Node, ParseError> {
        parse_input(input, &no_vars())
    }

    fn arg(text: &str) -> Arg {
        Arg {
            text: text.to_string(),
            glob: has_glob(text),
        }
    }

    fn simple(argv: &[&str], redirects: Vec<Redirect>) -> Node {
        Node::Simple(SimpleCommand {
            argv: argv.iter().map(|a| arg(a)).collect(),
            redirects,
        })
    }

    #[test]
    fn parses_simple_command() {
        assert_eq!(parse("ls src").unwrap(), simple(&["ls", "src"], vec![]));
    }

    #[test]
    fn parses_and_chain() {
        let node = parse("ls && cat a.txt").unwrap();
        let Node::Seq(nodes) = node else {
            panic!("expected Seq");
        };
        assert_eq!(nodes.len(), 2);
    }

    #[test]
    fn semicolon_behaves_like_and_chain() {
        let node = parse("ls; cat a.txt").unwrap();
        assert!(matches!(node, Node::Seq(_)));
    }

    #[test]
    fn parses_pipe() {
        let node = parse("cat a.txt | grep foo").unwrap();
        let Node::Pipe(cmds) = node else {
            panic!("expected Pipe");
        };
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].argv[0].text, "cat");
    }

    #[test]
    fn parses_pipe_without_spaces() {
        let node = parse("cat a.txt|grep foo").unwrap();
        assert!(matches!(node, Node::Pipe(_)));
    }

    #[test]
    fn parses_redirections() {
        let node = parse("echo hi > out.txt").unwrap();
        let Node::Simple(cmd) = node else {
            panic!("expected Simple");
        };
        assert_eq!(
            cmd.redirects,
            vec![Redirect::Out {
                path: "out.txt".to_string(),
                append: false
            }]
        );
        let node = parse("echo hi >> out.txt").unwrap();
        let Node::Simple(cmd) = node else {
            panic!("expected Simple");
        };
        assert_eq!(
            cmd.redirects,
            vec![Redirect::Out {
                path: "out.txt".to_string(),
                append: true
            }]
        );
    }

    #[test]
    fn parses_stderr_redirections() {
        let node = parse("ls 2> err.txt").unwrap();
        let Node::Simple(cmd) = node else {
            panic!("expected Simple");
        };
        assert_eq!(
            cmd.redirects,
            vec![Redirect::Err {
                path: "err.txt".to_string()
            }]
        );
        let node = parse("ls 2>&1").unwrap();
        let Node::Simple(cmd) = node else {
            panic!("expected Simple");
        };
        assert_eq!(cmd.redirects, vec![Redirect::ErrToOut]);
        let node = parse("ls &> all.txt").unwrap();
        let Node::Simple(cmd) = node else {
            panic!("expected Simple");
        };
        assert_eq!(
            cmd.redirects,
            vec![Redirect::All {
                path: "all.txt".to_string(),
                append: false
            }]
        );
    }

    #[test]
    fn quoted_operators_are_literal() {
        let node = parse("echo \"a|b\" 'c&&d'").unwrap();
        let Node::Simple(cmd) = node else {
            panic!("expected Simple");
        };
        assert_eq!(cmd.argv[1].text, "a|b");
        assert_eq!(cmd.argv[2].text, "c&&d");
    }

    #[test]
    fn quoted_fd2_is_not_a_redirect() {
        let node = parse("echo \"2\"> out.txt").unwrap();
        let Node::Simple(cmd) = node else {
            panic!("expected Simple");
        };
        assert_eq!(cmd.argv[1].text, "2");
        assert_eq!(
            cmd.redirects,
            vec![Redirect::Out {
                path: "out.txt".to_string(),
                append: false
            }]
        );
    }

    #[test]
    fn rejects_backticks_even_quoted() {
        assert!(matches!(parse("ls `rm -rf /`"), Err(ParseError::Backticks)));
        assert!(matches!(parse("echo \"a`b\""), Err(ParseError::Backticks)));
    }

    #[test]
    fn rejects_subshell_parens() {
        assert!(matches!(parse("(ls)"), Err(ParseError::SubshellParens)));
        assert!(matches!(
            parse("ls $(rm -rf /)"),
            Err(ParseError::InvalidVariable(_)) | Err(ParseError::UndeclaredVariable(_))
        ));
    }

    #[test]
    fn rejects_special_variables() {
        assert!(matches!(
            parse("echo $?"),
            Err(ParseError::SpecialVariable(_))
        ));
        assert!(matches!(
            parse("echo $0"),
            Err(ParseError::SpecialVariable(_))
        ));
        assert!(matches!(
            parse("echo $$"),
            Err(ParseError::SpecialVariable(_))
        ));
    }

    #[test]
    fn rejects_undeclared_variable() {
        assert!(matches!(
            parse("ls $ROOT"),
            Err(ParseError::UndeclaredVariable(_))
        ));
        assert!(matches!(
            parse("ls ${ROOT}"),
            Err(ParseError::UndeclaredVariable(_))
        ));
        assert!(matches!(
            parse("ls $(ROOT)"),
            Err(ParseError::UndeclaredVariable(_))
        ));
    }

    #[test]
    fn expands_declared_variables() {
        let mut vars = no_vars();
        vars.insert("ROOT".to_string(), "src".to_string());
        let node = parse_input("ls $ROOT/${SUB}/$(FILE)", &vars).unwrap_err();
        assert!(matches!(node, ParseError::UndeclaredVariable(_)));
        vars.insert("SUB".to_string(), "sub".to_string());
        vars.insert("FILE".to_string(), "a.txt".to_string());
        let node = parse_input("ls $ROOT/${SUB}/$(FILE)", &vars).unwrap();
        let Node::Simple(cmd) = node else {
            panic!("expected Simple");
        };
        assert_eq!(cmd.argv[1].text, "src/sub/a.txt");
    }

    #[test]
    fn rejects_assignment() {
        assert!(matches!(parse("FOO=bar ls"), Err(ParseError::Assignment)));
        let node = parse("echo \"FOO=bar\"").unwrap();
        let Node::Simple(cmd) = node else {
            panic!("expected Simple");
        };
        assert_eq!(cmd.argv[1].text, "FOO=bar");
    }

    #[test]
    fn rejects_unsupported_operators() {
        assert!(matches!(
            parse("ls < in.txt"),
            Err(ParseError::RedirectInUnsupported)
        ));
        assert!(matches!(parse("ls || cat"), Err(ParseError::OrOperator)));
        assert!(matches!(
            parse("ls &"),
            Err(ParseError::BackgroundAmpersand)
        ));
        assert!(matches!(
            parse("ls 2>> e"),
            Err(ParseError::AppendStderrUnsupported)
        ));
        assert!(matches!(
            parse("ls &>> e"),
            Err(ParseError::AppendStderrUnsupported)
        ));
    }

    #[test]
    fn rejects_trusted_in_pipe() {
        assert!(matches!(
            parse("trusted build | cat log"),
            Err(ParseError::TrustedInPipe)
        ));
        assert!(matches!(
            parse("cat log | trusted build"),
            Err(ParseError::TrustedInPipe)
        ));
    }

    #[test]
    fn allows_trusted_in_seq() {
        let node = parse("ls && trusted build").unwrap();
        let Node::Seq(nodes) = node else {
            panic!("expected Seq");
        };
        assert!(is_trusted(match &nodes[1] {
            Node::Simple(cmd) => cmd,
            _ => panic!("expected Simple"),
        }));
    }

    #[test]
    fn rejects_redirect_on_non_last_pipe_element() {
        assert!(matches!(
            parse("ls > out.txt | cat"),
            Err(ParseError::RedirectInPipe)
        ));
        let node = parse("ls | cat > out.txt").unwrap();
        assert!(matches!(node, Node::Pipe(_)));
    }

    #[test]
    fn rejects_empty_and_dangling_operators() {
        assert!(matches!(parse(""), Err(ParseError::MissingCommand)));
        assert!(matches!(parse("&& ls"), Err(ParseError::MissingCommand)));
        assert!(matches!(parse("ls &&"), Err(ParseError::MissingCommand)));
        assert!(matches!(parse("ls |"), Err(ParseError::MissingCommand)));
        assert!(matches!(
            parse("ls >"),
            Err(ParseError::MissingRedirectTarget)
        ));
    }

    #[test]
    fn marks_glob_arguments() {
        let node = parse("ls src/*.rs").unwrap();
        let Node::Simple(cmd) = node else {
            panic!("expected Simple");
        };
        assert!(cmd.argv[1].glob);
        assert!(!cmd.argv[0].glob);
    }

    #[test]
    fn rejects_glob_in_redirect_target() {
        assert!(matches!(
            parse("ls > *.txt"),
            Err(ParseError::InvalidGlob(_))
        ));
    }

    #[test]
    fn expand_globs_lists_matches_within_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/a.rs"), b"a").unwrap();
        std::fs::write(dir.path().join("src/b.rs"), b"b").unwrap();
        std::fs::write(dir.path().join("src/c.txt"), b"c").unwrap();
        let matches = expand_globs(dir.path(), "src/*.rs", DEFAULT_MAX_GLOB_MATCHES).unwrap();
        assert_eq!(
            matches,
            vec!["src/a.rs".to_string(), "src/b.rs".to_string()]
        );
    }

    #[test]
    fn expand_globs_respects_match_bound() {
        let dir = tempfile::tempdir().unwrap();
        for n in 0..5 {
            std::fs::write(dir.path().join(format!("f{n}.txt")), b"x").unwrap();
        }
        assert!(matches!(
            expand_globs(dir.path(), "*.txt", 3),
            Err(ParseError::TooManyGlobMatches(3))
        ));
    }

    #[test]
    fn expand_globs_rejects_invalid_pattern() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            expand_globs(dir.path(), "[", DEFAULT_MAX_GLOB_MATCHES),
            Err(ParseError::InvalidGlob(_))
        ));
    }
}
