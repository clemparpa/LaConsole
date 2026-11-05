use std::io::Read;
use std::time::Duration;

use super::{Ctx, ExecError, RawOutput};
use crate::parse::SimpleCommand;

pub const DEFAULT_MAX_HTTP_BODY_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_HTTP_RESPONSE_BYTES: usize = 1024 * 1024;
pub const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 10;
pub const MAX_REDIRECTS: usize = 5;

const ALLOWED_HOSTS: [&str; 1] = ["localhost"];

pub(crate) fn run(cmd: &SimpleCommand, ctx: &Ctx) -> Result<RawOutput, ExecError> {
    let args: Vec<&str> = cmd.argv[1..].iter().map(|a| a.text.as_str()).collect();
    if args.len() < 2 {
        return Err(ExecError::Fail(
            "http: usage: http <METHOD> <url> [--data <body>] [--header <k:v>]".to_string(),
        ));
    }
    let method = parse_method(args[0])?;
    let mut url = parse_url(args[1])?;
    let mut data: Option<Vec<u8>> = None;
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut i = 2;
    while i < args.len() {
        match args[i] {
            "--data" => {
                let Some(body) = args.get(i + 1) else {
                    return Err(ExecError::Fail("http: --data needs a value".to_string()));
                };
                if body.len() > ctx.limits.max_http_body_bytes {
                    return Err(ExecError::Denied(format!(
                        "http: --data too large ({} bytes max)",
                        ctx.limits.max_http_body_bytes
                    )));
                }
                data = Some(body.as_bytes().to_vec());
                i += 2;
            }
            "--header" => {
                let Some(hv) = args.get(i + 1) else {
                    return Err(ExecError::Fail("http: --header needs a value".to_string()));
                };
                let Some((k, v)) = hv.split_once(':') else {
                    return Err(ExecError::Fail(format!(
                        "http: invalid header '{hv}' (expected k:v)"
                    )));
                };
                headers.push((k.trim().to_string(), v.trim().to_string()));
                i += 2;
            }
            other => {
                return Err(ExecError::Fail(format!(
                    "http: unrecognized argument '{other}'"
                )));
            }
        }
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(ctx.limits.http_timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| ExecError::Fail(format!("http: client error: {err}")))?;

    let mut redirects_left = ctx.limits.max_http_redirects;
    loop {
        let mut req = client.request(method.clone(), url.as_str());
        for (k, v) in &headers {
            let name = reqwest::header::HeaderName::from_bytes(k.as_bytes())
                .map_err(|_| ExecError::Fail(format!("http: invalid header name '{k}'")))?;
            let value = reqwest::header::HeaderValue::from_str(v)
                .map_err(|_| ExecError::Fail(format!("http: invalid header value for '{k}'")))?;
            req = req.header(name, value);
        }
        if let Some(body) = &data {
            req = req.body(body.clone());
        }
        let resp = req
            .send()
            .map_err(|err| ExecError::Fail(format!("http: request failed: {err}")))?;
        let status = resp.status();
        if status.is_redirection() {
            if redirects_left == 0 {
                return Err(ExecError::Denied(format!(
                    "http: too many redirects (max {})",
                    ctx.limits.max_http_redirects
                )));
            }
            redirects_left -= 1;
            let Some(location) = resp.headers().get(reqwest::header::LOCATION) else {
                return Err(ExecError::Fail(format!(
                    "http: redirect {status} without Location header"
                )));
            };
            let location = location
                .to_str()
                .map_err(|_| ExecError::Fail("http: invalid Location header".to_string()))?;
            let next = url
                .join(location)
                .map_err(|_| ExecError::Fail("http: invalid redirect Location".to_string()))?;
            url = parse_url(next.as_str())?;
            continue;
        }
        let mut body = Vec::new();
        resp.take((ctx.limits.max_http_response_bytes + 1) as u64)
            .read_to_end(&mut body)
            .map_err(|err| ExecError::Fail(format!("http: read error: {err}")))?;
        if body.len() > ctx.limits.max_http_response_bytes {
            return Err(ExecError::Denied(format!(
                "http: response too large ({} bytes max)",
                ctx.limits.max_http_response_bytes
            )));
        }
        let code = if status.is_success() { 0 } else { 1 };
        let stderr = if status.is_success() {
            Vec::new()
        } else {
            format!("http: status {status}\n").into_bytes()
        };
        return Ok(RawOutput {
            code,
            stdout: body,
            stderr,
        });
    }
}

fn parse_method(raw: &str) -> Result<reqwest::Method, ExecError> {
    let upper = raw.to_ascii_uppercase();
    match upper.as_str() {
        "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS" => {
            Ok(reqwest::Method::from_bytes(upper.as_bytes())
                .map_err(|_| ExecError::Fail(format!("http: invalid method '{raw}'")))?)
        }
        _ => Err(ExecError::Fail(format!("http: unsupported method '{raw}'"))),
    }
}

fn parse_url(raw: &str) -> Result<reqwest::Url, ExecError> {
    let url = reqwest::Url::parse(raw)
        .map_err(|err| ExecError::Fail(format!("http: invalid url: {err}")))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(ExecError::Denied(format!(
            "http: scheme '{}' not allowed (http/https only)",
            url.scheme()
        )));
    }
    let host = url.host_str().unwrap_or("");
    let host_unbracketed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let allowed = ALLOWED_HOSTS.contains(&host)
        || matches!(
            host_unbracketed.parse::<std::net::IpAddr>(),
            Ok(std::net::IpAddr::V4(ip)) if ip == std::net::Ipv4Addr::LOCALHOST
        )
        || matches!(
            host_unbracketed.parse::<std::net::IpAddr>(),
            Ok(std::net::IpAddr::V6(ip)) if ip == std::net::Ipv6Addr::LOCALHOST
        );
    if !allowed {
        return Err(ExecError::Denied(format!(
            "http: host '{host}' not in allowlist (v1: localhost/127.0.0.1/[::1] only)"
        )));
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::super::{execute, Ctx, ExecError, ExecOutcome, Limits};
    use super::{parse_url, DEFAULT_MAX_HTTP_BODY_BYTES, MAX_REDIRECTS};
    use crate::parse::parse_input;
    use crate::resolve::Resolver;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    fn run_cmd(dir: &tempfile::TempDir, cmd: &str) -> Result<ExecOutcome, ExecError> {
        let resolver = Resolver::new(dir.path()).unwrap();
        let ctx = Ctx {
            resolver: &resolver,
            sensibles: &[],
            secrets: &[],
            limits: Limits::default(),
        };
        let node = parse_input(cmd, &HashMap::new()).unwrap();
        execute(&node, &ctx)
    }

    fn spawn_server(handler: impl Fn(&str) -> String + Send + Sync + 'static) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).unwrap() == 0 {
                    continue;
                }
                let path = request_line.split_whitespace().nth(1).unwrap_or("/");
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0u8; content_length];
                let _ = reader.read_exact(&mut body);
                let resp = handler(&format!("{path} {}", String::from_utf8_lossy(&body)));
                stream.write_all(resp.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
        });
        port
    }

    fn ok(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    }

    #[test]
    fn parse_url_allowlist() {
        for u in [
            "http://localhost/",
            "http://localhost:8080/x",
            "http://127.0.0.1/",
            "http://127.0.0.1:9000/",
            "http://[::1]/",
        ] {
            assert!(parse_url(u).is_ok(), "expected ok for {u}");
        }
        for u in [
            "http://169.254.169.254/latest/meta-data",
            "http://192.168.1.1/",
            "http://10.0.0.1/",
            "http://example.com/",
            "http://127.0.0.2/",
            "file:///etc/passwd",
            "ftp://localhost/",
        ] {
            assert!(
                matches!(parse_url(u), Err(ExecError::Denied(_))),
                "expected denied for {u}"
            );
        }
    }

    #[test]
    fn http_get_localhost_ok() {
        let dir = tempfile::tempdir().unwrap();
        let port = spawn_server(|_| ok("hello"));
        let out = run_cmd(&dir, &format!("http GET http://127.0.0.1:{port}/")).unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "hello");
    }

    #[test]
    fn http_follows_redirect_within_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let port = spawn_server(|req| {
            if req.starts_with("/final") {
                ok("landed")
            } else {
                "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
            }
        });
        let out = run_cmd(&dir, &format!("http GET http://127.0.0.1:{port}/")).unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "landed");
    }

    #[test]
    fn http_redirect_to_forbidden_host_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        let port = spawn_server(|_| {
            "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
        });
        let err = run_cmd(&dir, &format!("http GET http://127.0.0.1:{port}/")).unwrap_err();
        assert!(matches!(err, ExecError::Denied(_)));
    }

    #[test]
    fn http_too_many_redirects_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        let port = spawn_server(|_| {
            "HTTP/1.1 302 Found\r\nLocation: /loop\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
        });
        let err = run_cmd(&dir, &format!("http GET http://127.0.0.1:{port}/")).unwrap_err();
        match &err {
            ExecError::Denied(m) => assert!(m.contains("too many redirects"), "got {m}"),
            other => panic!("expected Denied, got {other:?}"),
        }
        let _ = MAX_REDIRECTS;
    }

    #[test]
    fn http_non_2xx_is_code_1_with_status() {
        let dir = tempfile::tempdir().unwrap();
        let port = spawn_server(|_| {
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
        });
        let out = run_cmd(&dir, &format!("http GET http://127.0.0.1:{port}/")).unwrap();
        assert_eq!(out.code, 1);
        assert!(out.stderr.contains("404"));
    }

    #[test]
    fn http_post_with_data_and_header() {
        let dir = tempfile::tempdir().unwrap();
        let port = spawn_server(|req| {
            assert!(req.starts_with("/submit payload"), "got {req:?}");
            ok("ok")
        });
        let out = run_cmd(
            &dir,
            &format!(
                r#"http POST http://127.0.0.1:{port}/submit --data payload --header "X-Test: 1""#
            ),
        )
        .unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "ok");
    }

    #[test]
    fn http_denies_oversized_data() {
        let dir = tempfile::tempdir().unwrap();
        let big = "x".repeat(DEFAULT_MAX_HTTP_BODY_BYTES + 1);
        let err =
            run_cmd(&dir, &format!("http POST http://127.0.0.1:1/ --data {big}")).unwrap_err();
        assert!(matches!(err, ExecError::Denied(_)));
    }

    #[test]
    fn http_rejects_bad_method_and_args() {
        let dir = tempfile::tempdir().unwrap();
        let err = run_cmd(&dir, "http FOO http://127.0.0.1:1/").unwrap_err();
        assert!(matches!(err, ExecError::Fail(m) if m.contains("unsupported method")));
        let err = run_cmd(&dir, "http GET").unwrap_err();
        assert!(matches!(err, ExecError::Fail(m) if m.contains("usage")));
        let err = run_cmd(&dir, "http GET http://127.0.0.1:1/ --bogus x").unwrap_err();
        assert!(matches!(err, ExecError::Fail(m) if m.contains("unrecognized argument")));
        let err = run_cmd(&dir, "http GET http://127.0.0.1:1/ --header nope").unwrap_err();
        assert!(matches!(err, ExecError::Fail(m) if m.contains("invalid header")));
    }
}
