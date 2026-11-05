use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::resolve::{Denied, Resolver};

pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_WRITE_BYTES: usize = 1024 * 1024;
pub const SECRET_MASK: &str = "***";

#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    #[error("path denied: {0}")]
    Denied(#[from] Denied),
    #[error("sensitive file: {0}")]
    Sensitive(String),
    #[error("write bound exceeded: {0} bytes max")]
    WriteBoundExceeded(usize),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

pub trait Sink {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, SinkError>;
}

pub fn mask_secrets(text: &str, secrets: &[String]) -> String {
    let mut masker = SecretMasker::new(secrets);
    let mut out = masker.mask(text.as_bytes());
    out.extend_from_slice(&masker.finish());
    String::from_utf8_lossy(&out).into_owned()
}

struct SecretMasker {
    secrets: Vec<Vec<u8>>,
    carry: Vec<u8>,
}

impl SecretMasker {
    fn new(secrets: &[String]) -> Self {
        let mut secrets: Vec<Vec<u8>> = secrets
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| s.clone().into_bytes())
            .collect();
        secrets.sort_by_key(|b| std::cmp::Reverse(b.len()));
        Self {
            secrets,
            carry: Vec::new(),
        }
    }

    fn mask(&mut self, bytes: &[u8]) -> Vec<u8> {
        if self.secrets.is_empty() {
            return bytes.to_vec();
        }
        let max_len = self.secrets[0].len();
        let mut data = std::mem::take(&mut self.carry);
        data.extend_from_slice(bytes);
        let mut out = Vec::with_capacity(data.len());
        let mut i = 0;
        while i < data.len() {
            let mut matched = false;
            for secret in &self.secrets {
                if data.len() - i >= secret.len() && data[i..i + secret.len()] == secret[..] {
                    out.extend_from_slice(SECRET_MASK.as_bytes());
                    i += secret.len();
                    matched = true;
                    break;
                }
            }
            if !matched {
                out.push(data[i]);
                i += 1;
            }
        }
        let keep = max_len - 1;
        if out.len() > keep {
            let split = out.len() - keep;
            self.carry = out.split_off(split);
        } else {
            self.carry = std::mem::take(&mut out);
        }
        out
    }

    fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.carry)
    }
}

struct TruncatedBuf {
    max: usize,
    head: Vec<u8>,
    tail: VecDeque<u8>,
    total: usize,
    overflowed: bool,
}

impl TruncatedBuf {
    fn new(max: usize) -> Self {
        Self {
            max,
            head: Vec::new(),
            tail: VecDeque::new(),
            total: 0,
            overflowed: false,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        self.total += bytes.len();
        if !self.overflowed {
            self.head.extend_from_slice(bytes);
            if self.head.len() > self.max {
                let head_keep = self.max / 2;
                let tail_keep = self.max - head_keep;
                self.tail = self.head[self.head.len() - tail_keep..]
                    .iter()
                    .copied()
                    .collect();
                self.head.truncate(head_keep);
                self.overflowed = true;
            }
            return;
        }
        let tail_keep = self.max - self.max / 2;
        for &b in bytes {
            self.tail.push_back(b);
            if self.tail.len() > tail_keep {
                self.tail.pop_front();
            }
        }
    }

    fn into_bytes(self) -> (Vec<u8>, bool) {
        if !self.overflowed {
            return (self.head, false);
        }
        let mut out = self.head;
        out.extend(self.tail.iter().copied());
        (out, true)
    }
}

pub struct FileSink {
    file: File,
    masker: SecretMasker,
    written: usize,
    max_write_bytes: usize,
}

impl FileSink {
    pub fn create(
        resolver: &Resolver,
        rel_path: &str,
        append: bool,
        sensibles: &[regex::Regex],
        secrets: &[String],
        max_write_bytes: usize,
    ) -> Result<Self, SinkError> {
        let target = resolver.resolve(rel_path)?;
        let rel = target
            .strip_prefix(resolver.root())
            .map_err(|_| Denied::AbsoluteOutsideRoot)?;
        let rel_str = rel.to_string_lossy();
        for pattern in sensibles {
            if pattern.is_match(&rel_str) {
                return Err(SinkError::Sensitive(rel_str.into_owned()));
            }
        }
        let file = if append {
            OpenOptions::new().create(true).append(true).open(&target)?
        } else {
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&target)?
        };
        Ok(Self {
            file,
            masker: SecretMasker::new(secrets),
            written: 0,
            max_write_bytes,
        })
    }

    pub fn written(&self) -> usize {
        self.written
    }
}

impl Sink for FileSink {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, SinkError> {
        let masked = self.masker.mask(bytes);
        if self.written + masked.len() > self.max_write_bytes {
            return Err(SinkError::WriteBoundExceeded(self.max_write_bytes));
        }
        self.file.write_all(&masked)?;
        self.written += masked.len();
        Ok(bytes.len())
    }
}

impl FileSink {
    pub fn finish(mut self) -> Result<(), SinkError> {
        let pending = self.masker.finish();
        if !pending.is_empty() {
            if self.written + pending.len() > self.max_write_bytes {
                return Err(SinkError::WriteBoundExceeded(self.max_write_bytes));
            }
            self.file.write_all(&pending)?;
            self.written += pending.len();
        }
        self.file.flush()?;
        Ok(())
    }
}

pub struct CallerSink {
    buf: TruncatedBuf,
    masker: SecretMasker,
}

impl CallerSink {
    pub fn new(max_output_bytes: usize, secrets: &[String]) -> Self {
        Self {
            buf: TruncatedBuf::new(max_output_bytes),
            masker: SecretMasker::new(secrets),
        }
    }

    pub fn finish(mut self) -> (String, bool) {
        let pending = self.masker.finish();
        if !pending.is_empty() {
            self.buf.push(&pending);
        }
        let (bytes, truncated) = self.buf.into_bytes();
        (String::from_utf8_lossy(&bytes).into_owned(), truncated)
    }
}

impl Sink for CallerSink {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, SinkError> {
        let masked = self.masker.mask(bytes);
        self.buf.push(&masked);
        Ok(bytes.len())
    }
}

pub struct PipeSink {
    buf: TruncatedBuf,
}

impl PipeSink {
    pub fn new(max_output_bytes: usize) -> Self {
        Self {
            buf: TruncatedBuf::new(max_output_bytes),
        }
    }

    pub fn finish(self) -> (Vec<u8>, bool) {
        self.buf.into_bytes()
    }
}

impl Sink for PipeSink {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, SinkError> {
        self.buf.push(bytes);
        Ok(bytes.len())
    }
}

pub fn sensitive_match(sensibles: &[regex::Regex], root: &Path, target: &Path) -> Option<String> {
    let rel = target.strip_prefix(root).ok()?;
    let rel_str = rel.to_string_lossy();
    sensibles
        .iter()
        .find(|p| p.is_match(&rel_str))
        .map(|_| rel_str.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn secrets(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn resolver(dir: &tempfile::TempDir) -> Resolver {
        Resolver::new(dir.path()).unwrap()
    }

    #[test]
    fn mask_secrets_replaces_known_secrets() {
        let s = secrets(&["tok-abc123"]);
        assert_eq!(
            mask_secrets("token=tok-abc123!", &s),
            format!("token={SECRET_MASK}!")
        );
    }

    #[test]
    fn mask_secrets_handles_multiple_and_overlapping() {
        let s = secrets(&["abcdef", "abc"]);
        assert_eq!(
            mask_secrets("x abcdef y abc z", &s),
            format!("x {SECRET_MASK} y {SECRET_MASK} z")
        );
    }

    #[test]
    fn mask_secrets_ignores_empty_secrets() {
        let s = secrets(&[""]);
        assert_eq!(mask_secrets("abc", &s), "abc");
    }

    #[test]
    fn file_sink_denies_escape_before_creating_anything() {
        let dir = tempfile::tempdir().unwrap();
        let r = resolver(&dir);
        let err = FileSink::create(&r, "../evil.txt", false, &[], &[], 1024)
            .err()
            .unwrap();
        assert!(matches!(err, SinkError::Denied(_)));
        assert!(!dir.path().join("../evil.txt").exists());
        assert!(!dir.path().parent().unwrap().join("evil.txt").exists());
    }

    #[test]
    fn file_sink_denies_sensitive_path_before_opening() {
        let dir = tempfile::tempdir().unwrap();
        let r = resolver(&dir);
        let sensibles = vec![regex::Regex::new(r".*\.env$").unwrap()];
        let err = FileSink::create(&r, ".env", false, &sensibles, &[], 1024)
            .err()
            .unwrap();
        assert!(matches!(err, SinkError::Sensitive(_)));
        assert!(!dir.path().join(".env").exists());
    }

    #[test]
    fn file_sink_masks_secrets_before_persisting() {
        let dir = tempfile::tempdir().unwrap();
        let r = resolver(&dir);
        let s = secrets(&["tok-abc123"]);
        let mut sink = FileSink::create(&r, "out.txt", false, &[], &s, 1024).unwrap();
        sink.write(b"token=tok-abc123\n").unwrap();
        sink.finish().unwrap();
        let content = fs::read_to_string(dir.path().join("out.txt")).unwrap();
        assert_eq!(content, format!("token={SECRET_MASK}\n"));
        assert!(!content.contains("tok-abc123"));
    }

    #[test]
    fn file_sink_masks_secret_split_across_writes() {
        let dir = tempfile::tempdir().unwrap();
        let r = resolver(&dir);
        let s = secrets(&["tok-abc123"]);
        let mut sink = FileSink::create(&r, "out.txt", false, &[], &s, 1024).unwrap();
        sink.write(b"tok-ab").unwrap();
        sink.write(b"c123!").unwrap();
        sink.finish().unwrap();
        let content = fs::read_to_string(dir.path().join("out.txt")).unwrap();
        assert_eq!(content, format!("{SECRET_MASK}!"));
    }

    #[test]
    fn file_sink_enforces_write_bound() {
        let dir = tempfile::tempdir().unwrap();
        let r = resolver(&dir);
        let mut sink = FileSink::create(&r, "out.txt", false, &[], &[], 5).unwrap();
        assert_eq!(sink.write(b"abc").unwrap(), 3);
        assert!(matches!(
            sink.write(b"def"),
            Err(SinkError::WriteBoundExceeded(5))
        ));
        sink.finish().unwrap();
        assert_eq!(fs::read(dir.path().join("out.txt")).unwrap(), b"abc");
    }

    #[test]
    fn file_sink_append_mode_appends() {
        let dir = tempfile::tempdir().unwrap();
        let r = resolver(&dir);
        fs::write(dir.path().join("log.txt"), b"one\n").unwrap();
        let mut sink = FileSink::create(&r, "log.txt", true, &[], &[], 1024).unwrap();
        sink.write(b"two\n").unwrap();
        sink.finish().unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("log.txt")).unwrap(),
            "one\ntwo\n"
        );
    }

    #[test]
    fn file_sink_truncate_mode_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let r = resolver(&dir);
        fs::write(dir.path().join("log.txt"), b"old-content").unwrap();
        let mut sink = FileSink::create(&r, "log.txt", false, &[], &[], 1024).unwrap();
        sink.write(b"new").unwrap();
        sink.finish().unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("log.txt")).unwrap(),
            "new"
        );
    }

    #[test]
    fn caller_sink_passes_through_under_bound() {
        let s = secrets(&["tok-abc123"]);
        let mut sink = CallerSink::new(1024, &s);
        sink.write(b"hello tok-abc123\n").unwrap();
        let (out, truncated) = sink.finish();
        assert!(!truncated);
        assert_eq!(out, format!("hello {SECRET_MASK}\n"));
    }

    #[test]
    fn caller_sink_truncates_head_and_tail_over_bound() {
        let mut sink = CallerSink::new(10, &[]);
        sink.write(b"0123456789ABCDEF").unwrap();
        let (out, truncated) = sink.finish();
        assert!(truncated);
        assert_eq!(out.len(), 10);
        assert!(out.starts_with("01234"));
        assert!(out.ends_with("BCDEF"));
    }

    #[test]
    fn caller_sink_masks_secret_split_across_writes() {
        let s = secrets(&["tok-abc123"]);
        let mut sink = CallerSink::new(1024, &s);
        sink.write(b"tok-ab").unwrap();
        sink.write(b"c123").unwrap();
        let (out, truncated) = sink.finish();
        assert!(!truncated);
        assert_eq!(out, SECRET_MASK);
    }

    #[test]
    fn pipe_sink_truncates_but_never_masks() {
        let mut sink = PipeSink::new(8);
        sink.write(b"tok-abc123-extra").unwrap();
        let (out, truncated) = sink.finish();
        assert!(truncated);
        assert_eq!(out, b"tok-xtra");
    }

    #[test]
    fn pipe_sink_passes_through_under_bound() {
        let mut sink = PipeSink::new(1024);
        sink.write(b"raw tok-abc123").unwrap();
        let (out, truncated) = sink.finish();
        assert!(!truncated);
        assert_eq!(out, b"raw tok-abc123");
    }

    #[test]
    fn sensitive_match_reports_relative_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let target = root.join("cfg/.env");
        let re = vec![regex::Regex::new(r".*\.env$").unwrap()];
        assert_eq!(
            sensitive_match(&re, &root, &target),
            Some("cfg/.env".to_string())
        );
        assert_eq!(sensitive_match(&re, &root, &root.join("ok.txt")), None);
    }
}
