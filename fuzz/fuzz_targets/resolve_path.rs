#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(dir) = tempfile::tempdir() else {
        return;
    };
    if let Ok(resolved) = la_console::resolve::resolve(dir.path(), input) {
        let Ok(root) = std::fs::canonicalize(dir.path()) else {
            return;
        };
        assert!(
            resolved.starts_with(&root),
            "resolve() escaped root: {resolved:?} for input {input:?}"
        );
    }
});
