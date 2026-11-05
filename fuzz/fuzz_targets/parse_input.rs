#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let vars = HashMap::new();
    if let Ok(node) = la_console::parse::parse_input(input, &vars) {
        assert!(
            !la_console::parse::pipe_has_trusted(&node),
            "trusted in pipe for input {input:?}"
        );
        for cmd in la_console::parse::all_commands(&node) {
            for arg in &cmd.argv {
                assert!(
                    !arg.text.contains('`') && !arg.text.contains("$("),
                    "sub-execution marker in arg for input {input:?}"
                );
            }
        }
    }
});
