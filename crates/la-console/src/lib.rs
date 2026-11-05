#![forbid(unsafe_code)]

pub mod console;

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_smoke() {
        assert_eq!(2 + 2, 4);
    }
}
