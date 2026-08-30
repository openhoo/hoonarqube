// Hoonarqube oracle fixture: rust:S7463 good

fn previous(bytes: &[u8], start: usize) -> usize {
    if start > 0 && bytes[start - 1] == b'x' {
        start - 1
    } else {
        start
    }
}

fn main() {
    println!("{}", previous(b"x", 1));
}
