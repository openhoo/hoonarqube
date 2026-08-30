// Hoonarqube oracle fixture: rust:S2437 good

fn permissions(mode: u32) -> bool {
    mode & 0o022 != 0
}

fn main() {
    let value = Some(0);
    let _matched = matches!(value, Some(0 | -1));
    println!("{}", permissions(0o755));
}
