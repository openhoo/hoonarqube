// Hoonarqube oracle fixture: rust:S1612 bad
fn main() {
    let result = Some('a').map(|s| s.to_uppercase());
    drop(result);
}
