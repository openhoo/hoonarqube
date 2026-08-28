// Hoonarqube oracle fixture: rust:S7418 bad
fn main() {
    #[allow(clippy::almost_swapped)] // Noncompliant: ineffective on import
    use std::collections::HashMap;
    let _: HashMap<u8, u8> = HashMap::new();
}
