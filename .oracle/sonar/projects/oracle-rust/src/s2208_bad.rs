// Hoonarqube oracle fixture: rust:S2208 bad
use std::collections::*; // Noncompliant
fn main() {
    let mut map = HashMap::new();
    map.insert(1, 2);
}
