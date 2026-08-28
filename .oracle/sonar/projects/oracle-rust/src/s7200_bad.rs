// Hoonarqube oracle fixture: rust:S7200 bad
fn main() {
    let mut values = vec![1, 2, 3, 4, 5];
    values.resize(0, 5); // Noncompliant: Resizing the vector to 0.
}
