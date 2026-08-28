// Hoonarqube oracle fixture: rust:S7456 bad
fn main() {
    let values = vec![1, 2, 3];
    let skipped = values.iter().skip(0).collect::<Vec<_>>(); // Noncompliant
    println!("{}", skipped.len());
}
