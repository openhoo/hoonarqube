// Hoonarqube oracle fixture: rust:S7451 bad
fn main() {
    let x = 1;
    let a = x % 1; // Noncompliant: remainder by one
    println!("{a}");
}
