// Hoonarqube oracle fixture: rust:S7454 bad
fn main() {
    let x = 2_32; // Noncompliant: mistyped literal suffix
    let y = 250_8;
    println!("{x} {y}");
}
