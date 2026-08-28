// Hoonarqube oracle fixture: rust:S6164 bad
fn main() {
    let x = 3.14; // Noncompliant: Approximates PI
    let y = 1_f64 / 3.1415926535; // Noncompliant: Approximates FRAC_1_PI
    println!("{x} {y}");
}
