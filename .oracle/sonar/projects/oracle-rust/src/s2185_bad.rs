// Hoonarqube oracle fixture: rust:S2185 bad
fn main() {
    let x = 1;
    let result = 0 * x; // Noncompliant: Result is always zero.
    println!("{result}");
}
