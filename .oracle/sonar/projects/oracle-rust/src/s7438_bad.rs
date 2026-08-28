// Hoonarqube oracle fixture: rust:S7438 bad
fn main() {
    let x = 1;
    if x & 1 == 2 { // Noncompliant: impossible bit mask
        println!("impossible");
    }
}
