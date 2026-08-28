// Hoonarqube oracle fixture: rust:S2589 bad
fn main() {
    let (a, b) = (true, false);
    if a && b || a { // Noncompliant: `b` is redundant
        println!("yes");
    }
}
