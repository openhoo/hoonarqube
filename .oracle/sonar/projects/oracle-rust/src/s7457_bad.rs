// Hoonarqube oracle fixture: rust:S7457 bad
fn main() {
    for x in (0..100).step_by(0) { // Noncompliant: panics
        println!("{x}");
    }
}
