// Hoonarqube oracle fixture: rust:S7415 bad
fn main() {
    let i = 20;
    while i > 10 {
        println!("let me loop forever!"); // Noncompliant: 'i' does not change
    }
}
