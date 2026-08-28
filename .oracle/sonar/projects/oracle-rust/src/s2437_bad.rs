// Hoonarqube oracle fixture: rust:S2437 bad
fn main() {
    let x = 1;
    if (x | 2) > 3 { // Noncompliant: Bit mask cannot affect this comparison
        println!("large");
    }
}
