// Hoonarqube oracle fixture: rust:S7437 bad
fn main() {
    let mut foo = 1;
    let mut bar = 2;
    foo = bar; // Noncompliant
    bar = foo; // Noncompliant
    println!("{foo} {bar}");
}
