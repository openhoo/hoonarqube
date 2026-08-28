// Hoonarqube oracle fixture: rust:S2148 bad
fn main() {
    let large_number = 1000000000;
    let precise_float = 1234567.890123;
    println!("{large_number} {precise_float}");
}
