// Hoonarqube oracle fixture: rust:S1656 bad
fn main() {
    let mut x = 5;
    x = x; // Self-assignment - does nothing
    println!("{x}");
}
