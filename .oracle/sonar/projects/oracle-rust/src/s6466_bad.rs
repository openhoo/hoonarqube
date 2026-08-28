// Hoonarqube oracle fixture: rust:S6466 bad
fn main() {
    let x = [1, 2, 3, 4];
    println!("{}", x[9]); // Out of bounds indexing
}
