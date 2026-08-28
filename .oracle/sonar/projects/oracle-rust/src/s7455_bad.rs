// Hoonarqube oracle fixture: rust:S7455 bad
fn main() {
    let mut iterator = [1, 2, 3].into_iter();
    for value in iterator.next() { // Noncompliant
        println!("{value}");
    }
}
