// Hoonarqube oracle fixture: rust:S7432 bad
fn main() {
    (10..=0).for_each(|x| println!("{}", x)); // Noncompliant: Empty range
    let arr = [1, 2, 3, 4, 5];
    let sub = &arr[3..1]; // Noncompliant: Reversed slice indexing
}
