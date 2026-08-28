// Hoonarqube oracle fixture: rust:S7464 bad
use std::iter;

fn main() {
    let values = iter::repeat(1_u8).collect::<Vec<_>>(); // Noncompliant: infinite iterator
    drop(values);
}
