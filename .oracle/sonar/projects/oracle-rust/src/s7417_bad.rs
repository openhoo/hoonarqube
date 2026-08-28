// Hoonarqube oracle fixture: rust:S7417 bad
use std::cmp::Ordering;

#[derive(Ord, PartialEq, Eq)]
struct Foo;

impl PartialOrd for Foo {
    fn partial_cmp(&self, _other: &Self) -> Option<Ordering> {
        None  // Noncompliant: Manually implemented PartialOrd when Ord is derived.
    }
}

fn main() {}
