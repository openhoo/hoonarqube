// Hoonarqube oracle fixture: rust:S7458 bad
use std::fmt;

pub struct A;

impl A {
    pub fn to_string(&self) -> String {
        "I am A".to_string() // Noncompliant: Inherent method shadows `Display::to_string`.
    }
}

impl fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "I am A, too")
    }
}

fn main() {}
