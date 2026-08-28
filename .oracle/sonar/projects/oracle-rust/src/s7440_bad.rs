// Hoonarqube oracle fixture: rust:S7440 bad
use std::fmt;

struct Structure(i32);
impl fmt::Display for Structure {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string()) // Noncompliant
    }
}

fn main() {}
