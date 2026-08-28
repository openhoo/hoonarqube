// Hoonarqube oracle fixture: rust:S7424 bad
#[derive(Hash)]
struct Foo;

impl PartialEq for Foo {
    fn eq(&self, other: &Self) -> bool {
        // Some custom equality logic
        true // Noncompliant
    }
}

fn main() {}
