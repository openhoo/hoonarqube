// Hoonarqube oracle fixture: rust:S7422 bad
use std::collections::hash_map::DefaultHasher;
use std::hash::Hash;

enum Foo { Empty, WithValue(u8) }

fn main() {
    let mut state = DefaultHasher::new();
    let my_enum = Foo::Empty;
    match my_enum {
        Foo::Empty => ().hash(&mut state), // Noncompliant
        Foo::WithValue(x) => x.hash(&mut state),
    }
}
