// Hoonarqube oracle fixture: rust:S7453 bad
struct Foo { bar: Bar }
struct Bar;

fn foo(x: &Foo) -> &mut Bar {
    unsafe {
        // Noncompliant: Converting immutable reference to mutable.
        &mut (*(x as *const Foo as *mut Foo)).bar
    }
}

fn main() {}
