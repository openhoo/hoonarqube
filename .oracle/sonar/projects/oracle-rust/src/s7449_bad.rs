// Hoonarqube oracle fixture: rust:S7449 bad
trait Animal {
    #[inline] // Noncompliant: Inline attribute on trait method without implementation.
    fn name(&self) -> &'static str;
}

fn main() {}
