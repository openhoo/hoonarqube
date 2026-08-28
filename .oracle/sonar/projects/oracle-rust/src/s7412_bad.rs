// Hoonarqube oracle fixture: rust:S7412 bad
fn main() {
    unsafe { (&() as *const ()).offset(1); } // Noncompliant: No-op on zero-sized type pointer.
}
