// Hoonarqube oracle fixture: rust:S7429 bad
fn main() {
    let null_fn: fn() = unsafe { std::mem::transmute(std::ptr::null::<()>()) }; // Noncompliant
    let _ = null_fn;
}
