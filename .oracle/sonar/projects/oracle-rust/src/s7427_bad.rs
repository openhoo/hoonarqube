// Hoonarqube oracle fixture: rust:S7427 bad
fn main() {
    let null_ref: &u64 = unsafe { std::mem::transmute(0 as *const u64) }; // Noncompliant
    println!("{null_ref}");
}
