// Hoonarqube oracle fixture: rust:S7414 bad
fn main() {
    let value: *const usize = unsafe { std::mem::transmute(6.0f64) }; // Noncompliant
    println!("{value:p}");
}
