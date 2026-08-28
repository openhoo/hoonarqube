// Hoonarqube oracle fixture: rust:S7420 bad
fn main() {
    let values = vec![2_u16];
    let converted = unsafe {
        std::mem::transmute::<_, Vec<u32>>(values) // Noncompliant
    };
    drop(converted);
}
