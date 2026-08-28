// Hoonarqube oracle fixture: rust:S7433 bad
fn main() {
    let a = [1_u8, 2, 3, 4];
    let p = &a as *const [u8] as *const [u32];
    unsafe {
        println!("{:?}", &*p); // Noncompliant: Undefined behavior
    }
}
