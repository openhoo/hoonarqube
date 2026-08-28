// Hoonarqube oracle fixture: rust:S4962 bad
fn main() {
    let ptr = 0 as *const i32;
    let mut_ptr = 0 as *mut i32;
    println!("{ptr:p} {mut_ptr:p}");
}
