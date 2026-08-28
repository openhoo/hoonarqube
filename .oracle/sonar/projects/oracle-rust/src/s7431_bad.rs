// Hoonarqube oracle fixture: rust:S7431 bad
const SIZE: usize = 128;

fn main() {
    let x = [2u16; SIZE];
    let mut y = [2u16; SIZE];
    unsafe {
        std::ptr::copy_nonoverlapping(
            x.as_ptr(), y.as_mut_ptr(), std::mem::size_of::<u16>()
        ); // Noncompliant: byte size used as element count
    }
}
