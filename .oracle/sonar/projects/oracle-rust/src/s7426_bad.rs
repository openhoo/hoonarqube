// Hoonarqube oracle fixture: rust:S7426 bad
#[repr(usize)]
enum NonPortable {
    X = 0x1_0000_0000, // Noncompliant
    Y = 0,
}

fn main() {}
