// Hoonarqube oracle fixture: rust:S7459 bad
fn f(reader: &mut dyn std::io::Read) {
    let mut vec: Vec<u8> = Vec::with_capacity(1000);
    unsafe { vec.set_len(1000); } // Noncompliant: Uninitialized vector
    reader.read_exact(&mut vec).unwrap(); // Undefined behavior!
}

fn main() {}
