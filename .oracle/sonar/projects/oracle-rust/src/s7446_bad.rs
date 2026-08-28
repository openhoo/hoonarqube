// Hoonarqube oracle fixture: rust:S7446 bad
pub fn foo(x: *const u8) {
    println!("{}", unsafe { *x });
}

// This call "looks" safe but will segfault or worse!
// foo(invalid_ptr);

fn main() {}
