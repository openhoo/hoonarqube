// Hoonarqube oracle fixture: rust:S7444 bad
fn overflow_check(a: u32, b: u32) {
    if a + b < a { // Noncompliant: overflow check may itself panic
        println!("overflow");
    }
}

fn main() { overflow_check(1, 2); }
