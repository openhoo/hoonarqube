// Hoonarqube oracle fixture: rust:S905 bad
fn get_result() -> i32 {
    let mut result = 42;
    if should_be_zero() {
        result == 0; // Noncompliant: no side effect, was an assignment intended?
    }
    result
}

fn should_be_zero() -> bool { true }

fn main() {}
