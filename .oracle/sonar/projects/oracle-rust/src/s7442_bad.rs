// Hoonarqube oracle fixture: rust:S7442 bad
fn do_something_with(_x: usize) {}

fn main() {
    let option: Option<usize> = None;
    if option.is_none() {
        do_something_with(option.unwrap()); // Noncompliant: always panics
    }
}
