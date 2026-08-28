// Hoonarqube oracle fixture: rust:S4325 bad
fn get_length(value: &str) -> usize {
    let length = value.len() as usize; // Noncompliant: 'value.len()' already returns a 'usize'
    length
}

fn main() {}
