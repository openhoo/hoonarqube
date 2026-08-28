// Hoonarqube oracle fixture: rust:S7428 bad
fn main() {
    let text = "bar";
    match &*text.to_ascii_lowercase() {
        "foo" => {},
        "Bar" => {}, // Noncompliant: This arm cannot match lowercased text.
        _ => {},
    }
}
