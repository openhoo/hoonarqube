// Hoonarqube oracle fixture: rust:S7430 bad
fn main() {
    let text = "a:b";
    for part in text.splitn(1, ":") { // Noncompliant
        println!("{part}");
    }
}
