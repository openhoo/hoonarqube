// Hoonarqube oracle fixture: rust:S1858 bad
fn main() {
    let message = String::from("hello world");
    println!("{}", message.to_string()); // Noncompliant: 'message' is already a String
}
