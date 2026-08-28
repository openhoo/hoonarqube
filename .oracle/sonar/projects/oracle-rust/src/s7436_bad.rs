// Hoonarqube oracle fixture: rust:S7436 bad
fn main() {
    let status_code = 200;
    if status_code <= 400 && status_code < 500 { // Noncompliant
        println!("ok");
    }
}
