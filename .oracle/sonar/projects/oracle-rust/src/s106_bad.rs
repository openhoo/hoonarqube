// Hoonarqube oracle fixture: rust:S106 bad
fn do_something() {
    println!("my message");  // Noncompliant, output directly to stdout without a logger
}

fn main() { do_something(); }
