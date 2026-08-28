// Hoonarqube oracle fixture: rust:S7445 bad
fn main() {
    let _ = option_env!("HOONARQUBE_ORACLE_UNSET").unwrap(); // Noncompliant
}
