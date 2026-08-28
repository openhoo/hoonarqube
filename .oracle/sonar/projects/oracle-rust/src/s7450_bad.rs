// Hoonarqube oracle fixture: rust:S7450 bad
use std::sync::Mutex;

fn main() {
    let _ = Mutex::new(1).lock(); // Noncompliant: immediately drops lock
}
