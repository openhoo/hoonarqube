// Hoonarqube oracle fixture: rust:S7448 bad
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;

fn main() {
    let mut options = OpenOptions::new();
    options.mode(644); // Noncompliant: non-octal value used
}
