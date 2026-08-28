// Hoonarqube oracle fixture: rust:S7447 bad
use std::fs::OpenOptions;

fn main() {
    let _ = OpenOptions::new().read(true).truncate(true).open("oracle.txt"); // Noncompliant
}
