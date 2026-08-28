// Hoonarqube oracle fixture: rust:S3807 bad
use std::ptr;

fn main() {
    let _: &[u8] = unsafe { std::slice::from_raw_parts(ptr::null(), 0) }; // Noncompliant
}
