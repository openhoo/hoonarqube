// Hoonarqube oracle fixture: rust:S7425 bad
use std::mem::MaybeUninit;

fn main() {
    let _: usize = unsafe { MaybeUninit::uninit().assume_init() }; // Noncompliant
}
