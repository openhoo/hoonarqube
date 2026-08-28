// Hoonarqube oracle fixture: rust:S6913 bad
use std::cmp::{max, min};

fn main() {
    let x = 50;
    let value = min(0, max(100, x));
    println!("{value}");
}
