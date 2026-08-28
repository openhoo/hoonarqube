// Hoonarqube oracle fixture: rust:S5856 bad
use regex::Regex;

fn main() {
    let _ = Regex::new("(");
}
