// Hoonarqube oracle fixture: rust:S7463 bad
fn main() {
    let a = 12u32;
    let b = 13u32;
    let result = if a > b { b - a } else { 0 }; // Noncompliant
    println!("{result}");
}
