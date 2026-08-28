// Hoonarqube oracle fixture: rust:S3723 bad
fn main() {
    let a = &[
        -1, -2, -3 // Noncompliant: missing comma makes subtraction
        -4, -5, -6,
    ];
    println!("{}", a.len());
}
