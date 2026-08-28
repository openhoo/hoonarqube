// Hoonarqube oracle fixture: rust:S7441 bad
fn main() {
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).expect("read failed");
    let num: i32 = input.parse().expect("not a number"); // Noncompliant
    println!("{num}");
}
