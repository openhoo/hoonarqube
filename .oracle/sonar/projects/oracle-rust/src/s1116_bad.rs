// Hoonarqube oracle fixture: rust:S1116 bad
fn main() {
    let x = 5;

    if x > 0 {
        println!("x is positive");
    }; // Noncompliant

    match x {
        1 => println!("x is one"),
        2 => println!("x is two"),
        _ => println!("x is something else"),
    }; // Noncompliant
}
