// Hoonarqube oracle fixture: rust:S1862 bad
fn main() {
    let param = 1;
    if param == 1 {
        println!("open");
    } else if param == 2 {
        println!("close");
    } else if param == 1 { // Noncompliant
        println!("background");
    }
}
