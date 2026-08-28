// Hoonarqube oracle fixture: rust:S7411 bad
fn main() {
    let condition = true;
    let result = if condition {
        println!("Hello World");
        42
    } else {
        println!("Hello World");
        24
    };
    println!("{result}");
}
