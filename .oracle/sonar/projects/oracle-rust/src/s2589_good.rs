// Hoonarqube oracle fixture: rust:S2589 good

fn key_shaped(name: &str) -> bool {
    name == "Id" || name == "Key"
}

fn main() {
    println!("{}", key_shaped("Id"));
}
