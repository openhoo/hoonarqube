// Hoonarqube oracle fixture: rust:S920 bad
fn check_value(value: bool) -> &'static str {
    match value {
        true => "Value is true",
        false => "Value is false",
    }
}

fn main() {}
