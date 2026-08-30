// Hoonarqube oracle fixture: rust:S920 good

fn accepts(flag: bool) {
    println!("{flag}");
}

fn classify(value: u8) -> u8 {
    match value {
        0 => 1,
        _ => 2,
    }
}

fn main() {
    accepts(true);
    println!("{}", classify(0));
}
