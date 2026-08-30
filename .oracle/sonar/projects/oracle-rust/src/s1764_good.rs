// Hoonarqube oracle fixture: rust:S1764 good

fn product(value: i32) -> i32 {
    value * value
}

fn sum(value: i32) -> i32 {
    value + value
}

fn main() {
    println!("{} {}", product(4), sum(4));
}
