// Hoonarqube oracle fixture: rust:S3723 good

fn count(empty: bool) -> usize {
    if empty {
        0
    } else {
        1
    }
}

fn main() {
    println!("{}", count(false));
}
