// Hoonarqube oracle fixture: rust:S7415 good

fn drain(values: &mut Vec<i32>) {
    while let Some(_value) = values.pop() {}
}

fn main() {
    drain(&mut vec![1, 2, 3]);
}
