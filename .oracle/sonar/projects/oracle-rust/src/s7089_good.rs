// Hoonarqube oracle fixture: rust:S7089 good

fn duplicate(values: &[i32]) -> Vec<i32> {
    let mut output = Vec::new();
    for value in values {
        output.push(*value);
        output.push(*value);
    }
    output
}

fn main() {
    println!("{:?}", duplicate(&[1, 2]));
}
