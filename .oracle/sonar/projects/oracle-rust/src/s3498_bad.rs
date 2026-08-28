// Hoonarqube oracle fixture: rust:S3498 bad
struct MyStruct {
    a: i32,
}

fn main() {
    let a = 1;
    let my_struct = MyStruct {
        a: a,  // Noncompliant
    };
    println!("{}", my_struct.a);
}
